from rest_framework.serializers import Serializer, ModelSerializer, \
                                       Field, ImageField, BooleanField, \
                                       IntegerField, CharField, EmailField,\
                                       DictField, PrimaryKeyRelatedField, \
                                       DateTimeField, ReadOnlyField, \
                                       ValidationError

from moneyed import Money

from mete import models as mete_models
from store import models as store_models

from django.conf import settings
from django.contrib.auth import models as auth_models



class AccountNotLocked:
    """
    Check if the account is not locked.
    """
    def __call__(self, value):
        account = value
        if account.is_locked:
            error = ("The action requires an non locked account. "
                     "The account is locked.")
            raise ValidationError(error)


class UserAccountNotLocked:
    """
    Check if the associated account is not locked
    """
    def __call__(self, value):
        user = value
        account = user.account
        AccountNotLocked()(account)


class MoneyField(Field):
    """
    Money objects are serialized into a string <Amount> <Currency>
    """

    def to_representation(self, obj):
        """ Money to string """
        return obj.__unicode__()

    def to_internal_value(self, data):
        """ String to Money """
        try:
            amount, currency = data.split()
        except:
            amount, currency = (data, 'EUR')

        return Money(amount, currency)



class AccountSerializer(ModelSerializer):
    balance = MoneyField(default=Money('0.00', 'EUR'), read_only=True)
    avatar = ImageField(read_only=True)

    locked = BooleanField(read_only=True, source='is_locked')

    class Meta:
        model = mete_models.Account
        fields = ['avatar', 'balance', 'locked', 'created_at',
                  'updated_at']


class UserSerializer(ModelSerializer):
    id = IntegerField(required=False)

    email = EmailField(required=False)

    first_name = CharField(required=False)
    last_name = CharField(required=False)

    account = AccountSerializer(many=False, required=False)

    def create(self, validated_data):
        # Create user
        try:
            account = validated_data.pop('account')
        except:
            # Well d'oh.
            pass

        user = auth_models.User.objects.create(**validated_data)
        return user

    class Meta:
        model = auth_models.User
        fields = ['id', 'username', 'email', 'first_name', 'last_name',
                  'account']


class ProductSerializer(ModelSerializer):

    price = MoneyField(default=Money('0.00', 'EUR'))
    prices = DictField(read_only=True)

    def get_prices(self, product):
        prices = [[str(p.price_set), str(p)] for p in product.price_set.all()]
        return dict(prices)

    class Meta:
        model = store_models.Product
        fields = ['id', 'name', 'picture', 'active', 'picture', 'prices',
                  'price']


class PurchaseSerializer(Serializer):
    """
    (De-)Serialize Purchase
    """
    product = PrimaryKeyRelatedField(
        many=False,
        queryset=store_models.Product.objects.all())

    def create(self, user):
        """
        Implement create to create, to perform purchase
        and create transaction.
        """

        # Assert user is not locked
        UserAccountNotLocked()(user)

        account = user.account

        # Get validated product
        product = self.validated_data['product']

        # Withdraw amount from account
        old_balance = account.balance
        new_balance = old_balance - product.price
        account.balance = new_balance
        account.save()

        # Add to transaction log
        mete_models.Transaction.objects.create(product=product,
                                               product_name=product.name,
                                               amount=-product.price )

        return {
            "product": product,
            "user": user,
            "old_balance": old_balance,
            "new_balance": new_balance,
        }


class DepositSerializer(Serializer):
    """
    Serialize a single money field as deposit.
    """
    amount = MoneyField(default=Money('0.00', 'EUR'))

    def create(self, user):
        """
        Deposit money on user account
        """
        # Assert user is not locked 
        UserAccountNotLocked()(user)

        account = user.account
        amount = self.validated_data['amount']

        old_balance = account.balance
        new_balance = account.balance + amount
        account.balance = new_balance
        account.save()

        # Add transaction to log
        mete_models.Transaction.objects.create(amount=amount)

        return {
            "user": user,
            "old_balance": old_balance,
            "new_balance": new_balance,
        }


class TransferSerializer(Serializer):
    """
    (De-)Serialize transfers
    """
    from_user = PrimaryKeyRelatedField(
        many=False,
        queryset=auth_models.User.objects.filter(is_active=True,
                                                 account__is_locked=False))

    to_user = PrimaryKeyRelatedField(
        many=False,
        queryset=auth_models.User.objects.filter(is_active=True,
                                                 account__is_locked=False))

    amount = MoneyField(default=Money('0.00', 'EUR'))

    def create(self):
        """
        Create a transfer between two accounts
        """
        from_user = self.validated_data['from_user']
        from_account = from_user.account

        to_user = self.validated_data['to_user']
        to_account = to_user.account

        amount = self.validated_data['amount']

        # Prevent stealing money
        if amount < Money(0, currency='EUR'):
            amount *= -1

        if from_account.id is not to_account.id:
            # Since the account was already loaded, this
            # would cause kind of a race condition and would lead to
            # spontaneous money formation.
            from_account.balance -= amount
            from_account.save()
            mete_models.Transaction.objects.create(amount=-amount)

            to_account.balance += amount
            to_account.save()
            mete_models.Transaction.objects.create(amount=amount)

        return {
            "from_account": from_account,
            "to_account": to_account,
            "amount": amount
        }


#
# == Session / Login
#
class LockedSessionUserSerializer(ModelSerializer):
    """Serialize only some of the fields"""

    class Meta:
        model = auth_models.User
        fields = ['id', 'username', 'first_name', 'last_name']


class SessionSerializer(Serializer):
    """ Serialize a user session """
    user = UserSerializer()
    is_authenticated = ReadOnlyField()
    is_active = ReadOnlyField()


class LockedSessionSerializer(Serializer):
    """Serialize a not (yet) activated session"""
    user = LockedSessionUserSerializer()
    is_authenticated = ReadOnlyField()
    is_active = ReadOnlyField()



class AuthenticationSerializer(Serializer):
    """
    Passwordless user authentication:
    Just expect a valid username.

    The session itself needs to be activated by a
    staff member in the admin backend.
    """
    username = CharField(required=True)
    client_identifier = CharField(required=True)

    def validate(self, data):
        """ Validate credentials """
        user = auth_models.User.objects\
            .filter(username=data['username'])\
            .first()

        if not user:
            raise ValidationError('Invalid credentials')

        # Set authentication backend to default ModelBackend
        user.backend = 'django.contrib.auth.backends.ModelBackend'

        data['user'] = user
        return data



#
# == Stats Serializers
#
class StatsDonationsSerializer(Serializer):
    """ Serialize Donation Amounts """
    total = MoneyField()
    current_month = MoneyField()


class StatsTransactionsSerializer(Serializer):
    """ Serialize Transactions Count """
    total = IntegerField()
    current_month = IntegerField()


class StatsSerializer(Serializer):
    """ Serialize stats """
    money_gauge = MoneyField()
    donations = StatsDonationsSerializer()
    transactions = StatsTransactionsSerializer()
    users = IntegerField()
    backend_version = CharField()


#
# == Transactions
#
class TransactionSerializer(Serializer):
    """ Serialize a single transaction """
    id = IntegerField()
    amount = MoneyField()
    product_name = CharField()
    product = ProductSerializer()
    created_at = DateTimeField()
