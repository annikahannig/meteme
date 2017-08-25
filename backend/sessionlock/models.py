from __future__ import unicode_literals

from django.db import models
from django.contrib.sessions.models import Session as DjangoSession
from django.contrib.auth.models import User as AuthUser


class Lock(models.Model):
    """
    This extends the base session with additional
    information, like: is this session activated.
    """
    session = models.OneToOneField(DjangoSession,
                                null=False,
                                blank=False,
                                on_delete=models.CASCADE)


    # Some metadata
    user_agent = models.CharField(max_length=255)

    client_ip = models.CharField(max_length=40)
    client_identifier = models.CharField(max_length=60)

    # The actual switch
    session_active = models.BooleanField(default=False)

    # Keep track of this
    updated_at = models.DateTimeField(auto_now=True)


    @property
    def user(self):
        """Get the corresponding auth user"""
        auth_user_id = self.session.get_decoded().get('_auth_user_id')
        if not auth_user_id:
            return None
        user = AuthUser.objects.get(pk=auth_user_id)
        return user


