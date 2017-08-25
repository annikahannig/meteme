from __future__ import unicode_literals

from django.db import models
from django.contrib.sessions.models import Session as DjangoSession


class Lock(models.Model):
    """
    This extends the base session with additional
    information, like: is this session activated.
    """
    session = models.OneToOneField(DjangoSession,
                                null=False,
                                blank=False,
                                on_delete=models.CASCADE)

    session_active = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)

