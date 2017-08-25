

from rest_framework import permissions
from sessionlock import models

class ActiveSessionOrAdmin(permissions.BasePermission):
    """
    Allow access if the session was activated
    by an admin.
    """
    def has_permission(self, request, view):
        """Check session"""
        # Is authenticated?
        if not request.user:
            return False # We are not even authenticated.

        # Is admin?
        if request.user.is_staff:
            return True

        # Otherwise: Check if we have an activated session
        key = request.session.session_key
        lock = models.Lock.objects.filter(session_id=key).first()
        if not lock:
            # This session is not even authenticated
            return False

        # If the session is activated, we allow the user
        # full access to the API.
        return lock.session_active




