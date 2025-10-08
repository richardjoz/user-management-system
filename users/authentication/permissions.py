from rest_framework.permissions import BasePermission
from users.models import UserLogin

class IsUserAuthenticated(BasePermission):
    """
    Allows access only to authenticated normal users.
    """

    def has_permission(self, request, view):
        return isinstance(request.user, UserLogin)
