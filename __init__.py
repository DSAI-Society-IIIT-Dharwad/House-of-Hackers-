"""
Authentication Module

JWT-based authentication, RBAC, and user management.
"""

from src.auth.models import (
    User, UserCreate, UserLogin, UserRole, Token,
    TokenData, Session, AuthEvent, PasswordChange
)
from src.auth.auth_manager import (
    AuthManager, get_auth_manager,
    AuthenticationError, AuthorizationError
)
from src.auth.rbac import (
    RBAC, get_rbac,
    require_auth, require_permission, require_role,
    get_current_user, is_admin, is_operator
)

__all__ = [
    # Models
    "User",
    "UserCreate",
    "UserLogin",
    "UserRole",
    "Token",
    "TokenData",
    "Session",
    "AuthEvent",
    "PasswordChange",
    
    # Auth Manager
    "AuthManager",
    "get_auth_manager",
    "AuthenticationError",
    "AuthorizationError",
    
    # RBAC
    "RBAC",
    "get_rbac",
    "require_auth",
    "require_permission",
    "require_role",
    "get_current_user",
    "is_admin",
    "is_operator",
]
