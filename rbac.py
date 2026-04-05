"""
Role-Based Access Control (RBAC)

Permission checking, role management, and access control decorators.
"""

from typing import List, Callable, Optional
from functools import wraps
import streamlit as st

from src.auth.models import UserRole, User
from src.auth.auth_manager import AuthorizationError
from config.security_config import get_security_config


class RBAC:
    """Role-Based Access Control Manager"""
    
    def __init__(self):
        """Initialize RBAC with configuration"""
        self.security_config = get_security_config()
        self.rbac_config = self.security_config.rbac
    
    def has_permission(self, user: User, permission: str) -> bool:
        """
        Check if user has permission
        
        Args:
            user: User to check
            permission: Permission name
            
        Returns:
            True if user has permission
        """
        if not self.rbac_config.enabled:
            return True  # RBAC disabled
        
        return self.rbac_config.has_permission(user.role.value, permission)
    
    def require_permission(self, user: User, permission: str):
        """
        Require user to have permission
        
        Args:
            user: User to check
            permission: Required permission
            
        Raises:
            AuthorizationError: If user lacks permission
        """
        if not self.has_permission(user, permission):
            raise AuthorizationError(
                f"User '{user.username}' with role '{user.role.value}' "
                f"does not have permission '{permission}'"
            )
    
    def require_role(self, user: User, roles: List[UserRole]):
        """
        Require user to have one of the specified roles
        
        Args:
            user: User to check
            roles: List of acceptable roles
            
        Raises:
            AuthorizationError: If user doesn't have required role
        """
        if user.role not in roles:
            raise AuthorizationError(
                f"User '{user.username}' with role '{user.role.value}' "
                f"does not have required role (need: {[r.value for r in roles]})"
            )
    
    def get_user_permissions(self, user: User) -> List[str]:
        """Get all permissions for user's role"""
        return self.rbac_config.get_role_permissions(user.role.value)
    
    def can_execute_scan(self, user: User) -> bool:
        """Check if user can execute scans"""
        return self.has_permission(user, "run_scans")
    
    def can_execute_attack(self, user: User) -> bool:
        """Check if user can execute attacks"""
        return self.has_permission(user, "run_attacks")
    
    def can_modify_config(self, user: User) -> bool:
        """Check if user can modify configuration"""
        return self.has_permission(user, "modify_config")
    
    def can_manage_users(self, user: User) -> bool:
        """Check if user can manage users"""
        return self.has_permission(user, "manage_users")
    
    def can_view_logs(self, user: User) -> bool:
        """Check if user can view logs"""
        return self.has_permission(user, "view_logs")


# Decorators for permission checking

def require_auth(func: Callable) -> Callable:
    """
    Decorator to require authentication
    
    Usage:
        @require_auth
        def protected_function():
            pass
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Check if user is authenticated
        if "user" not in st.session_state or st.session_state.user is None:
            st.error("🔒 Authentication required")
            st.switch_page("pages/00_Login_Optimized.py")
            st.stop()
        
        return func(*args, **kwargs)
    
    return wrapper


def require_permission(permission: str):
    """
    Decorator to require specific permission
    
    Usage:
        @require_permission("run_scans")
        def scan_function():
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Check authentication first
            if "user" not in st.session_state or st.session_state.user is None:
                st.error("🔒 Authentication required")
                st.switch_page("pages/00_Login_Optimized.py")
                st.stop()
            
            # Check permission
            rbac = get_rbac()
            user = st.session_state.user
            
            if not rbac.has_permission(user, permission):
                st.error(f"🚫 Permission denied: You need '{permission}' permission")
                st.stop()
            
            return func(*args, **kwargs)
        
        return wrapper
    
    return decorator


def require_role(*roles: UserRole):
    """
    Decorator to require specific role(s)
    
    Usage:
        @require_role(UserRole.ADMIN, UserRole.OPERATOR)
        def admin_function():
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Check authentication first
            if "user" not in st.session_state or st.session_state.user is None:
                st.error("🔒 Authentication required")
                st.switch_page("pages/00_Login_Optimized.py")
                st.stop()
            
            # Check role
            rbac = get_rbac()
            user = st.session_state.user
            
            try:
                rbac.require_role(user, list(roles))
            except AuthorizationError as e:
                st.error(f"🚫 {str(e)}")
                st.stop()
            
            return func(*args, **kwargs)
        
        return wrapper
    
    return decorator


# Streamlit UI helpers

def show_permission_error(permission: str):
    """Show permission error message"""
    st.error(f"🚫 You don't have permission to perform this action")
    st.info(f"Required permission: **{permission}**")


def check_permission_ui(user: User, permission: str, show_error: bool = True) -> bool:
    """
    Check permission and optionally show error in UI
    
    Args:
        user: Current user
        permission: Permission to check
        show_error: Show error message if permission denied
        
    Returns:
        True if user has permission
    """
    rbac = get_rbac()
    has_perm = rbac.has_permission(user, permission)
    
    if not has_perm and show_error:
        show_permission_error(permission)
    
    return has_perm


def get_current_user() -> Optional[User]:
    """Get current authenticated user from session"""
    return st.session_state.get("user")


def is_admin() -> bool:
    """Check if current user is admin"""
    user = get_current_user()
    return user is not None and user.role == UserRole.ADMIN


def is_operator() -> bool:
    """Check if current user is operator or admin"""
    user = get_current_user()
    return user is not None and user.role in [UserRole.ADMIN, UserRole.OPERATOR]


# Global RBAC instance
_rbac: Optional[RBAC] = None


def get_rbac() -> RBAC:
    """Get global RBAC instance"""
    global _rbac
    
    if _rbac is None:
        _rbac = RBAC()
    
    return _rbac
