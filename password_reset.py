"""
Password Reset Module

Handles password reset requests, token generation, email sending,
and password reset completion.
"""

import secrets
from datetime import datetime, timedelta
from typing import Optional, Tuple
from dataclasses import dataclass

from src.auth.database import get_db
from src.auth.db_models import UserDB, PasswordResetTokenDB
from config.config import get_config


@dataclass
class PasswordResetRequest:
    """Password reset request data"""
    email: str
    ip_address: Optional[str] = None


@dataclass
class PasswordResetResult:
    """Result of password reset operation"""
    success: bool
    message: str
    token: Optional[str] = None


class PasswordResetManager:
    """
    Password Reset Manager
    
    Handles the complete password reset flow:
    1. User requests reset with email
    2. System generates token and sends email
    3. User clicks link with token
    4. User sets new password
    """
    
    def __init__(self):
        """Initialize password reset manager"""
        self.config = get_config()
        self.token_expiry_hours = 1  # Tokens expire in 1 hour
        self.max_attempts_per_hour = 3  # Rate limiting
    
    def request_reset(self, email: str, ip_address: Optional[str] = None) -> PasswordResetResult:
        """
        Request password reset for an email
        
        Args:
            email: User email address
            ip_address: Client IP for rate limiting
            
        Returns:
            PasswordResetResult with success status
        """
        db = next(get_db())
        try:
            # Find user by email
            user = db.query(UserDB).filter(
                UserDB.email == email
            ).first()
            
            # Always return success to prevent email enumeration
            if not user:
                return PasswordResetResult(
                    success=True,
                    message="If an account exists with this email, a reset link has been sent."
                )
            
            # Check rate limiting
            recent_tokens = db.query(PasswordResetTokenDB).filter(
                PasswordResetTokenDB.user_id == user.id,
                PasswordResetTokenDB.created_at > datetime.utcnow() - timedelta(hours=1)
            ).count()
            
            if recent_tokens >= self.max_attempts_per_hour:
                return PasswordResetResult(
                    success=False,
                    message="Too many reset requests. Please try again later."
                )
            
            # Invalidate old tokens for this user
            db.query(PasswordResetTokenDB).filter(
                PasswordResetTokenDB.user_id == user.id,
                PasswordResetTokenDB.used == False
            ).update({"used": True})
            
            # Generate new token
            token = secrets.token_urlsafe(32)
            token_hash = self._hash_token(token)
            
            reset_token = PasswordResetTokenDB(
                id=secrets.token_urlsafe(16),
                user_id=user.id,
                token_hash=token_hash,
                expires_at=datetime.utcnow() + timedelta(hours=self.token_expiry_hours)
            )
            
            db.add(reset_token)
            db.commit()
            
            # Send email (in production, integrate with SendGrid/Resend)
            self._send_reset_email(user.email, user.username, token)
            
            return PasswordResetResult(
                success=True,
                message="If an account exists with this email, a reset link has been sent.",
                token=token  # In production, don't return token - it's in the email
            )
            
        except Exception as e:
            db.rollback()
            return PasswordResetResult(
                success=False,
                message=f"Error processing request: {str(e)}"
            )
        finally:
            db.close()
    
    def validate_token(self, token: str) -> Tuple[bool, Optional[str]]:
        """
        Validate password reset token
        
        Args:
            token: Reset token from email link
            
        Returns:
            Tuple of (is_valid, user_id)
        """
        db = next(get_db())
        try:
            token_hash = self._hash_token(token)
            
            reset_token = db.query(PasswordResetTokenDB).filter(
                PasswordResetTokenDB.token_hash == token_hash,
                PasswordResetTokenDB.used == False,
                PasswordResetTokenDB.expires_at > datetime.utcnow()
            ).first()
            
            if not reset_token:
                return False, None
            
            return True, reset_token.user_id
            
        finally:
            db.close()
    
    def reset_password(self, token: str, new_password: str, confirm_password: str) -> PasswordResetResult:
        """
        Complete password reset with new password
        
        Args:
            token: Reset token from email
            new_password: New password
            confirm_password: Password confirmation
            
        Returns:
            PasswordResetResult with success status
        """
        from src.auth.auth_manager import get_auth_manager, AuthenticationError
        
        db = next(get_db())
        try:
            # Validate token
            is_valid, user_id = self.validate_token(token)
            
            if not is_valid:
                return PasswordResetResult(
                    success=False,
                    message="Invalid or expired reset token."
                )
            
            # Validate passwords match
            if new_password != confirm_password:
                return PasswordResetResult(
                    success=False,
                    message="Passwords do not match."
                )
            
            # Validate password strength
            auth_manager = get_auth_manager()
            is_strong, msg = auth_manager.validate_password_strength(new_password)
            
            if not is_strong:
                return PasswordResetResult(
                    success=False,
                    message=msg
                )
            
            # Get user
            user = db.query(UserDB).filter(UserDB.id == user_id).first()
            
            if not user:
                return PasswordResetResult(
                    success=False,
                    message="User not found."
                )
            
            # Hash new password
            hashed_password, salt = auth_manager.hash_password(new_password)
            
            # Update user password
            user.hashed_password = hashed_password
            user.salt = salt
            user.failed_login_attempts = 0
            user.locked_until = None
            
            # Mark token as used
            token_hash = self._hash_token(token)
            db.query(PasswordResetTokenDB).filter(
                PasswordResetTokenDB.token_hash == token_hash
            ).update({"used": True})
            
            db.commit()
            
            # Log event
            from src.auth.models import AuthEvent
            auth_manager._log_auth_event(AuthEvent(
                event_type="password_reset",
                username=user.username,
                success=True
            ))
            
            return PasswordResetResult(
                success=True,
                message="Password has been reset successfully. You can now login with your new password."
            )
            
        except Exception as e:
            db.rollback()
            return PasswordResetResult(
                success=False,
                message=f"Error resetting password: {str(e)}"
            )
        finally:
            db.close()
    
    def _hash_token(self, token: str) -> str:
        """Hash token for storage"""
        import hashlib
        return hashlib.sha256(token.encode()).hexdigest()
    
    def _send_reset_email(self, email: str, username: str, token: str):
        """
        Send password reset email
        
        In production, integrate with SendGrid, Resend, or similar.
        For development, just log the reset link.
        """
        base_url = self.config.get("base_url", "http://localhost:8501")
        reset_url = f"{base_url}/reset-password?token={token}"
        
        # Development: Print reset link
        if not self.config.is_production:
            print(f"\n{'='*60}")
            print(f"PASSWORD RESET EMAIL (Development Mode)")
            print(f"{'='*60}")
            print(f"To: {email}")
            print(f"Username: {username}")
            print(f"Reset URL: {reset_url}")
            print(f"Expires in: {self.token_expiry_hours} hour(s)")
            print(f"{'='*60}\n")
        
        # TODO: Production email sending
        # Example with SendGrid:
        # from sendgrid import SendGridAPIClient
        # from sendgrid.helpers.mail import Mail
        # 
        # message = Mail(
        #     from_email=self.config.get("from_email"),
        #     to_emails=email,
        #     subject="Decepticon - Password Reset",
        #     html_content=f"""
        #     <h2>Password Reset Request</h2>
        #     <p>Hello {username},</p>
        #     <p>Click the link below to reset your password:</p>
        #     <a href="{reset_url}">Reset Password</a>
        #     <p>This link expires in 1 hour.</p>
        #     """
        # )
        # sg = SendGridAPIClient(self.config.get("sendgrid_api_key"))
        # sg.send(message)


# Global password reset manager
_password_reset_manager: Optional[PasswordResetManager] = None


def get_password_reset_manager() -> PasswordResetManager:
    """Get or create password reset manager instance"""
    global _password_reset_manager
    if _password_reset_manager is None:
        _password_reset_manager = PasswordResetManager()
    return _password_reset_manager
