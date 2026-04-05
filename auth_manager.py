"""
Authentication Manager

JWT-based authentication with user session management,
password hashing, and security features.
"""

import hashlib
import secrets
import jwt
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any
import bcrypt
import re

from src.auth.models import (
    User, UserInDB, UserLogin, UserCreate, Token, TokenData,
    Session, AuthEvent, PasswordChange, UserRole
)
from config.config import get_config
from config.security_config import get_security_config


class AuthenticationError(Exception):
    """Raised when authentication fails"""
    pass


class AuthorizationError(Exception):
    """Raised when authorization fails"""
    pass


class AuthManager:
    """
    Authentication Manager
    
    Handles user authentication, JWT token generation/validation,
    password hashing, and session management.
    """
    
    def __init__(self):
        """Initialize authentication manager"""
        self.config = get_config()
        self.security_config = get_security_config()
        
        # Initialize database
        from src.auth.database import init_db, get_db
        from src.auth.db_models import UserDB, SessionDB, AuthEventDB
        
        try:
            init_db()
        except Exception as e:
            print(f"[WARN] Database initialization warning: {e}")
        
        self.get_db = get_db
        self._UserDB = UserDB
        self._SessionDB = SessionDB
        self._AuthEventDB = AuthEventDB
        
        # Create default admin user if none exists
        self._create_default_users()
    
    def _create_default_users(self):
        """Create default users for development"""
        if not self.config.is_production:
            db = next(self.get_db())
            try:
                # Check if admin exists
                admin_exists = db.query(self._UserDB).filter(
                    self._UserDB.username == "admin"
                ).first()
                
                if not admin_exists:
                    # Admin user
                    admin = self.create_user(UserCreate(
                        username="admin",
                        password="admin123",  # Change in production!
                        full_name="System Administrator",
                        role=UserRole.ADMIN
                    ))
                    
                    # Operator user
                    operator = self.create_user(UserCreate(
                        username="operator",
                        password="operator123",
                        full_name="Security Operator",
                        role=UserRole.OPERATOR
                    ))
                    
                    print("[OK] Created default users: admin/admin123, operator/operator123")
                else:
                    print("[OK] Default users already exist")
            except Exception as e:
                print(f"[WARN] Error creating default users: {e}")
            finally:
                db.close()
    
    # ==================== PASSWORD HASHING ====================
    
    def hash_password(self, password: str) -> Tuple[str, str]:
        """
        Hash password with bcrypt
        
        Args:
            password: Plain text password
            
        Returns:
            Tuple of (hashed_password, salt)
        """
        # Generate salt
        salt = bcrypt.gensalt()
        
        # Hash password
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        
        return hashed.decode('utf-8'), salt.decode('utf-8')
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verify password against hash
        
        Args:
            password: Plain text password
            hashed_password: Hashed password
            
        Returns:
            True if password matches
        """
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'),
                hashed_password.encode('utf-8')
            )
        except Exception:
            return False
    
    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """
        Validate password strength
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, message)
        """
        auth_config = self.security_config.auth
        
        if len(password) < auth_config.password_min_length:
            return False, f"Password must be at least {auth_config.password_min_length} characters"
        
        if auth_config.password_require_uppercase and not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if auth_config.password_require_lowercase and not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if auth_config.password_require_numbers and not re.search(r'\d', password):
            return False, "Password must contain at least one number"
        
        if auth_config.password_require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        
        return True, "Password is strong"
    
    # ==================== USER MANAGEMENT ====================
    
    def create_user(self, user_data: UserCreate) -> User:
        """
        Create new user
        
        Args:
            user_data: User creation data
            
        Returns:
            Created user (without password)
        """
        db = next(self.get_db())
        try:
            # Check if username exists
            existing_user = db.query(self._UserDB).filter(
                self._UserDB.username == user_data.username
            ).first()
            
            if existing_user:
                raise ValueError(f"Username '{user_data.username}' already exists")
            
            # Check if email exists (if provided)
            if user_data.email:
                existing_email = db.query(self._UserDB).filter(
                    self._UserDB.email == user_data.email
                ).first()
                
                if existing_email:
                    raise ValueError(f"Email '{user_data.email}' is already registered")
            
            # Validate password strength
            is_valid, msg = self.validate_password_strength(user_data.password)
            if not is_valid:
                raise ValueError(msg)
            
            # Hash password
            hashed_password, salt = self.hash_password(user_data.password)
            
            # Create user ID
            user_id = secrets.token_urlsafe(16)
            
            # Create database user
            db_user = self._UserDB(
                id=user_id,
                username=user_data.username,
                email=user_data.email,
                full_name=user_data.full_name,
                role=user_data.role,
                hashed_password=hashed_password,
                salt=salt,
                is_active=True
            )
            
            db.add(db_user)
            db.commit()
            db.refresh(db_user)
            
            # Log event
            self._log_auth_event(AuthEvent(
                event_type="user_created",
                username=user_data.username,
                success=True,
                details=f"Role: {user_data.role.value}"
            ))
            
            # Return user without password
            return User(
                id=db_user.id,
                username=db_user.username,
                email=db_user.email,
                full_name=db_user.full_name,
                role=db_user.role,
                is_active=db_user.is_active,
                is_verified=db_user.is_verified,
                created_at=db_user.created_at,
                last_login=db_user.last_login
            )
        finally:
            db.close()
    
    def get_user(self, username: str) -> Optional[User]:
        """Get user by username"""
        db = next(self.get_db())
        try:
            db_user = db.query(self._UserDB).filter(
                self._UserDB.username == username
            ).first()
            
            if db_user:
                return User(
                    id=db_user.id,
                    username=db_user.username,
                    email=db_user.email,
                    full_name=db_user.full_name,
                    role=db_user.role,
                    is_active=db_user.is_active,
                    is_verified=db_user.is_verified,
                    created_at=db_user.created_at,
                    last_login=db_user.last_login
                )
            return None
        finally:
            db.close()
    
    # ==================== AUTHENTICATION ====================
    
    def authenticate(self, login_data: UserLogin, ip_address: Optional[str] = None) -> Token:
        """
        Authenticate user and generate JWT token
        
        Args:
            login_data: Login credentials
            ip_address: Client IP address
            
        Returns:
            JWT token
            
        Raises:
            AuthenticationError: If authentication fails
        """
        db = next(self.get_db())
        try:
            user = db.query(self._UserDB).filter(
                self._UserDB.username == login_data.username
            ).first()
            
            # Check if user exists
            if not user:
                self._log_auth_event(AuthEvent(
                    event_type="failed_login",
                    username=login_data.username,
                    success=False,
                    ip_address=ip_address,
                    details="User not found"
                ))
                raise AuthenticationError("Invalid username or password")
            
            # Check if account is locked
            if user.locked_until and user.locked_until > datetime.utcnow():
                self._log_auth_event(AuthEvent(
                    event_type="failed_login",
                    username=login_data.username,
                    success=False,
                    ip_address=ip_address,
                    details="Account locked"
                ))
                raise AuthenticationError(f"Account locked until {user.locked_until.isoformat()}")
            
            # Check if user is active
            if not user.is_active:
                raise AuthenticationError("Account is disabled")
            
            # Verify password
            if not self.verify_password(login_data.password, user.hashed_password):
                # Increment failed attempts
                user.failed_login_attempts += 1
                
                # Lock account if too many failures
                max_attempts = self.security_config.auth.max_login_attempts
                if user.failed_login_attempts >= max_attempts:
                    lockout_minutes = self.security_config.auth.lockout_duration_minutes
                    user.locked_until = datetime.utcnow() + timedelta(minutes=lockout_minutes)
                    
                    self._log_auth_event(AuthEvent(
                        event_type="account_locked",
                        username=login_data.username,
                        success=False,
                        ip_address=ip_address,
                        details=f"Too many failed attempts ({user.failed_login_attempts})"
                    ))
                    
                    raise AuthenticationError(
                        f"Too many failed attempts. Account locked for {lockout_minutes} minutes."
                    )
                
                self._log_auth_event(AuthEvent(
                    event_type="failed_login",
                    username=login_data.username,
                    success=False,
                    ip_address=ip_address,
                    details=f"Invalid password (attempt {user.failed_login_attempts})"
                ))
                
                raise AuthenticationError("Invalid username or password")
            
            # Reset failed attempts on successful login
            user.failed_login_attempts = 0
            user.locked_until = None
            user.last_login = datetime.utcnow()
            db.commit()
            
            # Generate JWT token
            token = self._generate_jwt_token(user, login_data.remember_me)
            
            # Create session
            self._create_session(user, ip_address)
            
            # Log successful login
            self._log_auth_event(AuthEvent(
                event_type="login",
                username=login_data.username,
                success=True,
                ip_address=ip_address
            ))
            
            return token
        finally:
            db.close()
    
    def _generate_jwt_token(self, user, remember_me: bool = False) -> Token:
        """Generate JWT token for user"""
        auth_config = self.security_config.auth
        
        # Set expiration
        if remember_me:
            expires_delta = timedelta(days=auth_config.remember_me_days)
        else:
            expires_delta = timedelta(minutes=auth_config.jwt_expiration_minutes)
        
        expires_at = datetime.utcnow() + expires_delta
        
        # Create payload
        payload = {
            "sub": user.username,
            "role": user.role.value,
            "exp": expires_at,
            "iat": datetime.utcnow(),
            "jti": secrets.token_urlsafe(16)
        }
        
        # Encode token
        token = jwt.encode(
            payload,
            self.config.get("jwt_secret"),
            algorithm=auth_config.jwt_algorithm
        )
        
        return Token(
            access_token=token,
            expires_in=int(expires_delta.total_seconds())
        )
    
    def verify_token(self, token: str) -> TokenData:
        """
        Verify and decode JWT token
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded token data
            
        Raises:
            AuthenticationError: If token is invalid
        """
        try:
            payload = jwt.decode(
                token,
                self.config.get("jwt_secret"),
                algorithms=[self.security_config.auth.jwt_algorithm]
            )
            
            return TokenData(
                username=payload["sub"],
                role=UserRole(payload["role"]),
                exp=datetime.fromtimestamp(payload["exp"]),
                iat=datetime.fromtimestamp(payload["iat"]),
                jti=payload.get("jti")
            )
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except jwt.JWTError as e:
            raise AuthenticationError(f"Invalid token: {str(e)}")
    
    # ==================== SESSION MANAGEMENT ====================
    
    def _create_session(self, user, ip_address: Optional[str] = None) -> Session:
        """Create user session"""
        db = next(self.get_db())
        try:
            session_id = secrets.token_urlsafe(32)
            
            expires_at = datetime.utcnow() + timedelta(
                minutes=self.security_config.auth.session_timeout_minutes
            )
            
            # Get role from user (handle both DB model and UserInDB)
            user_role = user.role if hasattr(user, 'role') else UserRole.VIEWER
            
            db_session = self._SessionDB(
                session_id=session_id,
                user_id=user.id,
                username=user.username,
                role=user_role,
                expires_at=expires_at,
                ip_address=ip_address
            )
            
            db.add(db_session)
            db.commit()
            db.refresh(db_session)
            
            return Session(
                session_id=db_session.session_id,
                user_id=db_session.user_id,
                username=db_session.username,
                role=db_session.role,
                created_at=db_session.created_at,
                last_activity=db_session.last_activity,
                expires_at=db_session.expires_at,
                ip_address=db_session.ip_address,
                is_active=db_session.is_active
            )
        finally:
            db.close()
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID"""
        db = next(self.get_db())
        try:
            db_session = db.query(self._SessionDB).filter(
                self._SessionDB.session_id == session_id,
                self._SessionDB.is_active == True
            ).first()
            
            if db_session and db_session.expires_at > datetime.utcnow():
                # Update last activity
                db_session.last_activity = datetime.utcnow()
                db.commit()
                
                return Session(
                    session_id=db_session.session_id,
                    user_id=db_session.user_id,
                    username=db_session.username,
                    role=db_session.role,
                    created_at=db_session.created_at,
                    last_activity=db_session.last_activity,
                    expires_at=db_session.expires_at,
                    ip_address=db_session.ip_address,
                    is_active=db_session.is_active
                )
            return None
        finally:
            db.close()
    
    def invalidate_session(self, session_id: str):
        """Invalidate session"""
        db = next(self.get_db())
        try:
            db_session = db.query(self._SessionDB).filter(
                self._SessionDB.session_id == session_id
            ).first()
            
            if db_session:
                db_session.is_active = False
                db.commit()
        finally:
            db.close()
    
    # ==================== AUDIT LOGGING ====================
    
    def _log_auth_event(self, event: AuthEvent):
        """Log authentication event"""
        db = next(self.get_db())
        try:
            db_event = self._AuthEventDB(
                event_type=event.event_type,
                username=event.username,
                success=event.success,
                ip_address=event.ip_address,
                user_agent=event.user_agent,
                details=event.details
            )
            db.add(db_event)
            db.commit()
            
            # Print in development
            if not self.config.is_production:
                status = "[SUCCESS]" if event.success else "[FAILED]"
                print(f"{status} Auth Event: {event.event_type} - {event.username}")
        except Exception as e:
            print(f"[WARN] Error logging auth event: {e}")
        finally:
            db.close()
    
    def get_auth_events(self, username: Optional[str] = None, limit: int = 100) -> list[AuthEvent]:
        """Get authentication events"""
        db = next(self.get_db())
        try:
            query = db.query(self._AuthEventDB)
            
            if username:
                query = query.filter(self._AuthEventDB.username == username)
            
            db_events = query.order_by(self._AuthEventDB.timestamp.desc()).limit(limit).all()
            
            return [
                AuthEvent(
                    event_type=e.event_type,
                    username=e.username,
                    success=e.success,
                    ip_address=e.ip_address,
                    user_agent=e.user_agent,
                    timestamp=e.timestamp,
                    details=e.details
                )
                for e in db_events
            ]
        finally:
            db.close()
    
    # ==================== OAUTH AUTHENTICATION ====================
    
    def authenticate_oauth(self, oauth_user_info, ip_address: Optional[str] = None) -> Tuple[User, Token]:
        """
        Authenticate or create user from OAuth info
        
        Args:
            oauth_user_info: OAuthUserInfo from OAuth provider
            ip_address: Client IP address
            
        Returns:
            Tuple of (User, Token)
        """
        from src.auth.db_models import OAuthConnectionDB
        from src.auth.oauth import OAuthProvider
        
        db = next(self.get_db())
        try:
            # Check if OAuth connection already exists
            oauth_conn = db.query(OAuthConnectionDB).filter(
                OAuthConnectionDB.provider == oauth_user_info.provider.value,
                OAuthConnectionDB.provider_user_id == oauth_user_info.provider_user_id
            ).first()
            
            if oauth_conn:
                # Existing user - get user and update tokens
                user = db.query(self._UserDB).filter(
                    self._UserDB.id == oauth_conn.user_id
                ).first()
                
                if not user:
                    raise AuthenticationError("OAuth connection found but user not found")
                
                # Update OAuth tokens
                # Note: In production, you'd store the access/refresh tokens
                user.last_login = datetime.utcnow()
                db.commit()
                
                # Generate JWT token
                token = self._generate_jwt_token(user)
                
                self._log_auth_event(AuthEvent(
                    event_type="oauth_login",
                    username=user.username,
                    success=True,
                    ip_address=ip_address,
                    details=f"Provider: {oauth_user_info.provider.value}"
                ))
                
                return User(
                    id=user.id,
                    username=user.username,
                    email=user.email,
                    full_name=user.full_name,
                    role=user.role,
                    is_active=user.is_active,
                    is_verified=user.is_verified,
                    created_at=user.created_at,
                    last_login=user.last_login
                ), token
            else:
                # New user - create account
                # Generate unique username from OAuth info
                base_username = oauth_user_info.username or oauth_user_info.email.split('@')[0] if oauth_user_info.email else f"user_{secrets.token_hex(4)}"
                username = self._generate_unique_username(db, base_username)
                
                # Create user
                user_id = secrets.token_urlsafe(16)
                new_user = self._UserDB(
                    id=user_id,
                    username=username,
                    email=oauth_user_info.email,
                    full_name=oauth_user_info.name,
                    role=UserRole.VIEWER,
                    hashed_password=None,  # No password for OAuth-only users
                    salt=None,
                    is_active=True,
                    is_verified=True,  # OAuth users are considered verified
                    avatar_url=oauth_user_info.avatar_url
                )
                
                db.add(new_user)
                db.commit()
                db.refresh(new_user)
                
                # Create OAuth connection
                oauth_conn = OAuthConnectionDB(
                    id=secrets.token_urlsafe(16),
                    user_id=user_id,
                    provider=oauth_user_info.provider.value,
                    provider_user_id=oauth_user_info.provider_user_id
                )
                
                db.add(oauth_conn)
                db.commit()
                
                # Generate JWT token
                token = self._generate_jwt_token(new_user)
                
                self._log_auth_event(AuthEvent(
                    event_type="oauth_register",
                    username=username,
                    success=True,
                    ip_address=ip_address,
                    details=f"Provider: {oauth_user_info.provider.value}"
                ))
                
                return User(
                    id=new_user.id,
                    username=new_user.username,
                    email=new_user.email,
                    full_name=new_user.full_name,
                    role=new_user.role,
                    is_active=new_user.is_active,
                    is_verified=new_user.is_verified,
                    created_at=new_user.created_at,
                    last_login=new_user.last_login
                ), token
                
        except Exception as e:
            db.rollback()
            raise AuthenticationError(f"OAuth authentication failed: {str(e)}")
        finally:
            db.close()
    
    def _generate_unique_username(self, db, base_username: str) -> str:
        """Generate unique username if base is taken"""
        # Clean username
        username = re.sub(r'[^a-zA-Z0-9_]', '_', base_username.lower())[:45]
        
        if len(username) < 3:
            username = f"user_{secrets.token_hex(4)}"
        
        # Check if exists
        existing = db.query(self._UserDB).filter(
            self._UserDB.username == username
        ).first()
        
        if not existing:
            return username
        
        # Add suffix
        for i in range(1, 1000):
            new_username = f"{username}_{i}"
            if not db.query(self._UserDB).filter(
                self._UserDB.username == new_username
            ).first():
                return new_username
        
        return f"user_{secrets.token_hex(8)}"


# Global authentication manager
_auth_manager: Optional[AuthManager] = None


def get_auth_manager() -> AuthManager:
    """Get global authentication manager"""
    global _auth_manager
    
    if _auth_manager is None:
        _auth_manager = AuthManager()
    
    return _auth_manager
