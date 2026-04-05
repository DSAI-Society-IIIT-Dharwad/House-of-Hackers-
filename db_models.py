"""
Database Models for Authentication

SQLAlchemy ORM models for users and sessions.
"""

from sqlalchemy import Column, String, Boolean, DateTime, Integer, Enum as SQLEnum, Text, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from datetime import datetime
from src.auth.database import Base
from src.auth.models import UserRole


class UserDB(Base):
    """User database model"""
    __tablename__ = "users"
    
    id = Column(String(32), primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=True)
    full_name = Column(String(255), nullable=True)
    hashed_password = Column(String(255), nullable=True)  # Nullable for OAuth-only users
    salt = Column(String(255), nullable=True)
    role = Column(SQLEnum(UserRole), default=UserRole.VIEWER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    last_login = Column(DateTime, nullable=True)
    avatar_url = Column(String(500), nullable=True)  # For OAuth avatars
    phone_number = Column(String(20), nullable=True, index=True)
    preferences = Column(Text, nullable=True)  # Store JSON preferences
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationship to OAuth connections
    oauth_connections = relationship("OAuthConnectionDB", back_populates="user")
    
    def __repr__(self):
        return f"<User {self.username} ({self.role.value})>"


class OAuthConnectionDB(Base):
    """OAuth connection database model for linking external providers"""
    __tablename__ = "oauth_connections"
    
    id = Column(String(32), primary_key=True)
    user_id = Column(String(32), ForeignKey("users.id"), nullable=False, index=True)
    provider = Column(String(20), nullable=False, index=True)  # google, github, microsoft
    provider_user_id = Column(String(100), nullable=False)
    access_token = Column(Text, nullable=True)
    refresh_token = Column(Text, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationship to user
    user = relationship("UserDB", back_populates="oauth_connections")
    
    # Unique constraint on provider + provider_user_id
    __table_args__ = (
        {"schema": None},
    )
    
    def __repr__(self):
        return f"<OAuthConnection {self.provider} for user {self.user_id}>"


class SessionDB(Base):
    """Session database model"""
    __tablename__ = "sessions"
    
    session_id = Column(String(64), primary_key=True, index=True)
    user_id = Column(String(32), index=True, nullable=False)
    username = Column(String(50), index=True, nullable=False)
    role = Column(SQLEnum(UserRole), nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    last_activity = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    ip_address = Column(String(45), nullable=True)  # IPv6 max length
    user_agent = Column(String(500), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    
    def __repr__(self):
        return f"<Session {self.session_id} for {self.username}>"


class AuthEventDB(Base):
    """Authentication event database model for audit logging"""
    __tablename__ = "auth_events"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String(50), nullable=False, index=True)
    username = Column(String(50), nullable=False, index=True)
    success = Column(Boolean, nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    timestamp = Column(DateTime, default=func.now(), nullable=False, index=True)
    details = Column(String(500), nullable=True)
    
    def __repr__(self):
        status = "✅" if self.success else "❌"
        return f"<AuthEvent {status} {self.event_type} - {self.username}>"


class PasswordResetTokenDB(Base):
    """Password reset token database model"""
    __tablename__ = "password_reset_tokens"
    
    id = Column(String(32), primary_key=True)
    user_id = Column(String(32), ForeignKey("users.id"), nullable=False, index=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    
    def __repr__(self):
        return f"<PasswordResetToken for user {self.user_id}>"
