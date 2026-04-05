"""
Redis Session Storage

Fast, scalable session storage using Redis with automatic expiration.
Falls back to database if Redis is unavailable.
"""

import redis
import json
import pickle
from datetime import datetime, timedelta
from typing import Optional
from src.auth.models import Session, UserRole
from config.config import get_config


class RedisSessionStore:
    """Redis-based session storage with database fallback"""
    
    def __init__(self):
        """Initialize Redis connection"""
        self.config = get_config()
        self.redis_url = self.config.get("redis_url")
        self.enabled = self.config.get("enable_redis_sessions", False)
        self.redis_client = None
        
        if self.enabled and self.redis_url:
            try:
                self.redis_client = redis.from_url(
                    self.redis_url,
                    decode_responses=False,  # We'll use pickle
                    socket_connect_timeout=5,
                    socket_timeout=5
                )
                # Test connection
                self.redis_client.ping()
                print(f"✅ Redis session store connected: {self.redis_url}")
            except Exception as e:
                print(f"⚠️  Redis connection failed: {e}")
                print("   Falling back to database sessions")
                self.redis_client = None
                self.enabled = False
    
    def _get_key(self, session_id: str) -> str:
        """Get Redis key for session"""
        return f"session:{session_id}"
    
    def create_session(self, session: Session, ttl_seconds: Optional[int] = None) -> bool:
        """
        Create or update session in Redis
        
        Args:
            session: Session object to store
            ttl_seconds: Time-to-live in seconds (default: from config)
            
        Returns:
            True if stored successfully, False otherwise
        """
        if not self.redis_client:
            return False
        
        try:
            # Calculate TTL
            if ttl_seconds is None:
                # Calculate from session expiration
                now = datetime.utcnow()
                ttl_seconds = int((session.expires_at - now).total_seconds())
            
            # Serialize session
            session_data = pickle.dumps(session)
            
            # Store in Redis with expiration
            key = self._get_key(session.session_id)
            self.redis_client.setex(key, ttl_seconds, session_data)
            
            return True
        except Exception as e:
            print(f"[WARN] Redis session creation failed: {e}")
            return False
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """
        Retrieve session from Redis
        
        Args:
            session_id: Session ID to retrieve
            
        Returns:
            Session object if found and valid, None otherwise
        """
        if not self.redis_client:
            return None
        
        try:
            key = self._get_key(session_id)
            session_data = self.redis_client.get(key)
            
            if session_data is None:
                return None
            
            # Deserialize session
            session = pickle.loads(session_data)
            
            # Check if session is expired
            if session.expires_at < datetime.utcnow():
                self.delete_session(session_id)
                return None
            
            # Update last activity and extend TTL
            session.last_activity = datetime.utcnow()
            ttl = int((session.expires_at - datetime.utcnow()).total_seconds())
            self.redis_client.setex(key, ttl, pickle.dumps(session))
            
            return session
        except Exception as e:
            print(f"⚠️  Redis session retrieval failed: {e}")
            return None
    
    def delete_session(self, session_id: str) -> bool:
        """
        Delete session from Redis
        
        Args:
            session_id: Session ID to delete
            
        Returns:
            True if deleted, False otherwise
        """
        if not self.redis_client:
            return False
        
        try:
            key = self._get_key(session_id)
            self.redis_client.delete(key)
            return True
        except Exception as e:
            print(f"[WARN] Redis session deletion failed: {e}")
            return False
    
    def delete_user_sessions(self, user_id: str) -> int:
        """
        Delete all sessions for a user
        
        Args:
            user_id: User ID
            
        Returns:count of sessions deleted
        """
        if not self.redis_client:
            return 0
        
        try:
            # Scan for all session keys
            deleted = 0
            for key in self.redis_client.scan_iter("session:*"):
                session_data = self.redis_client.get(key)
                if session_data:
                    session = pickle.loads(session_data)
                    if session.user_id == user_id:
                        self.redis_client.delete(key)
                        deleted += 1
            return deleted
        except Exception as e:
            print(f"[WARN] Redis bulk deletion failed: {e}")
            return 0
    
    def get_active_session_count(self) -> int:
        """
        Get count of active sessions in Redis
        
        Returns:
            Number of active sessions
        """
        if not self.redis_client:
            return 0
        
        try:
            # Count all session keys
            count = 0
            for _ in self.redis_client.scan_iter("session:*"):
                count += 1
            return count
        except Exception as e:
            print(f"[WARN] Redis session count failed: {e}")
            return 0
    
    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions (Redis auto-expires, but check anyway)
        
        Returns:
            Number of sessions cleaned up
        """
        if not self.redis_client:
            return 0
        
        try:
            cleaned = 0
            now = datetime.utcnow()
            
            for key in self.redis_client.scan_iter("session:*"):
                session_data = self.redis_client.get(key)
                if session_data:
                    session = pickle.loads(session_data)
                    if session.expires_at < now:
                        self.redis_client.delete(key)
                        cleaned += 1
            
            return cleaned
        except Exception as e:
            print(f"[WARN] Redis cleanup failed: {e}")
            return 0
    
    def health_check(self) -> bool:
        """
        Check if Redis is healthy
        
        Returns:
            True if healthy, False otherwise
        """
        if not self.redis_client:
            return False
        
        try:
            self.redis_client.ping()
            return True
        except:
            return False


# Global Redis session store instance
_redis_store = None


def get_redis_store() -> RedisSessionStore:
    """Get global Redis session store instance"""
    global _redis_store
    if _redis_store is None:
        _redis_store = RedisSessionStore()
    return _redis_store
