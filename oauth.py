"""
OAuth Integration

Google and GitHub OAuth 2.0 authentication support.
Handles OAuth flow, user creation/linking, and token management.
"""

import secrets
import httpx
from datetime import datetime
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum

from config.config import get_config


class OAuthProvider(str, Enum):
    """Supported OAuth providers"""
    GOOGLE = "google"
    GITHUB = "github"
    MICROSOFT = "microsoft"


@dataclass
class OAuthUserInfo:
    """Standardized user info from OAuth providers"""
    provider: OAuthProvider
    provider_user_id: str
    email: Optional[str]
    name: Optional[str]
    avatar_url: Optional[str]
    username: Optional[str] = None


class OAuthManager:
    """
    OAuth 2.0 Manager
    
    Handles OAuth authentication flow for multiple providers.
    """
    
    def __init__(self):
        """Initialize OAuth manager with configuration"""
        self.config = get_config()
        self._load_provider_configs()
    
    def _load_provider_configs(self):
        """Load OAuth provider configurations"""
        # Google OAuth
        self.google_client_id = self.config.get("google_client_id")
        self.google_client_secret = self.config.get("google_client_secret")
        
        # GitHub OAuth
        self.github_client_id = self.config.get("github_client_id")
        self.github_client_secret = self.config.get("github_client_secret")
        
        # Microsoft OAuth (optional)
        self.microsoft_client_id = self.config.get("microsoft_client_id")
        self.microsoft_client_secret = self.config.get("microsoft_client_secret")
        
        # Base URL for callbacks
        self.base_url = self.config.get("base_url", "http://localhost:8501")
    
    def is_provider_configured(self, provider: OAuthProvider) -> bool:
        """Check if a provider is properly configured"""
        if provider == OAuthProvider.GOOGLE:
            return bool(self.google_client_id and self.google_client_secret)
        elif provider == OAuthProvider.GITHUB:
            return bool(self.github_client_id and self.github_client_secret)
        elif provider == OAuthProvider.MICROSOFT:
            return bool(self.microsoft_client_id and self.microsoft_client_secret)
        return False
    
    def get_available_providers(self) -> list[OAuthProvider]:
        """Get list of configured providers"""
        providers = []
        for provider in [OAuthProvider.GOOGLE, OAuthProvider.GITHUB, OAuthProvider.MICROSOFT]:
            if self.is_provider_configured(provider):
                providers.append(provider)
        return providers
    
    def get_authorization_url(self, provider: OAuthProvider, state: str) -> str:
        """
        Get OAuth authorization URL for provider
        
        Args:
            provider: OAuth provider
            state: Random state string for CSRF protection
            
        Returns:
            Authorization URL to redirect user to
        """
        if provider == OAuthProvider.GOOGLE:
            return self._get_google_auth_url(state)
        elif provider == OAuthProvider.GITHUB:
            return self._get_github_auth_url(state)
        elif provider == OAuthProvider.MICROSOFT:
            return self._get_microsoft_auth_url(state)
        raise ValueError(f"Unsupported provider: {provider}")
    
    def _get_google_auth_url(self, state: str) -> str:
        """Get Google OAuth authorization URL"""
        redirect_uri = f"{self.base_url}/auth/callback/google"
        params = {
            "client_id": self.google_client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "access_type": "offline",
            "prompt": "consent"
        }
        query = "&".join(f"{k}={v}" for k, v in params.items())
        return f"https://accounts.google.com/o/oauth2/v2/auth?{query}"
    
    def _get_github_auth_url(self, state: str) -> str:
        """Get GitHub OAuth authorization URL"""
        redirect_uri = f"{self.base_url}/auth/callback/github"
        params = {
            "client_id": self.github_client_id,
            "redirect_uri": redirect_uri,
            "scope": "user:email",
            "state": state
        }
        query = "&".join(f"{k}={v}" for k, v in params.items())
        return f"https://github.com/login/oauth/authorize?{query}"
    
    def _get_microsoft_auth_url(self, state: str) -> str:
        """Get Microsoft OAuth authorization URL"""
        redirect_uri = f"{self.base_url}/auth/callback/microsoft"
        params = {
            "client_id": self.microsoft_client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state
        }
        query = "&".join(f"{k}={v}" for k, v in params.items())
        return f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?{query}"
    
    async def exchange_code_for_token(
        self, provider: OAuthProvider, code: str
    ) -> Tuple[str, Optional[str]]:
        """
        Exchange authorization code for access token
        
        Args:
            provider: OAuth provider
            code: Authorization code from callback
            
        Returns:
            Tuple of (access_token, refresh_token)
        """
        if provider == OAuthProvider.GOOGLE:
            return await self._exchange_google_code(code)
        elif provider == OAuthProvider.GITHUB:
            return await self._exchange_github_code(code)
        elif provider == OAuthProvider.MICROSOFT:
            return await self._exchange_microsoft_code(code)
        raise ValueError(f"Unsupported provider: {provider}")
    
    async def _exchange_google_code(self, code: str) -> Tuple[str, Optional[str]]:
        """Exchange Google authorization code for tokens"""
        redirect_uri = f"{self.base_url}/auth/callback/google"
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "client_id": self.google_client_id,
                    "client_secret": self.google_client_secret,
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "grant_type": "authorization_code"
                }
            )
            
            if response.status_code != 200:
                raise ValueError(f"Google token exchange failed: {response.text}")
            
            data = response.json()
            return data["access_token"], data.get("refresh_token")
    
    async def _exchange_github_code(self, code: str) -> Tuple[str, Optional[str]]:
        """Exchange GitHub authorization code for token"""
        redirect_uri = f"{self.base_url}/auth/callback/github"
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://github.com/login/oauth/access_token",
                headers={"Accept": "application/json"},
                data={
                    "client_id": self.github_client_id,
                    "client_secret": self.github_client_secret,
                    "code": code,
                    "redirect_uri": redirect_uri
                }
            )
            
            if response.status_code != 200:
                raise ValueError(f"GitHub token exchange failed: {response.text}")
            
            data = response.json()
            return data["access_token"], None
    
    async def _exchange_microsoft_code(self, code: str) -> Tuple[str, Optional[str]]:
        """Exchange Microsoft authorization code for tokens"""
        redirect_uri = f"{self.base_url}/auth/callback/microsoft"
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                data={
                    "client_id": self.microsoft_client_id,
                    "client_secret": self.microsoft_client_secret,
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "grant_type": "authorization_code"
                }
            )
            
            if response.status_code != 200:
                raise ValueError(f"Microsoft token exchange failed: {response.text}")
            
            data = response.json()
            return data["access_token"], data.get("refresh_token")
    
    async def get_user_info(self, provider: OAuthProvider, access_token: str) -> OAuthUserInfo:
        """
        Get user info from OAuth provider
        
        Args:
            provider: OAuth provider
            access_token: Access token from provider
            
        Returns:
            Standardized user info
        """
        if provider == OAuthProvider.GOOGLE:
            return await self._get_google_user_info(access_token)
        elif provider == OAuthProvider.GITHUB:
            return await self._get_github_user_info(access_token)
        elif provider == OAuthProvider.MICROSOFT:
            return await self._get_microsoft_user_info(access_token)
        raise ValueError(f"Unsupported provider: {provider}")
    
    async def _get_google_user_info(self, access_token: str) -> OAuthUserInfo:
        """Get user info from Google"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if response.status_code != 200:
                raise ValueError(f"Google user info failed: {response.text}")
            
            data = response.json()
            
            return OAuthUserInfo(
                provider=OAuthProvider.GOOGLE,
                provider_user_id=data["sub"],
                email=data.get("email"),
                name=data.get("name"),
                avatar_url=data.get("picture"),
                username=None  # Google doesn't provide username
            )
    
    async def _get_github_user_info(self, access_token: str) -> OAuthUserInfo:
        """Get user info from GitHub"""
        async with httpx.AsyncClient() as client:
            # Get user profile
            response = await client.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github.v3+json"
                }
            )
            
            if response.status_code != 200:
                raise ValueError(f"GitHub user info failed: {response.text}")
            
            data = response.json()
            
            # If email is not public, fetch from emails endpoint
            email = data.get("email")
            if not email:
                email_response = await client.get(
                    "https://api.github.com/user/emails",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/vnd.github.v3+json"
                    }
                )
                if email_response.status_code == 200:
                    emails = email_response.json()
                    primary_email = next(
                        (e["email"] for e in emails if e.get("primary")),
                        None
                    )
                    email = primary_email
            
            return OAuthUserInfo(
                provider=OAuthProvider.GITHUB,
                provider_user_id=str(data["id"]),
                email=email,
                name=data.get("name"),
                avatar_url=data.get("avatar_url"),
                username=data.get("login")
            )
    
    async def _get_microsoft_user_info(self, access_token: str) -> OAuthUserInfo:
        """Get user info from Microsoft"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://graph.microsoft.com/v1.0/me",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if response.status_code != 200:
                raise ValueError(f"Microsoft user info failed: {response.text}")
            
            data = response.json()
            
            return OAuthUserInfo(
                provider=OAuthProvider.MICROSOFT,
                provider_user_id=data["id"],
                email=data.get("mail") or data.get("userPrincipalName"),
                name=data.get("displayName"),
                avatar_url=None,
                username=None
            )
    
    def generate_state(self) -> str:
        """Generate random state string for CSRF protection"""
        return secrets.token_urlsafe(32)


# Global OAuth manager instance
_oauth_manager: Optional[OAuthManager] = None


def get_oauth_manager() -> OAuthManager:
    """Get or create OAuth manager instance"""
    global _oauth_manager
    if _oauth_manager is None:
        _oauth_manager = OAuthManager()
    return _oauth_manager
