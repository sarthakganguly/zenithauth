from typing import Optional, List, Dict, Any
from zenithauth.core.security import SecurityHandler
from zenithauth.core.tokens import TokenManager, TokenSettings, TokenPair
from zenithauth.core.revocation import RevocationStore
from zenithauth.core.exceptions import RevokedTokenError, InvalidCredentialsError
from zenithauth.protocols.user_repo import UserRepositoryProtocol
from zenithauth.core.authorizer import Authorizer

class ZenithAuth:
    def __init__(
        self, 
        secret_key: str, 
        redis_url: str,
        repository: Optional[UserRepositoryProtocol] = None,
        algorithm: str = "HS256"
    ):
        self.security = SecurityHandler()
        self.tokens = TokenManager(TokenSettings(secret_key=secret_key, algorithm=algorithm))
        self.revocation = RevocationStore(redis_url)
        self.repository = repository
        self.authorizer = Authorizer()

    async def authorize_role(self, token: str, required_role: str) -> Dict[str, Any]:
        """Verify token AND check for a specific role."""
        payload = await self.authorize(token) # This already checks Redis revocation
        if not self.authorizer.has_role(payload, required_role):
            from zenithauth.core.authorizer import InsufficientPermissionsError
            raise InsufficientPermissionsError(f"Role '{required_role}' required.")
        return payload

    async def authenticate(self, email: str, password: str) -> TokenPair:
        """
        High-level login method. 
        Checks credentials against the repo and returns tokens.
        """
        if not self.repository:
            raise RuntimeError("Repository not configured for authentication.")

        user = await self.repository.get_by_email(email)
        if not user:
            raise InvalidCredentialsError("User not found.")

        # Verify password
        self.security.verify_password(user.hashed_password, password)
        
        # Issue tokens
        return self.tokens.generate_auth_tokens(user_id=user.id, scopes=user.roles)

    async def authorize(self, token: str) -> Dict[str, Any]:
        """
        The "Guard" method for protecting routes.
        Decodes token and checks the Redis blacklist.
        """
        payload = self.tokens.decode_token(token)
        
        # Check if revoked (logout check)
        if await self.revocation.is_revoked(payload["jti"]):
            raise RevokedTokenError("Token has been revoked.")
            
        return payload

    async def logout(self, token: str):
        """Invalidates a token immediately."""
        payload = self.tokens.decode_token(token)
        await self.revocation.revoke(
            jti=payload["jti"], 
            expires_at=payload["exp"]
        )