from typing import Optional, Dict, Any
from zenithauth.config import ZenithSettings
from zenithauth.core.security import SecurityHandler
from zenithauth.core.tokens import TokenManager
from zenithauth.core.revocation import RevocationStore
from zenithauth.core.authorizer import Authorizer
from zenithauth.protocols.user_repo import UserRepositoryProtocol
from zenithauth.core.policy import PasswordPolicy

class ZenithAuth:
    def __init__(
        self, 
        settings: Optional[ZenithSettings] = None,
        repository: Optional[UserRepositoryProtocol] = None
    ):
        # If settings aren't passed, load from env automatically
        self.settings = settings or ZenithSettings()

        # Initialize Policy
        self.policy = PasswordPolicy(
            min_length=self.settings.MIN_PASSWORD_LENGTH,
            require_non_alpha=self.settings.REQUIRE_NON_ALPHA
        )

        self.security = SecurityHandler(policy=self.policy)
        self.tokens = TokenManager(self.settings)
        self.revocation = RevocationStore(self.settings.REDIS_URL)
        self.authorizer = Authorizer()
        self.repository = repository

    async def authorize(self, token: str) -> Dict[str, Any]:
        """Validates token signature and checks Redis for revocation."""
        payload = self.tokens.decode_token(token)
        
        if await self.revocation.is_revoked(payload["jti"]):
            from zenithauth.core.exceptions import RevokedTokenError
            raise RevokedTokenError("Token has been revoked.")
            
        return payload

    async def logout(self, token: str):
        """Extracts JTI and revokes the token in Redis."""
        payload = self.tokens.decode_token(token)
        await self.revocation.revoke(
            jti=payload["jti"], 
            expires_at=payload["exp"]
        )