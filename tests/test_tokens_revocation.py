import pytest
import os
import asyncio
from zenithauth.core.tokens import TokenManager, TokenSettings
from zenithauth.core.revocation import RevocationStore

@pytest.mark.asyncio
async def test_token_revocation_flow():
    # 1. Setup
    settings = TokenSettings(secret_key="test-secret")
    tm = TokenManager(settings)
    # REDIS_URL comes from our docker-compose.yml
    redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
    store = RevocationStore(redis_url)

    # 2. Create Token
    tokens = tm.generate_auth_tokens(user_id="user_1")
    payload = tm.decode_token(tokens.access_token)
    jti = payload["jti"]

    # 3. Check not revoked
    assert await store.is_revoked(jti) is False

    # 4. Revoke (Logout)
    await store.revoke(jti, payload["exp"])

    # 5. Check revoked
    assert await store.is_revoked(jti) is True