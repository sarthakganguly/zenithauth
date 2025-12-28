import pytest
import os
from zenithauth.manager import ZenithAuth
from zenithauth.core.identity import UserInDB
from .mock_repo import MockUserRepository

@pytest.mark.asyncio
async def test_manager_full_flow():
    # Setup
    redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
    repo = MockUserRepository()
    auth = ZenithAuth(secret_key="top-secret", redis_url=redis_url, repository=repo)

    # 1. Create a fake user in repo
    hashed_pwd = auth.security.hash_password("password123456")
    user = UserInDB(
        id="user_01", 
        email="test@example.com", 
        hashed_password=hashed_pwd,
        roles=["admin"]
    )
    await repo.save_user(user)

    # 2. Authenticate
    tokens = await auth.authenticate("test@example.com", "password123456")
    assert tokens.access_token is not None

    # 3. Authorize Access
    payload = await auth.authorize(tokens.access_token)
    assert payload["sub"] == "user_01"
    assert "admin" in payload["scopes"]

    # 4. Logout
    await auth.logout(tokens.access_token)

    # 5. Verify access is now denied
    from zenithauth.core.exceptions import RevokedTokenError
    with pytest.raises(RevokedTokenError):
        await auth.authorize(tokens.access_token)