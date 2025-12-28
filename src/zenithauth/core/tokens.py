from datetime import datetime, timedelta, timezone
import uuid
from typing import List, Optional, Dict
from jose import jwt, JWTError
from pydantic import BaseModel
from zenithauth.core.exceptions import TokenExpiredError, ZenithAuthError

class TokenSettings(BaseModel):
    secret_key: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class TokenManager:
    def __init__(self, settings: TokenSettings):
        self.settings = settings

    def create_token(self, subject: str, expires_delta: timedelta, scopes: List[str] = []) -> str:
        expire = datetime.now(timezone.utc) + expires_delta
        to_encode = {
            "sub": str(subject),
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "jti": str(uuid.uuid4()),  # Unique ID for revocation
            "scopes": scopes
        }
        return jwt.encode(to_encode, self.settings.secret_key, algorithm=self.settings.algorithm)

    def generate_auth_tokens(self, user_id: str, scopes: List[str] = []) -> TokenPair:
        access = self.create_token(
            subject=user_id, 
            expires_delta=timedelta(minutes=self.settings.access_token_expire_minutes),
            scopes=scopes
        )
        refresh = self.create_token(
            subject=user_id, 
            expires_delta=timedelta(days=self.settings.refresh_token_expire_days)
        )
        return TokenPair(access_token=access, refresh_token=refresh)

    def decode_token(self, token: str) -> Dict:
        try:
            return jwt.decode(token, self.settings.secret_key, algorithms=[self.settings.algorithm])
        except jwt.ExpiredSignatureError:
            raise TokenExpiredError("Token has expired.")
        except JWTError:
            raise ZenithAuthError("Invalid token.")