from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from zenithauth.core.exceptions import InvalidCredentialsError

class SecurityHandler:
    def __init__(self):
        # Default parameters are secure: Argon2id
        self.ph = PasswordHasher()

    def hash_password(self, password: str) -> str:
        if len(password) < 12:
            raise ValueError("Password must be at least 12 characters.")
        return self.ph.hash(password)

    def verify_password(self, hashed: str, plain: str) -> bool:
        try:
            return self.ph.verify(hashed, plain)
        except VerifyMismatchError:
            raise InvalidCredentialsError("Invalid password.")