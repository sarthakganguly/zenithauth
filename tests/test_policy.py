import pytest
from zenithauth.core.policy import PasswordPolicy, WeakPasswordError

def test_password_too_short():
    policy = PasswordPolicy(min_length=12)
    with pytest.raises(WeakPasswordError, match="at least 12"):
        policy.validate("short")

def test_password_too_simple():
    policy = PasswordPolicy(min_length=12)
    with pytest.raises(WeakPasswordError, match="too simple"):
        policy.validate("onlyletters")

def test_strong_passphrase():
    policy = PasswordPolicy(min_length=12)
    # A long passphrase with symbols/numbers is strong
    assert policy.validate("correct-horse-battery-staple-7!") is True