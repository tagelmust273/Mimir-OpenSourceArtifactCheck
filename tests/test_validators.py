import pytest
from src.security.validators import InputValidator


class TestInputValidator:
    def test_validate_ip_valid(self):
        is_valid, error = InputValidator.validate_ip("8.8.8.8")
        assert is_valid is True
        assert error is None

    def test_validate_ip_private(self):
        is_valid, error = InputValidator.validate_ip("192.168.1.1")
        assert is_valid is False
        assert "Private" in error

    def test_validate_domain_valid(self):
        is_valid, error = InputValidator.validate_domain("google.com")
        assert is_valid is True

    def test_validate_hash_md5(self):
        is_valid, error, hash_type = InputValidator.validate_hash("5d41402abc4b2a76b9719d911017c592")
        assert is_valid is True
        assert hash_type == "md5"
