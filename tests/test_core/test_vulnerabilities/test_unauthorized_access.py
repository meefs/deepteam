import pytest

from deepteam.vulnerabilities import UnauthorizedAccess
from deepteam.vulnerabilities.unauthorized_access import UnauthorizedAccessType


class TestUnauthorizedAccess:

    def test_unauthorized_access_all_types(self):
        types = [
            "bfla",
            "bola",
            "rbac",
            "debug access",
            "shell injection",
            "sql injection",
            "ssrf",
        ]
        unauthorized_access = UnauthorizedAccess(types=types)
        assert sorted(
            type.value for type in unauthorized_access.types
        ) == sorted(types)

    def test_unauthorized_access_all_types_default(self):
        unauthorized_access = UnauthorizedAccess()
        assert sorted(
            type.value for type in unauthorized_access.types
        ) == sorted(type.value for type in UnauthorizedAccessType)

    def test_unauthorized_access_bfla(self):
        types = ["bfla"]
        unauthorized_access = UnauthorizedAccess(types=types)
        assert sorted(
            type.value for type in unauthorized_access.types
        ) == sorted(types)

    def test_unauthorized_access_bola(self):
        types = ["bola"]
        unauthorized_access = UnauthorizedAccess(types=types)
        assert sorted(
            type.value for type in unauthorized_access.types
        ) == sorted(types)

    def test_unauthorized_access_rbac(self):
        types = ["rbac"]
        unauthorized_access = UnauthorizedAccess(types=types)
        assert sorted(
            type.value for type in unauthorized_access.types
        ) == sorted(types)

    def test_unauthorized_access_debug_access(self):
        types = ["debug access"]
        unauthorized_access = UnauthorizedAccess(types=types)
        assert sorted(
            type.value for type in unauthorized_access.types
        ) == sorted(types)

    def test_unauthorized_access_shell_injection(self):
        types = ["shell injection"]
        unauthorized_access = UnauthorizedAccess(types=types)
        assert sorted(
            type.value for type in unauthorized_access.types
        ) == sorted(types)

    def test_unauthorized_access_sql_injection(self):
        types = ["sql injection"]
        unauthorized_access = UnauthorizedAccess(types=types)
        assert sorted(
            type.value for type in unauthorized_access.types
        ) == sorted(types)

    def test_unauthorized_access_ssrf(self):
        types = ["ssrf"]
        unauthorized_access = UnauthorizedAccess(types=types)
        assert sorted(
            type.value for type in unauthorized_access.types
        ) == sorted(types)

    def test_unauthorized_access_all_types_invalid(self):
        types = [
            "bfla",
            "bola",
            "rbac",
            "debug access",
            "shell injection",
            "sql injection",
            "ssrf",
            "invalid",
        ]
        with pytest.raises(ValueError):
            UnauthorizedAccess(types=types)
