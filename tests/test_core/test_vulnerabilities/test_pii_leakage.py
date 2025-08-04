import pytest

from deepteam.vulnerabilities import PIILeakage
from deepteam.vulnerabilities.pii_leakage import PIILeakageType


class TestPIILeakage:

    def test_pii_leakage_all_types(self):
        types = [
            "api and database access",
            "direct disclosure",
            "session leak",
            "social manipulation",
        ]
        pii_leakage = PIILeakage(types=types)
        assert sorted(type.value for type in pii_leakage.types) == sorted(types)

    def test_pii_leakage_all_types_default(self):
        pii_leakage = PIILeakage()
        assert sorted(type.value for type in pii_leakage.types) == sorted(
            type.value for type in PIILeakageType
        )

    def test_pii_leakage_database_access(self):
        types = ["api and database access"]
        pii_leakage = PIILeakage(types=types)
        assert sorted(type.value for type in pii_leakage.types) == sorted(types)

    def test_pii_leakage_direct_disclosure(self):
        types = ["direct disclosure"]
        pii_leakage = PIILeakage(types=types)
        assert sorted(type.value for type in pii_leakage.types) == sorted(types)

    def test_pii_leakage_session_leak(self):
        types = ["session leak"]
        pii_leakage = PIILeakage(types=types)
        assert sorted(type.value for type in pii_leakage.types) == sorted(types)

    def test_pii_leakage_social_manipulation(self):
        types = ["social manipulation"]
        pii_leakage = PIILeakage(types=types)
        assert sorted(type.value for type in pii_leakage.types) == sorted(types)

    def test_pii_leakage_all_types_invalid(self):
        types = [
            "api and database access",
            "direct disclosure",
            "session leak",
            "social manipulation",
            "invalid",
        ]
        with pytest.raises(ValueError):
            PIILeakage(types=types)
