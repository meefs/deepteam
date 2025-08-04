import pytest

from deepteam.vulnerabilities import SQLInjection
from deepteam.vulnerabilities.sql_injection import SQLInjectionType


class TestSQLInjection:

    def test_sql_injection_all_types(self):
        types = [
            "blind_sql_injection",
            "union_based_injection",
            "error_based_injection",
        ]
        sql_injection = SQLInjection(types=types)
        assert sorted(type.value for type in sql_injection.types) == sorted(
            types
        )

    def test_sql_injection_all_types_default(self):
        sql_injection = SQLInjection()
        assert sorted(type.value for type in sql_injection.types) == sorted(
            type.value for type in SQLInjectionType
        )

    def test_sql_injection_blind_sql_injection(self):
        types = ["blind_sql_injection"]
        sql_injection = SQLInjection(types=types)
        assert sorted(type.value for type in sql_injection.types) == sorted(
            types
        )

    def test_sql_injection_union_based_injection(self):
        types = ["union_based_injection"]
        sql_injection = SQLInjection(types=types)
        assert sorted(type.value for type in sql_injection.types) == sorted(
            types
        )

    def test_sql_injection_error_based_injection(self):
        types = ["error_based_injection"]
        sql_injection = SQLInjection(types=types)
        assert sorted(type.value for type in sql_injection.types) == sorted(
            types
        )

    def test_sql_injection_all_types_invalid(self):
        types = [
            "blind_sql_injection",
            "union_based_injection",
            "error_based_injection",
            "invalid",
        ]
        with pytest.raises(ValueError):
            SQLInjection(types=types)
