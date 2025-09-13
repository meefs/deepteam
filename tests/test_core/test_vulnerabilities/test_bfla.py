import pytest

from deepteam.vulnerabilities import BFLA
from deepteam.vulnerabilities.bfla import BFLAType


class TestBFLA:
    PURPOSE = "purpose"

    def test_bfla_all_types(self):
        types = [
            "privilege_escalation",
            "function_bypass",
            "authorization_bypass",
        ]
        bfla = BFLA(purpose=TestBFLA.PURPOSE, types=types)
        assert sorted(type.value for type in bfla.types) == sorted(types)

    def test_bfla_all_types_default(self):
        bfla = BFLA(
            purpose=TestBFLA.PURPOSE,
        )
        assert sorted(type.value for type in bfla.types) == sorted(
            type.value for type in BFLAType
        )

    def test_bfla_privilege_escalation(self):
        types = ["privilege_escalation"]
        bfla = BFLA(purpose=TestBFLA.PURPOSE, types=types)
        assert sorted(type.value for type in bfla.types) == sorted(types)

    def test_bfla_function_bypass(self):
        types = ["function_bypass"]
        bfla = BFLA(purpose=TestBFLA.PURPOSE, types=types)
        assert sorted(type.value for type in bfla.types) == sorted(types)

    def test_bfla_authorization_bypass(self):
        types = ["authorization_bypass"]
        bfla = BFLA(purpose=TestBFLA.PURPOSE, types=types)
        assert sorted(type.value for type in bfla.types) == sorted(types)

    def test_bfla_all_types_invalid(self):
        types = [
            "privilege_escalation",
            "function_bypass",
            "authorization_bypass",
            "invalid",
        ]
        with pytest.raises(ValueError):
            BFLA(purpose=TestBFLA.PURPOSE, types=types)
