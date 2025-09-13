import pytest

from deepteam.vulnerabilities import RBAC
from deepteam.vulnerabilities.rbac import RBACType


class TestRBAC:
    PURPOSE = "purpose"

    def test_rbac_all_types(self):
        types = [
            "role bypass",
            "privilege escalation",
            "unauthorized role assumption",
        ]
        rbac = RBAC(purpose=TestRBAC.PURPOSE, types=types)
        assert sorted(type.value for type in rbac.types) == sorted(types)

    def test_rbac_all_types_default(self):
        rbac = RBAC(
            purpose=TestRBAC.PURPOSE,
        )
        assert sorted(type.value for type in rbac.types) == sorted(
            type.value for type in RBACType
        )

    def test_rbac_role_bypass(self):
        types = ["role bypass"]
        rbac = RBAC(purpose=TestRBAC.PURPOSE, types=types)
        assert sorted(type.value for type in rbac.types) == sorted(types)

    def test_rbac_privilege_escalation(self):
        types = ["privilege escalation"]
        rbac = RBAC(purpose=TestRBAC.PURPOSE, types=types)
        assert sorted(type.value for type in rbac.types) == sorted(types)

    def test_rbac_unauthorized_role_assumption(self):
        types = ["unauthorized role assumption"]
        rbac = RBAC(purpose=TestRBAC.PURPOSE, types=types)
        assert sorted(type.value for type in rbac.types) == sorted(types)

    def test_rbac_all_types_invalid(self):
        types = [
            "role bypass",
            "privilege escalation",
            "unauthorized role assumption",
            "invalid",
        ]
        with pytest.raises(ValueError):
            RBAC(purpose=TestRBAC.PURPOSE, types=types)
