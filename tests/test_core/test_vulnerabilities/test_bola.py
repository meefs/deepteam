import pytest

from deepteam.vulnerabilities import BOLA
from deepteam.vulnerabilities.bola import BOLAType


class TestBOLA:

    def test_bola_all_types(self):
        types = [
            "object_access_bypass",
            "cross_customer_access",
            "unauthorized_object_manipulation",
        ]
        bola = BOLA(types=types)
        assert sorted(type.value for type in bola.types) == sorted(types)

    def test_bola_all_types_default(self):
        bola = BOLA()
        assert sorted(type.value for type in bola.types) == sorted(
            type.value for type in BOLAType
        )

    def test_bola_object_access_bypass(self):
        types = ["object_access_bypass"]
        bola = BOLA(types=types)
        assert sorted(type.value for type in bola.types) == sorted(types)

    def test_bola_cross_customer_access(self):
        types = ["cross_customer_access"]
        bola = BOLA(types=types)
        assert sorted(type.value for type in bola.types) == sorted(types)

    def test_bola_unauthorized_object_manipulation(self):
        types = ["unauthorized_object_manipulation"]
        bola = BOLA(types=types)
        assert sorted(type.value for type in bola.types) == sorted(types)

    def test_bola_all_types_invalid(self):
        types = [
            "object_access_bypass",
            "cross_customer_access",
            "unauthorized_object_manipulation",
            "invalid",
        ]
        with pytest.raises(ValueError):
            BOLA(types=types)
