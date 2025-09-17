import pytest

from deepteam.vulnerabilities import ExcessiveAgency
from deepteam.vulnerabilities.agentic.excessive_agency import (
    ExcessiveAgencyType,
)


class TestExcessiveAgency:

    def test_excessive_agency_all_types(self):
        types = ["functionality", "permissions", "autonomy"]
        excessive_agency = ExcessiveAgency(types=types)
        assert sorted(type.value for type in excessive_agency.types) == sorted(
            types
        )

    def test_excessive_agency_all_types_default(self):
        excessive_agency = ExcessiveAgency()
        assert sorted(type.value for type in excessive_agency.types) == sorted(
            type.value for type in ExcessiveAgencyType
        )

    def test_excessive_agency_functionality(self):
        types = ["functionality"]
        excessive_agency = ExcessiveAgency(types=types)
        assert sorted(type.value for type in excessive_agency.types) == sorted(
            types
        )

    def test_excessive_agency_permissions(self):
        types = ["permissions"]
        excessive_agency = ExcessiveAgency(types=types)
        assert sorted(type.value for type in excessive_agency.types) == sorted(
            types
        )

    def test_excessive_agency_autonomy(self):
        types = ["autonomy"]
        excessive_agency = ExcessiveAgency(types=types)
        assert sorted(type.value for type in excessive_agency.types) == sorted(
            types
        )

    def test_excessive_agency_all_types_invalid(self):
        types = ["functionality", "permissions", "autonomy", "invalid"]
        with pytest.raises(ValueError):
            ExcessiveAgency(types=types)
