import pytest

from deepteam.vulnerabilities import DebugAccess
from deepteam.vulnerabilities.debug_access import DebugAccessType


class TestDebugAccess:

    def test_debug_access_all_types(self):
        types = [
            "debug_mode_bypass",
            "development_endpoint_access",
            "administrative_interface_exposure",
        ]
        debug_access = DebugAccess(types=types)
        assert sorted(type.value for type in debug_access.types) == sorted(
            types
        )

    def test_debug_access_all_types_default(self):
        debug_access = DebugAccess()
        assert sorted(type.value for type in debug_access.types) == sorted(
            type.value for type in DebugAccessType
        )

    def test_debug_access_debug_mode_bypass(self):
        types = ["debug_mode_bypass"]
        debug_access = DebugAccess(types=types)
        assert sorted(type.value for type in debug_access.types) == sorted(
            types
        )

    def test_debug_access_development_endpoint_access(self):
        types = ["development_endpoint_access"]
        debug_access = DebugAccess(types=types)
        assert sorted(type.value for type in debug_access.types) == sorted(
            types
        )

    def test_debug_access_administrative_interface_exposure(self):
        types = ["administrative_interface_exposure"]
        debug_access = DebugAccess(types=types)
        assert sorted(type.value for type in debug_access.types) == sorted(
            types
        )

    def test_debug_access_all_types_invalid(self):
        types = [
            "debug_mode_bypass",
            "development_endpoint_access",
            "administrative_interface_exposure",
            "invalid",
        ]
        with pytest.raises(ValueError):
            DebugAccess(types=types)
