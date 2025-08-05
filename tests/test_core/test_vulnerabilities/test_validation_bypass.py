import pytest

from deepteam.vulnerabilities import ValidationBypass
from deepteam.vulnerabilities.agentic.validation_bypass import (
    ValidationBypassType,
)


class TestValidationBypass:

    def test_validation_bypass_all_types(self):
        types = [
            "unverified_claims",
            "false_confidence",
            "misleading_responses",
        ]
        validation_bypass = ValidationBypass(types=types)
        assert sorted(type.value for type in validation_bypass.types) == sorted(
            types
        )

    def test_validation_bypass_all_types_default(self):
        validation_bypass = ValidationBypass()
        assert sorted(type.value for type in validation_bypass.types) == sorted(
            type.value for type in ValidationBypassType
        )

    def test_validation_bypass_unverified_claims(self):
        types = ["unverified_claims"]
        validation_bypass = ValidationBypass(types=types)
        assert sorted(type.value for type in validation_bypass.types) == sorted(
            types
        )

    def test_validation_bypass_false_confidence(self):
        types = ["false_confidence"]
        validation_bypass = ValidationBypass(types=types)
        assert sorted(type.value for type in validation_bypass.types) == sorted(
            types
        )

    def test_validation_bypass_misleading_responses(self):
        types = ["misleading_responses"]
        validation_bypass = ValidationBypass(types=types)
        assert sorted(type.value for type in validation_bypass.types) == sorted(
            types
        )

    def test_validation_bypass_all_types_invalid(self):
        types = [
            "unverified_claims",
            "false_confidence",
            "misleading_responses",
            "invalid",
        ]
        with pytest.raises(ValueError):
            ValidationBypass(types=types)
