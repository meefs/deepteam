import pytest

from deepteam.vulnerabilities import PersonalSafety
from deepteam.vulnerabilities.personal_safety import PersonalSafetyType


class TestPersonalSafety:

    def test_personal_safety_all_types(self):
        types = [
            "bullying",
            "self-harm",
            "unsafe practices",
            "dangerous challenges",
            "stalking",
        ]
        personal_safety = PersonalSafety(types=types)
        assert sorted(type.value for type in personal_safety.types) == sorted(
            types
        )

    def test_personal_safety_all_types_default(self):
        personal_safety = PersonalSafety()
        assert sorted(type.value for type in personal_safety.types) == sorted(
            type.value for type in PersonalSafetyType
        )

    def test_personal_safety_bullying(self):
        types = ["bullying"]
        personal_safety = PersonalSafety(types=types)
        assert sorted(type.value for type in personal_safety.types) == sorted(
            types
        )

    def test_personal_safety_self_harm(self):
        types = ["self-harm"]
        personal_safety = PersonalSafety(types=types)
        assert sorted(type.value for type in personal_safety.types) == sorted(
            types
        )

    def test_personal_safety_unsafe_practices(self):
        types = ["unsafe practices"]
        personal_safety = PersonalSafety(types=types)
        assert sorted(type.value for type in personal_safety.types) == sorted(
            types
        )

    def test_personal_safety_dangerous_challenges(self):
        types = ["dangerous challenges"]
        personal_safety = PersonalSafety(types=types)
        assert sorted(type.value for type in personal_safety.types) == sorted(
            types
        )

    def test_personal_safety_stalking(self):
        types = ["stalking"]
        personal_safety = PersonalSafety(types=types)
        assert sorted(type.value for type in personal_safety.types) == sorted(
            types
        )

    def test_personal_safety_all_types_invalid(self):
        types = [
            "bullying",
            "self-harm",
            "unsafe practices",
            "dangerous challenges",
            "stalking",
            "invalid",
        ]
        with pytest.raises(ValueError):
            PersonalSafety(types=types)
