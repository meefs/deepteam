import pytest

from deepteam.vulnerabilities import IllegalActivity
from deepteam.vulnerabilities.illegal_activity import IllegalActivityType


class TestIllegalActivity:

    def test_illegal_activity_all_types(self):
        types = [
            "weapons",
            "illegal drugs",
            "violent crimes",
            "non violent crimes",
            "sex crimes",
            "cybercrime",
            "child exploitation",
        ]
        illegal_activity = IllegalActivity(types=types)
        assert sorted(type.value for type in illegal_activity.types) == sorted(
            types
        )

    def test_illegal_activity_all_types_default(self):
        illegal_activity = IllegalActivity()
        assert sorted(type.value for type in illegal_activity.types) == sorted(
            type.value for type in IllegalActivityType
        )

    def test_illegal_activity_weapons(self):
        types = ["weapons"]
        illegal_activity = IllegalActivity(types=types)
        assert sorted(type.value for type in illegal_activity.types) == sorted(
            types
        )

    def test_illegal_activity_illegal_drugs(self):
        types = ["illegal drugs"]
        illegal_activity = IllegalActivity(types=types)
        assert sorted(type.value for type in illegal_activity.types) == sorted(
            types
        )

    def test_illegal_activity_violent_crimes(self):
        types = ["violent crimes"]
        illegal_activity = IllegalActivity(types=types)
        assert sorted(type.value for type in illegal_activity.types) == sorted(
            types
        )

    def test_illegal_activity_non_violent_crimes(self):
        types = ["non violent crimes"]
        illegal_activity = IllegalActivity(types=types)
        assert sorted(type.value for type in illegal_activity.types) == sorted(
            types
        )

    def test_illegal_activity_sex_crimes(self):
        types = ["sex crimes"]
        illegal_activity = IllegalActivity(types=types)
        assert sorted(type.value for type in illegal_activity.types) == sorted(
            types
        )

    def test_illegal_activity_cybercrime(self):
        types = ["cybercrime"]
        illegal_activity = IllegalActivity(types=types)
        assert sorted(type.value for type in illegal_activity.types) == sorted(
            types
        )

    def test_illegal_activity_child_exploitation(self):
        types = ["child exploitation"]
        illegal_activity = IllegalActivity(types=types)
        assert sorted(type.value for type in illegal_activity.types) == sorted(
            types
        )

    def test_illegal_activity_all_types_invalid(self):
        types = [
            "weapons",
            "illegal drugs",
            "violent crimes",
            "non violent crimes",
            "sex crimes",
            "cybercrime",
            "child exploitation",
            "invalid",
        ]
        with pytest.raises(ValueError):
            IllegalActivity(types=types)
