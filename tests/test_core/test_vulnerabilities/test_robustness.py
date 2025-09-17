import pytest

from deepteam.vulnerabilities import Robustness
from deepteam.vulnerabilities.agentic.robustness import RobustnessType


class TestRobustness:

    def test_robustness_all_types(self):
        types = ["input overreliance", "hijacking"]
        robustness = Robustness(types=types)
        assert sorted(type.value for type in robustness.types) == sorted(types)

    def test_robustness_all_types_default(self):
        robustness = Robustness()
        assert sorted(type.value for type in robustness.types) == sorted(
            type.value for type in RobustnessType
        )

    def test_robustness_input_overreliance(self):
        types = ["input overreliance"]
        robustness = Robustness(types=types)
        assert sorted(type.value for type in robustness.types) == sorted(types)

    def test_robustness_hijacking(self):
        types = ["hijacking"]
        robustness = Robustness(types=types)
        assert sorted(type.value for type in robustness.types) == sorted(types)

    def test_robustness_all_types_invalid(self):
        types = ["input overreliance", "hijacking", "invalid"]
        with pytest.raises(ValueError):
            Robustness(types=types)
