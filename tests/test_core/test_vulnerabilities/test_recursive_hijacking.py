import pytest

from deepteam.vulnerabilities import RecursiveHijacking
from deepteam.vulnerabilities.agentic.recursive_hijacking import (
    RecursiveHijackingType,
)


class TestRecursiveHijacking:

    def test_recursive_hijacking_all_types(self):
        types = [
            "self_modifying_goals",
            "recursive_objective_chaining",
            "goal_propagation_attacks",
        ]
        recursive_hijacking = RecursiveHijacking(types=types)
        assert sorted(
            type.value for type in recursive_hijacking.types
        ) == sorted(types)

    def test_recursive_hijacking_all_types_default(self):
        recursive_hijacking = RecursiveHijacking()
        assert sorted(
            type.value for type in recursive_hijacking.types
        ) == sorted(type.value for type in RecursiveHijackingType)

    def test_recursive_hijacking_self_modifying_goals(self):
        types = ["self_modifying_goals"]
        recursive_hijacking = RecursiveHijacking(types=types)
        assert sorted(
            type.value for type in recursive_hijacking.types
        ) == sorted(types)

    def test_recursive_hijacking_recursive_objective_chaining(self):
        types = ["recursive_objective_chaining"]
        recursive_hijacking = RecursiveHijacking(types=types)
        assert sorted(
            type.value for type in recursive_hijacking.types
        ) == sorted(types)

    def test_recursive_hijacking_goal_propagation_attacks(self):
        types = ["goal_propagation_attacks"]
        recursive_hijacking = RecursiveHijacking(types=types)
        assert sorted(
            type.value for type in recursive_hijacking.types
        ) == sorted(types)

    def test_recursive_hijacking_all_types_invalid(self):
        types = [
            "self_modifying_goals",
            "recursive_objective_chaining",
            "goal_propagation_attacks",
            "invalid",
        ]
        with pytest.raises(ValueError):
            RecursiveHijacking(types=types)
