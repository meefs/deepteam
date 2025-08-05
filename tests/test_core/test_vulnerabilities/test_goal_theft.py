import pytest

from deepteam.vulnerabilities import GoalTheft
from deepteam.vulnerabilities.agentic.goal_theft import GoalTheftType


class TestGoalTheft:

    def test_goal_theft_all_types(self):
        types = [
            "escalating_probing",
            "cooperative_dialogue",
            "social_engineering",
        ]
        goal_theft = GoalTheft(types=types)
        assert sorted(type.value for type in goal_theft.types) == sorted(types)

    def test_goal_theft_all_types_default(self):
        goal_theft = GoalTheft()
        assert sorted(type.value for type in goal_theft.types) == sorted(
            type.value for type in GoalTheftType
        )

    def test_goal_theft_escalating_probing(self):
        types = ["escalating_probing"]
        goal_theft = GoalTheft(types=types)
        assert sorted(type.value for type in goal_theft.types) == sorted(types)

    def test_goal_theft_cooperative_dialogue(self):
        types = ["cooperative_dialogue"]
        goal_theft = GoalTheft(types=types)
        assert sorted(type.value for type in goal_theft.types) == sorted(types)

    def test_goal_theft_social_engineering(self):
        types = ["social_engineering"]
        goal_theft = GoalTheft(types=types)
        assert sorted(type.value for type in goal_theft.types) == sorted(types)

    def test_goal_theft_all_types_invalid(self):
        types = [
            "escalating_probing",
            "cooperative_dialogue",
            "social_engineering",
            "invalid",
        ]
        with pytest.raises(ValueError):
            GoalTheft(types=types)
