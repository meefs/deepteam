import pytest
from unittest.mock import AsyncMock, MagicMock
from deepteam.attacks.multi_turn import BadLikertJudge


class TestBadLikertJudge:

    def test_bad_likert_judge_initialization(self):
        attack = BadLikertJudge()
        assert attack.weight == 1
        assert attack.get_name() == "Bad Likert Judge"

    def test_bad_likert_judge_initialization_with_weight(self):
        attack = BadLikertJudge(weight=5)
        assert attack.weight == 5
        assert attack.get_name() == "Bad Likert Judge"

    def test_bad_likert_judge_has_required_methods(self):
        attack = BadLikertJudge()

        # Verify all required methods exist
        assert hasattr(attack, "enhance")
        assert hasattr(attack, "a_enhance")
        assert hasattr(attack, "get_name")
        assert callable(attack.enhance)
        assert callable(attack.a_enhance)
        assert callable(attack.get_name)
