import pytest
from unittest.mock import AsyncMock, MagicMock
from deepteam.attacks.multi_turn import BadLikertJudge
from deepteam.vulnerabilities import Bias
from deepteam.test_case.test_case import RTTurn


class TestBadLikertJudge:

    BIAS = Bias(types=["gender"])

    def test_bad_likert_judge_initialization(self):
        attack = BadLikertJudge()
        assert attack.weight == 1
        assert attack.get_name() == "Bad Likert Judge"

    def test_bad_likert_judge_initialization_with_weight(self):
        attack = BadLikertJudge(weight=5)
        assert attack.weight == 5
        assert attack.get_name() == "Bad Likert Judge"

    def test_bad_likert_judge_enhance_and_turns(self):
        attack = BadLikertJudge(num_turns=0)

        # Mock the required components
        mock_callback = MagicMock(return_value="Mock response")

        # Just a user turn
        user_only_turns = [RTTurn(role="user", content="User content")]
        # Just an assistant turn
        assistant_only_turns = [
            RTTurn(role="assistant", content="Assistant content")
        ]
        # Both user and assistant turn
        user_and_assistant_turns = [
            RTTurn(role="user", content="User content"),
            RTTurn(role="assistant", content="Assistant content"),
        ]

        # Test for various cases:
        type_to_turns = attack.progress(
            TestBadLikertJudge.BIAS,
            mock_callback,
        )

        user_only_turns_result = attack._get_turns(
            mock_callback, user_only_turns
        )
        user_and_assistant_turns_result = attack._get_turns(
            mock_callback, user_and_assistant_turns
        )

        assert len(type_to_turns.keys()) == 1
        assert isinstance(
            type_to_turns.get(TestBadLikertJudge.BIAS.types[0]), list
        ) and all(
            isinstance(turn, RTTurn)
            for turn in type_to_turns.get(TestBadLikertJudge.BIAS.types[0])
        )
        assert user_only_turns_result[1].role == "assistant"
        with pytest.raises(ValueError):
            attack._get_turns(mock_callback, assistant_only_turns)
        assert len(user_and_assistant_turns_result) == 2

    @pytest.mark.asyncio
    async def test_bad_likert_judge_async_enhance_and_turns(self):
        attack = BadLikertJudge(num_turns=0)

        # Mock the required components
        mock_callback = AsyncMock(return_value="Mock response")

        # Just a user turn
        user_only_turns = [RTTurn(role="user", content="User content")]
        # Just an assistant turn
        assistant_only_turns = [
            RTTurn(role="assistant", content="Assistant content")
        ]
        # Both user and assistant turn
        user_and_assistant_turns = [
            RTTurn(role="user", content="User content"),
            RTTurn(role="assistant", content="Assistant content"),
        ]

        # Test for various cases:
        type_to_turns = await attack.a_progress(
            TestBadLikertJudge.BIAS,
            mock_callback,
        )

        user_only_turns_result = await attack._a_get_turns(
            mock_callback, user_only_turns
        )
        user_and_assistant_turns_result = await attack._a_get_turns(
            mock_callback, user_and_assistant_turns
        )

        assert len(type_to_turns.keys()) == 1
        assert isinstance(
            type_to_turns.get(TestBadLikertJudge.BIAS.types[0]), list
        ) and all(
            isinstance(turn, RTTurn)
            for turn in type_to_turns.get(TestBadLikertJudge.BIAS.types[0])
        )
        assert user_only_turns_result[1].role == "assistant"
        with pytest.raises(ValueError):
            await attack._a_get_turns(mock_callback, assistant_only_turns)
        assert len(user_and_assistant_turns_result) == 2

    def test_bad_likert_judge_has_required_methods(self):
        attack = BadLikertJudge()

        # Verify all required methods exist
        assert hasattr(attack, "progress")
        assert hasattr(attack, "a_progress")
        assert hasattr(attack, "get_name")
        assert hasattr(attack, "_get_turns")
        assert hasattr(attack, "_a_get_turns")
        assert callable(attack.progress)
        assert callable(attack.a_progress)
        assert callable(attack.get_name)
        assert callable(attack._get_turns)
        assert callable(attack._a_get_turns)
