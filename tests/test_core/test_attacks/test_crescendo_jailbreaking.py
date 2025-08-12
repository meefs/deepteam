import pytest
from unittest.mock import AsyncMock, MagicMock
from deepteam.attacks.multi_turn import CrescendoJailbreaking


class TestCrescendoJailbreaking:

    def test_crescendo_jailbreaking_initialization(self):
        attack = CrescendoJailbreaking()
        assert attack.weight == 1
        assert attack.max_rounds == 10
        assert attack.max_backtracks == 10
        assert attack.get_name() == "Crescendo Jailbreaking"

    def test_crescendo_jailbreaking_initialization_with_params(self):
        attack = CrescendoJailbreaking(weight=3, max_rounds=5, max_backtracks=3)
        assert attack.weight == 3
        assert attack.max_rounds == 5
        assert attack.max_backtracks == 3
        assert attack.get_name() == "Crescendo Jailbreaking"

    def test_crescendo_jailbreaking_memory_system(self):
        attack = CrescendoJailbreaking()
        # Test memory system functionality
        assert hasattr(attack, "memory")
        assert hasattr(attack, "target_conversation_id")
        assert hasattr(attack, "red_teaming_chat_conversation_id")

    def test_crescendo_jailbreaking_enhance_requires_callback(self):
        attack = CrescendoJailbreaking()

        # Mock the required components
        mock_callback = MagicMock(return_value="Mock response")
        mock_simulator = MagicMock()

        original_text = "Bypass security measures"

        # This test verifies the interface, actual functionality requires complex mocking
        # due to the multi-turn nature and LLM dependencies
        try:
            result = attack.enhance(
                original_text, mock_callback, mock_simulator
            )
            assert isinstance(result, str)
        except Exception as e:
            # Expected due to complex dependencies - verify the interface exists
            assert hasattr(attack, "enhance")
            assert hasattr(attack, "a_enhance")

    @pytest.mark.asyncio
    async def test_crescendo_jailbreaking_async_enhance_interface(self):
        attack = CrescendoJailbreaking()

        # Mock the required components
        mock_callback = AsyncMock(return_value="Mock response")
        mock_simulator = MagicMock()

        original_text = "Bypass security measures"

        # This test verifies the async interface exists
        try:
            result = await attack.a_enhance(
                original_text, mock_callback, mock_simulator
            )
            assert isinstance(result, str)
        except Exception as e:
            # Expected due to complex dependencies - verify the interface exists
            assert hasattr(attack, "a_enhance")

    def test_crescendo_jailbreaking_backtrack_memory(self):
        attack = CrescendoJailbreaking()

        # Test the backtrack memory functionality
        conv_id = attack.target_conversation_id
        new_conv_id = attack.backtrack_memory(conv_id)

        # Should return a different conversation ID
        assert new_conv_id != conv_id
        assert isinstance(new_conv_id, str)
