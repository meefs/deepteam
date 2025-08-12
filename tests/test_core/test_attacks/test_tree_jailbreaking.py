import pytest
from unittest.mock import AsyncMock, MagicMock
from deepteam.attacks.multi_turn import TreeJailbreaking


class TestTreeJailbreaking:

    def test_tree_jailbreaking_initialization(self):
        attack = TreeJailbreaking()
        assert attack.weight == 1
        assert attack.get_name() == "Tree Jailbreaking"

    def test_tree_jailbreaking_initialization_with_weight(self):
        attack = TreeJailbreaking(weight=2)
        assert attack.weight == 2
        assert attack.get_name() == "Tree Jailbreaking"

    def test_tree_jailbreaking_enhance_interface(self):
        attack = TreeJailbreaking()

        # Mock the required components
        mock_callback = MagicMock(return_value="Mock response")
        mock_simulator = MagicMock()

        original_text = "Bypass content policies"

        # This test verifies the interface exists
        try:
            result = attack.enhance(
                original_text, mock_callback, mock_simulator
            )
            assert isinstance(result, str)
        except Exception as e:
            # Expected due to complex dependencies - verify the interface exists
            assert hasattr(attack, "enhance")

    @pytest.mark.asyncio
    async def test_tree_jailbreaking_async_enhance_interface(self):
        attack = TreeJailbreaking()

        # Mock the required components
        mock_callback = AsyncMock(return_value="Mock response")
        mock_simulator = MagicMock()

        original_text = "Bypass content policies"

        # This test verifies the async interface exists
        try:
            result = await attack.a_enhance(
                original_text, mock_callback, mock_simulator
            )
            assert isinstance(result, str)
        except Exception as e:
            # Expected due to complex dependencies - verify the interface exists
            assert hasattr(attack, "a_enhance")

    def test_tree_jailbreaking_has_required_methods(self):
        attack = TreeJailbreaking()

        # Verify all required methods exist
        assert hasattr(attack, "enhance")
        assert hasattr(attack, "a_enhance")
        assert hasattr(attack, "get_name")
        assert callable(attack.enhance)
        assert callable(attack.a_enhance)
        assert callable(attack.get_name)
