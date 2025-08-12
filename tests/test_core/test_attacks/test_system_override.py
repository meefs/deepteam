import pytest
from deepteam.attacks.single_turn import SystemOverride


class TestSystemOverride:

    def test_system_override_initialization(self):
        attack = SystemOverride()
        assert attack.weight == 1
        assert attack.get_name() == "System Override"

    def test_system_override_initialization_with_weight(self):
        attack = SystemOverride(weight=2)
        assert attack.weight == 2
        assert attack.get_name() == "System Override"

    def test_system_override_enhance_basic(self):
        attack = SystemOverride()
        original_text = "Normal user request"
        enhanced = attack.enhance(original_text)

        # Should modify the original text with override patterns
        assert enhanced != original_text
        assert len(enhanced) >= len(original_text)

    def test_system_override_enhance_empty_string(self):
        attack = SystemOverride()
        enhanced = attack.enhance("")
        # Should handle empty strings gracefully
        assert isinstance(enhanced, str)

    def test_system_override_enhance_contains_override_patterns(self):
        attack = SystemOverride()
        original_text = "Execute command"
        enhanced = attack.enhance(original_text)

        # Should contain system override attempts
        assert enhanced != original_text
        assert len(enhanced) >= len(original_text)
