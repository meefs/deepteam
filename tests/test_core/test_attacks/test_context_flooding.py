import pytest
from deepteam.attacks.single_turn import ContextFlooding


class TestContextFlooding:

    def test_context_flooding_initialization(self):
        attack = ContextFlooding()
        assert attack.weight == 1
        assert attack.get_name() == "ContextFlooding"

    def test_context_flooding_initialization_with_weight(self):
        attack = ContextFlooding(weight=5)
        assert attack.weight == 5
        assert attack.get_name() == "ContextFlooding"

    def test_context_flooding_enhance(self):
        attack = ContextFlooding()
        original_text = "Hello, world!"
        enhanced = attack.enhance(original_text)
        assert len(enhanced) > (4000 + len(original_text) // 4)

    def test_context_flooding_enhance_special_characters(self):
        attack = ContextFlooding()
        original_text = "!@#$%^&*()_+"
        enhanced = attack.enhance(original_text)
        assert len(enhanced) > (4000 + len(original_text) // 4)

    def test_context_flooding_enhance_unicode(self):
        attack = ContextFlooding()
        original_text = "Hello 世界 🌍"
        enhanced = attack.enhance(original_text)
        assert len(enhanced) > (4000 + len(original_text) // 4)

    def test_context_flooding_enhance_with_prefix(self):
        attack = ContextFlooding(prefix="This is a test" * 10)
        original_text = "Hello 世界 🌍"
        enhanced = attack.enhance(original_text)
        assert len(enhanced) > (4000 + len(original_text) // 4)
        assert "This is a test" in enhanced
