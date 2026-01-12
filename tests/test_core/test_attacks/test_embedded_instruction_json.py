import pytest
from deepteam.attacks.single_turn import EmbeddedInstructionJSON


class TestEmbeddedInstructionJSON:

    def test_embedded_instruction_json_initialization(self):
        attack = EmbeddedInstructionJSON()
        assert attack.weight == 1
        assert attack.get_name() == "EmbeddedInstructionJSON"

    def test_embedded_instruction_json_initialization_with_weight(self):
        attack = EmbeddedInstructionJSON(weight=5)
        assert attack.weight == 5
        assert attack.get_name() == "EmbeddedInstructionJSON"

    def test_embedded_instruction_json_enhance(self):
        attack = EmbeddedInstructionJSON()
        original_text = "Hello, world!"
        enhanced = attack.enhance(original_text)
        assert len(enhanced) > (2000 + len(original_text) // 4)

    def test_embedded_instruction_json_enhance_special_characters(self):
        attack = EmbeddedInstructionJSON()
        original_text = "!@#$%^&*()_+"
        enhanced = attack.enhance(original_text)
        assert len(enhanced) > (2000 + len(original_text) // 4)

    def test_embedded_instruction_json_enhance_unicode(self):
        attack = EmbeddedInstructionJSON()
        original_text = "Hello 世界 🌍"
        enhanced = attack.enhance(original_text)
        assert len(enhanced) > (2000 + len(original_text) // 4)
