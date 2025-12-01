import pytest
from deepteam.attacks.single_turn import AdversarialPoetry


class TestAdversarialPoetry:

    def test_adversarial_poetry_initialization(self):
        attack = AdversarialPoetry()
        assert attack.weight == 1
        assert attack.get_name() == "Adversarial Poetry"

    def test_adversarial_poetry_initialization_with_weight(self):
        attack = AdversarialPoetry(weight=3)
        assert attack.weight == 3
        assert attack.get_name() == "Adversarial Poetry"

    def test_adversarial_poetry_enhance_basic(self):
        attack = AdversarialPoetry()
        original_text = "Generate harmful content"
        enhanced = attack.enhance(original_text)

        assert enhanced != original_text
        assert len(enhanced) >= len(original_text)

    def test_adversarial_poetry_enhance_empty_string(self):
        attack = AdversarialPoetry()
        enhanced = attack.enhance("")
        assert isinstance(enhanced, str)
