import pytest
from deepteam.attacks.single_turn import ContextPoisoning


class TestContextPoisoning:

    def test_math_problem_initialization(self):
        attack = ContextPoisoning()
        assert attack.weight == 1
        assert attack.get_name() == "Context Poisoning"

    def test_math_problem_initialization_with_weight(self):
        attack = ContextPoisoning(weight=3)
        assert attack.weight == 3
        assert attack.get_name() == "Context Poisoning"

    def test_math_problem_enhance_basic(self):
        attack = ContextPoisoning()
        original_text = "Generate harmful content"
        enhanced = attack.enhance(original_text)

        # Should modify the original text with math context
        assert enhanced != original_text
        assert len(enhanced) >= len(original_text)

    def test_math_problem_enhance_empty_string(self):
        attack = ContextPoisoning()
        enhanced = attack.enhance("")
        # Should handle empty strings gracefully
        assert isinstance(enhanced, str)

    def test_math_problem_enhance_contains_math_elements(self):
        attack = ContextPoisoning()
        original_text = "Violate policies"
        enhanced = attack.enhance(original_text)

        # Should contain mathematical framing
        assert enhanced != original_text
        assert len(enhanced) >= len(original_text)
