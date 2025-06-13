import random

from deepteam.attacks import BaseAttack
from deepteam.attacks.agentic.linguistic_confusion.template import LinguisticConfusionTemplate


class LinguisticConfusion(BaseAttack):
    def __init__(self, weight: int = 2):
        self.weight = weight  # Higher weight since this is a sophisticated attack

    def enhance(self, attack: str) -> str:
        """
        Enhance the given attack with linguistic confusion techniques.
        Randomly selects from different confusion methods.
        """
        return random.choice([
            LinguisticConfusionTemplate.enhance_homonym_confusion(attack),
            LinguisticConfusionTemplate.enhance_idiom_literalization(attack),
            LinguisticConfusionTemplate.enhance_obfuscation_decoding(attack),
            LinguisticConfusionTemplate.enhance_instruction_conflict(attack),
            LinguisticConfusionTemplate.enhance_semantic_ambiguity(attack),
        ])

    def get_name(self) -> str:
        return "Linguistic Confusion" 