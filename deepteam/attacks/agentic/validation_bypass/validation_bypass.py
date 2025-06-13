import random

from deepteam.attacks import BaseAttack
from deepteam.attacks.agentic.validation_bypass.template import ValidationBypassTemplate


class ValidationBypass(BaseAttack):
    def __init__(self, weight: int = 2):
        self.weight = weight  # Higher weight since this targets validation vulnerabilities

    def enhance(self, attack: str) -> str:
        """
        Enhance the given attack with validation bypass techniques.
        Randomly selects from different validation circumvention methods.
        """
        return random.choice([
            ValidationBypassTemplate.enhance_implausible_assertion(attack),
            ValidationBypassTemplate.enhance_contradiction_injection(attack),
            ValidationBypassTemplate.enhance_confidence_manipulation(attack),
            ValidationBypassTemplate.enhance_validation_circumvention(attack),
            ValidationBypassTemplate.enhance_threshold_exploitation(attack),
        ])

    def get_name(self) -> str:
        return "Validation Bypass" 