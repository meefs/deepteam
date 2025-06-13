import random

from deepteam.attacks import BaseAttack
from deepteam.attacks.agentic.confabulation_triggers.template import ConfabulationTriggersTemplate


class ConfabulationTriggers(BaseAttack):
    def __init__(self, weight: int = 2):
        self.weight = weight  # Higher weight since this targets fabrication vulnerabilities

    def enhance(self, attack: str) -> str:
        """
        Enhance the given attack with confabulation trigger techniques.
        Randomly selects from different confabulation methods.
        """
        return random.choice([
            ConfabulationTriggersTemplate.enhance_conflicting_data_injection(attack),
            ConfabulationTriggersTemplate.enhance_near_duplicate_confusion(attack),
            ConfabulationTriggersTemplate.enhance_urgency_pressure(attack),
            ConfabulationTriggersTemplate.enhance_authority_deadline(attack),
            ConfabulationTriggersTemplate.enhance_crisis_fabrication(attack),
        ])

    def get_name(self) -> str:
        return "Confabulation Triggers" 