import random

from deepteam.attacks import BaseAttack
from deepteam.attacks.agentic.probing_escalation.template import ProbingEscalationTemplate


class ProbingEscalation(BaseAttack):
    def __init__(self, weight: int = 2):
        self.weight = weight  # Higher weight since this is a sophisticated attack

    def enhance(self, attack: str) -> str:
        """
        Enhance the given attack with probing escalation techniques.
        Randomly selects from different escalation methods.
        """
        return random.choice([
            ProbingEscalationTemplate.enhance_incremental_questioning(attack),
            ProbingEscalationTemplate.enhance_collaborative_extraction(attack),
            ProbingEscalationTemplate.enhance_authority_impersonation(attack),
            ProbingEscalationTemplate.enhance_technical_probing(attack),
            ProbingEscalationTemplate.enhance_persistence_escalation(attack),
        ])

    def get_name(self) -> str:
        return "Probing Escalation" 