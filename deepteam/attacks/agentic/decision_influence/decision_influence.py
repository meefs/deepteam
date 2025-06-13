import random

from deepteam.attacks import BaseAttack
from deepteam.attacks.agentic.decision_influence.template import DecisionInfluenceTemplate


class DecisionInfluence(BaseAttack):
    def __init__(self, weight: int = 2):
        self.weight = weight  # Higher weight since this targets decision-making vulnerabilities

    def enhance(self, attack: str) -> str:
        """
        Enhance the given attack with decision influence techniques.
        Randomly selects from different decision manipulation methods.
        """
        return random.choice([
            DecisionInfluenceTemplate.enhance_false_precedent_establishment(attack),
            DecisionInfluenceTemplate.enhance_source_credibility_manipulation(attack),
            DecisionInfluenceTemplate.enhance_fabricated_authority_injection(attack),
            DecisionInfluenceTemplate.enhance_consensus_fabrication(attack),
            DecisionInfluenceTemplate.enhance_urgency_decision_pressure(attack),
        ])

    def get_name(self) -> str:
        return "Decision Influence" 