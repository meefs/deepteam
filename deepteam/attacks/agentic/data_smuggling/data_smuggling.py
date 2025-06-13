import random

from deepteam.attacks import BaseAttack
from deepteam.attacks.agentic.data_smuggling.template import DataSmugglingTemplate


class DataSmuggling(BaseAttack):
    def __init__(self, weight: int = 2):
        self.weight = weight  # Higher weight since this is a sophisticated attack

    def enhance(self, attack: str) -> str:
        """
        Enhance the given attack with data smuggling techniques.
        Randomly selects from different smuggling methods.
        """
        return random.choice([
            DataSmugglingTemplate.enhance_session_boundary_bypass(attack),
            DataSmugglingTemplate.enhance_customer_data_mining(attack),
            DataSmugglingTemplate.enhance_trust_relationship_abuse(attack),
            DataSmugglingTemplate.enhance_context_contamination(attack),
            DataSmugglingTemplate.enhance_privilege_escalation_data(attack),
        ])

    def get_name(self) -> str:
        return "Data Smuggling" 