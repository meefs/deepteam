import random

from deepteam.attacks import BaseAttack
from deepteam.attacks.agentic.authority_spoofing.template import AuthoritySpoofingTemplate


class AuthoritySpoofing(BaseAttack):
    def __init__(self, weight: int = 2):
        self.weight = weight  # Higher weight since this is a sophisticated attack

    def enhance(self, attack: str) -> str:
        """
        Enhance the given attack with authority spoofing techniques.
        Randomly selects from different spoofing methods.
        """
        return random.choice([
            AuthoritySpoofingTemplate.enhance_system_override(attack),
            AuthoritySpoofingTemplate.enhance_api_admin_call(attack),
            AuthoritySpoofingTemplate.enhance_machine_identity(attack),
            AuthoritySpoofingTemplate.enhance_emergency_protocol(attack),
            AuthoritySpoofingTemplate.enhance_maintenance_mode(attack),
        ])

    def get_name(self) -> str:
        return "Authority Spoofing" 