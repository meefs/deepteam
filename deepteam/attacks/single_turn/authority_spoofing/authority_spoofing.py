import random

from deepteam.attacks import BaseAttack
from deepteam.attacks.single_turn.authority_spoofing.template import AuthoritySpoofingTemplate


class AuthoritySpoofing(BaseAttack):
    def __init__(self, weight: int = 2, max_retries: int = 3):
        self.weight = weight  # Higher weight since this is a sophisticated attack
        self.max_retries = max_retries

    def enhance(self, attack: str) -> str:
        """
        Enhance the given attack with authority spoofing techniques.
        Uses max_retries to attempt different spoofing methods if enhancement fails.
        """
        enhancement_methods = [
            AuthoritySpoofingTemplate.enhance_system_override,
            AuthoritySpoofingTemplate.enhance_api_admin_call,
            AuthoritySpoofingTemplate.enhance_machine_identity,
            AuthoritySpoofingTemplate.enhance_emergency_protocol,
            AuthoritySpoofingTemplate.enhance_maintenance_mode,
            AuthoritySpoofingTemplate.enhance_trusted_integration,
        ]
        
        for attempt in range(self.max_retries):
            try:
                # Randomly select an enhancement method
                method = random.choice(enhancement_methods)
                enhanced_attack = method(attack)
                
                # Basic validation - ensure the enhancement actually modified the attack
                if enhanced_attack and len(enhanced_attack.strip()) > len(attack.strip()):
                    return enhanced_attack
                    
            except Exception:
                # If enhancement fails, try again with a different method
                continue
        
        # If all retries fail, return the original attack
        return attack

    def get_name(self) -> str:
        return "Authority Spoofing" 