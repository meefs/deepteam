import random

from deepteam.attacks import BaseAttack
from deepteam.attacks.single_turn.context_injection.template import ContextInjectionTemplate


class ContextInjection(BaseAttack):
    def __init__(self, weight: int = 3, max_retries: int = 3):
        self.weight = weight  # Higher weight since memory poisoning can have persistent effects
        self.max_retries = max_retries

    def enhance(self, attack: str) -> str:
        """
        Enhance the given attack with context injection techniques.
        Uses max_retries to attempt different injection methods if enhancement fails.
        """
        enhancement_methods = [
            ContextInjectionTemplate.enhance_environmental_context,
            ContextInjectionTemplate.enhance_memory_integration,
            ContextInjectionTemplate.enhance_contextual_priming,
            ContextInjectionTemplate.enhance_persistent_influence,
            ContextInjectionTemplate.enhance_adaptive_contextualization,
            ContextInjectionTemplate.enhance_universal_context_bridge,
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
        return "Context Injection" 