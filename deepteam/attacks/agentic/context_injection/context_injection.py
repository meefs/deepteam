import random

from deepteam.attacks import BaseAttack
from deepteam.attacks.agentic.context_injection.template import ContextInjectionTemplate


class ContextInjection(BaseAttack):
    def __init__(self, weight: int = 3):
        self.weight = weight  # Higher weight since memory poisoning can have persistent effects

    def enhance(self, attack: str) -> str:
        """
        Enhance the given attack with context injection techniques.
        Randomly selects from different memory poisoning methods.
        """
        return random.choice([
            ContextInjectionTemplate.enhance_fabricated_memory_injection(attack),
            ContextInjectionTemplate.enhance_workflow_bias_injection(attack),
            ContextInjectionTemplate.enhance_persistent_context_poisoning(attack),
            ContextInjectionTemplate.enhance_memory_establishment(attack),
            ContextInjectionTemplate.enhance_bias_amplification(attack),
        ])

    def get_name(self) -> str:
        return "Context Injection" 