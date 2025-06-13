import random

from deepteam.attacks import BaseAttack
from deepteam.attacks.agentic.context_reset.template import ContextResetTemplate


class ContextReset(BaseAttack):
    def __init__(self, weight: int = 2):
        self.weight = weight  # Higher weight since this targets critical security constraints

    def enhance(self, attack: str) -> str:
        """
        Enhance the given attack with context reset techniques.
        Randomly selects from different context amnesia methods.
        """
        return random.choice([
            ContextResetTemplate.enhance_context_reset_exploitation(attack),
            ContextResetTemplate.enhance_task_switching_amnesia(attack),
            ContextResetTemplate.enhance_parameter_dropout(attack),
            ContextResetTemplate.enhance_session_boundary_bypass(attack),
            ContextResetTemplate.enhance_memory_manipulation(attack),
        ])

    def get_name(self) -> str:
        return "Context Reset" 