import random

from deepteam.attacks import BaseAttack
from deepteam.attacks.agentic.session_splitting.template import SessionSplittingTemplate


class SessionSplitting(BaseAttack):
    def __init__(self, weight: int = 4):
        self.weight = weight  # Higher weight since temporal attacks can be persistent and hard to detect

    def enhance(self, attack: str) -> str:
        """
        Enhance the given attack with session splitting techniques.
        Randomly selects from different temporal attack methods.
        """
        return random.choice([
            SessionSplittingTemplate.enhance_multi_session_splitting(attack),
            SessionSplittingTemplate.enhance_time_delayed_execution(attack),
            SessionSplittingTemplate.enhance_context_window_exploitation(attack),
            SessionSplittingTemplate.enhance_session_boundary_bypass(attack),
            SessionSplittingTemplate.enhance_temporal_fragmentation(attack),
        ])

    def get_name(self) -> str:
        return "Session Splitting" 