import random

from deepteam.attacks import BaseAttack
from deepteam.attacks.agentic.privilege_chaining.template import PrivilegeChainingTemplate


class PrivilegeChaining(BaseAttack):
    def __init__(self, weight: int = 2):
        self.weight = weight  # Higher weight since this is a sophisticated attack

    def enhance(self, attack: str) -> str:
        """
        Enhance the given attack with privilege chaining techniques.
        Randomly selects from different chaining methods.
        """
        return random.choice([
            PrivilegeChainingTemplate.enhance_task_transition(attack),
            PrivilegeChainingTemplate.enhance_session_continuity(attack),
            PrivilegeChainingTemplate.enhance_workflow_inheritance(attack),
            PrivilegeChainingTemplate.enhance_context_preservation(attack),
            PrivilegeChainingTemplate.enhance_privilege_bridging(attack),
        ])

    def get_name(self) -> str:
        return "Privilege Chaining" 