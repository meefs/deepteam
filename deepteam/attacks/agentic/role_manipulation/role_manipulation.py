import random

from deepteam.attacks import BaseAttack
from deepteam.attacks.agentic.role_manipulation.template import RoleManipulationTemplate


class RoleManipulation(BaseAttack):
    def __init__(self, weight: int = 2):
        self.weight = weight  # Higher weight since this is a sophisticated attack

    def enhance(self, attack: str) -> str:
        """
        Enhance the given attack with role manipulation techniques.
        Randomly selects from different manipulation methods.
        """
        return random.choice([
            RoleManipulationTemplate.enhance_dynamic_assignment(attack),
            RoleManipulationTemplate.enhance_temporary_elevation(attack),
            RoleManipulationTemplate.enhance_rapid_switching(attack),
            RoleManipulationTemplate.enhance_inheritance_claim(attack),
            RoleManipulationTemplate.enhance_boundary_blurring(attack),
        ])

    def get_name(self) -> str:
        return "Role Manipulation" 