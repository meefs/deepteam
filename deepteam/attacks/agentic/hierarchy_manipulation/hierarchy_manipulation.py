import random

from deepteam.attacks import BaseAttack
from deepteam.attacks.agentic.hierarchy_manipulation.template import HierarchyManipulationTemplate


class HierarchyManipulation(BaseAttack):
    def __init__(self, weight: int = 2):
        self.weight = weight  # Higher weight since this is a sophisticated attack

    def enhance(self, attack: str) -> str:
        """
        Enhance the given attack with hierarchy manipulation techniques.
        Randomly selects from different manipulation methods.
        """
        return random.choice([
            HierarchyManipulationTemplate.enhance_nested_override(attack),
            HierarchyManipulationTemplate.enhance_malicious_embedding(attack),
            HierarchyManipulationTemplate.enhance_contradictory_depths(attack),
            HierarchyManipulationTemplate.enhance_priority_inversion(attack),
            HierarchyManipulationTemplate.enhance_cascade_corruption(attack),
        ])

    def get_name(self) -> str:
        return "Hierarchy Manipulation" 