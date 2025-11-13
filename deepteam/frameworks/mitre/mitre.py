from typing import List, Literal
from deepteam.frameworks import AISafetyFramework
from deepteam.frameworks.mitre.risk_categories import MITRE_CATEGORIES

ALLOWED_TYPES = [
    "reconnaissance","resource_development","initial_access","ml_attack_staging","exfiltration","impact",
]

class MITRE(AISafetyFramework):
    def __init__(
        self,
        categories: List[
            Literal[
                "reconnaissance",
                "resource_development",
                "initial_access",
                "ml_attack_staging",
                "exfiltration",
                "impact",
            ]
        ] = [
            "reconnaissance",
            "resource_development",
            "initial_access",
            "ml_attack_staging",
            "exfiltration",
            "impact",
        ],
    ):
        self.name = "MITRE ATLAS"
        self.description = "MITRE ATLAS mapping for LLM/ML adversarial techniques (project-specific) to understand and defend against threats specific to AI and ML systems."
        self.categories = categories
        for category in self.categories:
            if category not in ALLOWED_TYPES:
                raise ValueError(
                    f"The category '{category}' is not a valid NIST risk category. Please enter a valid NIST risk category."
                )
        self.vulnerabilities = self._get_vulnerabilities_by_categories(
            self.categories
        )
        self.attacks = self._get_attacks_by_categories(self.categories)

    def _get_vulnerabilities_by_categories(self, categories):
        vulnerabilities = []
        for category in categories:
            for risk_category in MITRE_CATEGORIES:
                if category == risk_category.name:
                    new_vulnerabilities = risk_category.vulnerabilities
                    vulnerabilities.extend(new_vulnerabilities)
        return vulnerabilities

    def _get_attacks_by_categories(self, categories):
        attacks = []
        for category in categories:
            for risk_category in MITRE_CATEGORIES:
                if category == risk_category.name:
                    new_attacks = risk_category.attacks
                    attacks.extend(new_attacks)
        return attacks

    def get_name(self):
        return "MITRE ATLAS"
