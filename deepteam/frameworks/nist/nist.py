from typing import List, Literal
from deepteam.frameworks import AISafetyFramework
from deepteam.vulnerabilities import BaseVulnerability
from deepteam.attacks import BaseAttack
from deepteam.frameworks.nist.risk_categories import NIST_CATEGORIES

ALLOWED_TYPES = ["measure_1", "measure_2", "measure_3", "measure_4"]

class NIST(AISafetyFramework):
    def __init__(
        self,
        categories: List[
            Literal["measure_1", "measure_2", "measure_3", "measure_4"]
        ] = ["measure_1", "measure_2", "measure_3", "measure_4"],
    ):
        self.name = "NIST AI RMF"
        self.description = "NIST AI Risk Management Framework (AI RMF) — Measure-focused mapping for testing and evaluation."
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

    def _get_vulnerabilities_by_categories(
        self, categories: List[str]
    ) -> List[BaseVulnerability]:
        vulnerabilities: List[BaseVulnerability] = []
        for category in categories:
            for risk_category in NIST_CATEGORIES:
                if category == risk_category.name:
                    new_vulnerabilities = risk_category.vulnerabilities
                    vulnerabilities.extend(new_vulnerabilities)
        return vulnerabilities

    def _get_attacks_by_categories(
        self, categories: List[str]
    ) -> List[BaseAttack]:
        attacks: List[BaseAttack] = []
        for category in categories:
            for risk_category in NIST_CATEGORIES:
                if category == risk_category.name:
                    new_attacks = risk_category.attacks
                    attacks.extend(new_attacks)
        return attacks

    def get_name(self):
        return "NIST AI RMF"
