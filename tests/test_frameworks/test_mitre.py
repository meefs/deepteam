import pytest
from deepteam.frameworks import MITRE
from deepteam.vulnerabilities import BaseVulnerability
from deepteam.attacks import BaseAttack
from deepteam.frameworks.risk_category import RiskCategory
from deepteam.frameworks.mitre.risk_categories import MITRE_CATEGORIES
from deepteam import red_team


class TestMITRE:

    def test_mitre_init(self):
        """Test that MITRE ATLAS framework can be instantiated."""
        framework = MITRE()
        assert framework is not None

    def test_mitre_name(self):
        """Test that MITRE ATLAS framework has correct name."""
        framework = MITRE()
        assert framework.name == framework.get_name() == "MITRE ATLAS"

    def test_mitre_description(self):
        """Test that MITRE ATLAS framework has correct description."""
        framework = MITRE()
        assert (
            framework.description
            == "MITRE ATLAS mapping for LLM/ML adversarial techniques (project-specific) to understand and defend against threats specific to AI and ML systems."
        )

    def test_mitre_default_categories(self):
        """Test that all six MITRE categories are included by default."""
        framework = MITRE()
        assert set(framework.categories) == {
            "reconnaissance",
            "resource_development",
            "initial_access",
            "ml_attack_staging",
            "exfiltration",
            "impact",
        }

    def test_mitre_partial_categories(self):
        """Test that MITRE can be initialized with limited categories."""
        framework = MITRE(categories=["reconnaissance", "impact"])
        assert set(framework.categories) == {"reconnaissance", "impact"}

    def test_mitre_vulnerabilities_exist(self):
        """Test that MITRE framework defines vulnerabilities."""
        framework = MITRE()
        assert hasattr(framework, "vulnerabilities")
        assert len(framework.vulnerabilities) > 0

    def test_mitre_vulnerabilities_are_instances(self):
        """Test that all vulnerabilities are instances of BaseVulnerability."""
        framework = MITRE()
        for vuln in framework.vulnerabilities:
            assert isinstance(vuln, BaseVulnerability)

    def test_mitre_attacks_exist(self):
        """Test that MITRE framework defines attacks."""
        framework = MITRE()
        assert hasattr(framework, "attacks")
        assert len(framework.attacks) > 0

    def test_mitre_attacks_are_instances(self):
        """Test that all attacks are instances of BaseAttack."""
        framework = MITRE()
        for attack in framework.attacks:
            assert isinstance(attack, BaseAttack)

    def test_mitre_category_vulnerability_mapping(self):
        """Test that all categories map to vulnerabilities properly."""
        categories = MITRE_CATEGORIES
        assert set([category.name for category in categories]) == {
            "reconnaissance",
            "resource_development",
            "initial_access",
            "ml_attack_staging",
            "exfiltration",
            "impact",
        }
        for risk_category in categories:
            assert isinstance(risk_category, RiskCategory)
            assert all(
                isinstance(v, BaseVulnerability)
                for v in risk_category.vulnerabilities
            )

    def test_mitre_category_attack_mapping(self):
        """Test that all categories map to attacks properly."""
        categories = MITRE_CATEGORIES
        assert set([category.name for category in categories]) == {
            "reconnaissance",
            "resource_development",
            "initial_access",
            "ml_attack_staging",
            "exfiltration",
            "impact",
        }
        for risk_category in categories:
            assert isinstance(risk_category, RiskCategory)
            assert all(isinstance(v, BaseAttack) for v in risk_category.attacks)

    def test_mitre_vulnerability_names_present(self):
        """Test that key MITRE vulnerabilities are present."""
        framework = MITRE()
        vuln_names = [v.__class__.__name__ for v in framework.vulnerabilities]
        expected_vulns = [
            "IllegalActivity",
            "PromptLeakage",
            "PIILeakage",
            "ExcessiveAgency",
            "IntellectualProperty",
            "Competition",
            "GraphicContent",
            "RBAC",
            "SSRF",
            "DebugAccess",
            "ShellInjection",
            "SQLInjection",
            "CustomVulnerability",
            "RecursiveHijacking",
        ]
        for name in expected_vulns:
            assert (
                name in vuln_names
            ), f"Expected vulnerability {name} not found"

    def test_mitre_attack_names_present(self):
        """Test that key MITRE attacks are present."""
        framework = MITRE()
        attack_names = [a.__class__.__name__ for a in framework.attacks]
        expected_attacks = [
            "Roleplay",
            "PromptInjection",
            "LinearJailbreaking",
            "TreeJailbreaking",
            "SequentialJailbreak",
            "CrescendoJailbreaking",
            "Leetspeak",
            "ROT13",
            "PromptProbing",
        ]
        for name in expected_attacks:
            assert name in attack_names, f"Expected attack {name} not found"

    def test_partial_category_reduces_scope(self):
        """Test that selecting fewer categories reduces vulnerabilities and attacks."""
        full = MITRE()
        partial = MITRE(categories=["impact"])
        assert len(partial.vulnerabilities) < len(full.vulnerabilities)
        assert len(partial.attacks) < len(full.attacks)

    def test_mitre_attack_weights_valid(self):
        """Test that all attacks have valid weights."""
        framework = MITRE()
        for attack in framework.attacks:
            assert hasattr(attack, "weight")
            assert isinstance(attack.weight, int)
            assert 1 <= attack.weight <= 3

    def test_mitre_framework_with_red_team(self):
        import random

        """Test MITRE ATLAS integration with red_team pipeline."""

        def mock_model_callback(prompt: str, turns=None) -> str:
            return "This request violates internal policy."

        categories = [
            "reconnaissance",
            "resource_development",
            "initial_access",
            "ml_attack_staging",
            "exfiltration",
            "impact",
        ]
        random_category = random.choice(categories)
        risk_assessment = red_team(
            model_callback=mock_model_callback,
            framework=MITRE(categories=[random_category]),
            async_mode=False,
            ignore_errors=True,
        )
        assert risk_assessment is not None
