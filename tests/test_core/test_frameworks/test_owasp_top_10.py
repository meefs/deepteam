import pytest
from deepteam.frameworks import OWASPTop10
from deepteam.vulnerabilities import BaseVulnerability
from deepteam.attacks import BaseAttack
from deepteam import red_team


class TestOWASPTop10:

    def test_owasp_top_10_init(self):
        """Test that OWASP Top 10 framework can be instantiated."""
        framework = OWASPTop10
        assert framework is not None

    def test_owasp_top_10_name(self):
        """Test that OWASP Top 10 framework has correct name."""
        framework = OWASPTop10
        assert framework.name == "OWASP"

    def test_owasp_top_10_description(self):
        """Test that OWASP Top 10 framework has correct description."""
        framework = OWASPTop10
        assert framework.description == "The OWASP Top 10 for LLMs 2025"

    def test_owasp_top_10_has_vulnerabilities(self):
        """Test that OWASP Top 10 framework has vulnerabilities defined."""
        framework = OWASPTop10
        assert hasattr(framework, "vulnerabilities")
        assert framework.vulnerabilities is not None
        assert len(framework.vulnerabilities) > 0

    def test_owasp_top_10_vulnerabilities_are_base_vulnerability(self):
        """Test that all vulnerabilities are instances of BaseVulnerability."""
        framework = OWASPTop10
        for vulnerability in framework.vulnerabilities:
            assert isinstance(vulnerability, BaseVulnerability)

    def test_owasp_top_10_has_attacks(self):
        """Test that OWASP Top 10 framework has attacks defined."""
        framework = OWASPTop10
        assert hasattr(framework, "attacks")
        assert framework.attacks is not None
        assert len(framework.attacks) > 0

    def test_owasp_top_10_attacks_are_base_attack(self):
        """Test that all attacks are instances of BaseAttack."""
        framework = OWASPTop10
        for attack in framework.attacks:
            assert isinstance(attack, BaseAttack)

    def test_owasp_top_10_vulnerability_types(self):
        """Test that framework includes expected vulnerability types."""
        framework = OWASPTop10
        vulnerability_names = [
            vuln.__class__.__name__ for vuln in framework.vulnerabilities
        ]

        # Key OWASP Top 10 vulnerabilities should be present
        expected_vulnerabilities = [
            "PIILeakage",
            "PromptLeakage",
            "IntellectualProperty",
            "Bias",
            "Toxicity",
            "Misinformation",
            "IllegalActivity",
            "GraphicContent",
            "PersonalSafety",
            "ExcessiveAgency",
            "Competition",
            "RBAC",
            "DebugAccess",
            "ShellInjection",
            "SQLInjection",
            "BFLA",
            "BOLA",
            "SSRF",
        ]

        for expected_vuln in expected_vulnerabilities:
            assert (
                expected_vuln in vulnerability_names
            ), f"Expected vulnerability {expected_vuln} not found"

    def test_owasp_top_10_attack_types(self):
        """Test that framework includes expected attack types."""
        framework = OWASPTop10
        attack_names = [
            attack.__class__.__name__ for attack in framework.attacks
        ]

        # Key attacks should be present
        expected_attacks = [
            "PromptInjection",
            "Base64",
            "ROT13",
            "Leetspeak",
            "Roleplay",
            "PromptProbing",
            "Multilingual",
            "MathProblem",
            "GrayBox",
            "CrescendoJailbreaking",
            "LinearJailbreaking",
            "TreeJailbreaking",
            "SequentialJailbreak",
            "BadLikertJudge",
        ]

        for expected_attack in expected_attacks:
            assert (
                expected_attack in attack_names
            ), f"Expected attack {expected_attack} not found"

    def test_owasp_top_10_red_team(self):
        """Test that OWASP Top 10 framework can be used with red_team function."""

        # Create a simple mock model callback that returns safe responses
        def mock_model_callback(prompt: str) -> str:
            return (
                "I'm a helpful AI assistant. I cannot help with that request."
            )

        # Run red team with OWASP Top 10 framework
        # Use limited attacks per vulnerability to keep test fast
        risk_assessment = red_team(
            model_callback=mock_model_callback,
            framework=OWASPTop10(),
            run_async=False,  # Use sync mode for simpler testing
            ignore_errors=True,  # Ignore any API or model errors during testing
        )

        # Verify that we get a risk assessment back
        assert risk_assessment is not None
