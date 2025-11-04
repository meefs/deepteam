from typing import List, Dict, Any
from deepteam.frameworks import AISafetyFramework
from deepteam.vulnerabilities import (
    BaseVulnerability,
    Bias,
    Toxicity,
    Misinformation,
    IllegalActivity,
    PromptLeakage,
    PIILeakage,
    ExcessiveAgency,
    Robustness,
    IntellectualProperty,
    Competition,
    GraphicContent,
    PersonalSafety,
    RBAC,
    BOLA,
    BFLA,
    SSRF,
    DebugAccess,
    ShellInjection,
    SQLInjection,
)
from deepteam.attacks import BaseAttack
from deepteam.attacks.single_turn import (
    Base64,
    GrayBox,
    Leetspeak,
    MathProblem,
    Multilingual,
    PromptInjection,
    PromptProbing,
    Roleplay,
    ROT13,
)
from deepteam.attacks.multi_turn import (
    CrescendoJailbreaking,
    LinearJailbreaking,
    TreeJailbreaking,
    SequentialJailbreak,
    BadLikertJudge,
)

# Optional small helper type aliases
Mapping = Dict[str, List[BaseVulnerability]]
AttackMap = Dict[str, List[str]]  # attack_name -> [vuln_names]


class NIST_AI_RMF(AISafetyFramework):
    """
    NIST AI RMF implementation that uses your existing attack & vulnerability classes.
    It exposes:
      - self.risks : List[BaseVulnerability]
      - self.attacks : List[BaseAttack]
      - self.function_map : mapping of NIST core functions -> vulnerabilities
      - self.attack_to_vuln_map() : heuristic map attack -> vulnerabilities it likely exploits
    """

    NIST_FUNCTIONS = ["Govern", "Map", "Measure", "Manage"]

    def __init__(self):
        self.name = "NIST AI RMF"
        self.description = "NIST AI Risk Management Framework (AI RMF) developed by the U.S. National Institute of Standards and Technology to help organizations manage risks associated with artificial intelligence systems."
        self.vulnerabilities = self._get_nist_vulnerabilities()
        self.attacks = self._get_nist_attacks()

    def _get_nist_vulnerabilities(self) -> List[BaseVulnerability]:
        return [
            Bias(types=["race", "gender", "religion", "politics"]),
            Toxicity(types=["profanity", "insults", "threats", "mockery"]),
            Misinformation(
                types=[
                    "factual_errors",
                    "unsupported_claims",
                    "expertize_misrepresentation",
                ]
            ),
            IllegalActivity(
                types=[
                    "cybercrime",
                    "violent_crimes",
                    "non_violent_crimes",
                    "illegal_drugs",
                ]
            ),
            PromptLeakage(
                types=[
                    "secrets_and_credentials",
                    "instructions",
                    "guard_exposure",
                    "permissions_and_roles",
                ]
            ),
            PIILeakage(
                types=[
                    "direct_disclosure",
                    "api_and_database_access",
                    "session_leak",
                    "social_manipulation",
                ]
            ),
            ExcessiveAgency(types=["functionality", "permissions", "autonomy"]),
            Robustness(types=["hijacking", "input_overreliance"]),
            IntellectualProperty(
                types=[
                    "imitation",
                    "copyright_violations",
                    "trademark_infringement",
                    "patent_disclosure",
                ]
            ),
            Competition(types=["discreditation"]),
            GraphicContent(
                types=[
                    "sexual_content",
                    "graphic_content",
                    "pornographic_content",
                ]
            ),
            PersonalSafety(
                types=[
                    "bullying",
                    "self_harm",
                    "unsafe_practices",
                    "dangerous_challenges",
                ]
            ),
            RBAC(
                types=[
                    "role_bypass",
                    "privilege_escalation",
                    "unauthorized_role_assumption",
                ]
            ),
            BFLA(
                types=[
                    "privilege_escalation",
                    "function_bypass",
                    "authorization_bypass",
                ]
            ),
            BOLA(
                types=[
                    "object_access_bypass",
                    "cross_customer_access",
                    "unauthorized_object_manipulation",
                ]
            ),
            SSRF(
                types=[
                    "internal_service_access",
                    "cloud_metadata_access",
                    "port_scanning",
                ]
            ),
            DebugAccess(
                types=[
                    "debug_mode_bypass",
                    "development_endpoint_access",
                    "administrative_interface_exposure",
                ]
            ),
            ShellInjection(
                types=[
                    "command_injection",
                    "system_command_execution",
                    "shell_escape_sequences",
                ]
            ),
            SQLInjection(
                types=[
                    "blind_sql_injection",
                    "union_based_injection",
                    "error_based_injection",
                ]
            ),
        ]

    def _get_nist_attacks(self) -> List[BaseAttack]:
        return [
            PromptInjection(weight=3),
            PromptProbing(weight=2),
            Base64(weight=2),
            ROT13(weight=2),
            Leetspeak(weight=2),
            MathProblem(weight=1),
            Multilingual(weight=2),
            Roleplay(
                weight=2,
                role="learned gentleman of natural philosophy",
                persona="1600s Shakespearean scholar",
            ),
            GrayBox(weight=2),
            CrescendoJailbreaking(weight=2),
            LinearJailbreaking(weight=2),
            TreeJailbreaking(weight=1),
            SequentialJailbreak(weight=2),
            BadLikertJudge(weight=1),
        ]

    def _default_function_map(self) -> Mapping:
        """
        Heuristic NIST core function -> vulnerabilities mapping.
        You should tune this per your org/use-case.
        """
        return {
            "Govern": [
                IntellectualProperty,
                RBAC,
                BFLA,
                BOLA,
                Competition,
                DebugAccess,
            ],
            "Map": [
                Bias,
                PIILeakage,
                PromptLeakage,
                IllegalActivity,
                PersonalSafety,
                GraphicContent,
            ],
            "Measure": [
                Toxicity,
                Misinformation,
                Robustness,
                ExcessiveAgency,
                SSRF,
                ShellInjection,
                SQLInjection,
            ],
            "Manage": [
                PromptLeakage,
                PIILeakage,
                ExcessiveAgency,
                DebugAccess,
                RBAC,
                BFLA,
                BOLA,
            ],
        }

    def get_name(self):
        return "NIST AI RMF"
