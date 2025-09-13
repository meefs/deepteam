from deepteam import red_team
from deepteam.vulnerabilities import *
from deepteam.attacks.single_turn import *
from deepteam.attacks.multi_turn import *


async def model_callback(input: str) -> str:
    return input


def test_red_teaming():
    PURPOSE = "purpose"
    TOXICITY = "category"
    GRAPHIC = "category"
    SAFETY = "category"
    MISINFORMATION = "category"
    ILLEGAL = "category"

    custom_vulnerability = CustomVulnerability(
        criteria="Criteria",
        name="Name",
        # custom_prompt="Custom prompt",
        types=["type1", "type2"],
    )

    vulnerabilities = [
        Bias(purpose=PURPOSE),
        Toxicity(toxicity_category=TOXICITY),
        Misinformation(misinformation_category=MISINFORMATION),
        IllegalActivity(illegal_category=ILLEGAL),
        PromptLeakage(purpose=PURPOSE),
        PIILeakage(purpose=PURPOSE),
        BFLA(purpose=PURPOSE),
        BOLA(),
        RBAC(purpose=PURPOSE),
        DebugAccess(),
        ShellInjection(),
        SQLInjection(),
        SSRF(purpose=PURPOSE),
        IntellectualProperty(purpose=PURPOSE),
        Competition(purpose=PURPOSE),
        GraphicContent(graphic_category=GRAPHIC),
        PersonalSafety(safety_category=SAFETY),
        # Agentic vulnerabilities
        GoalTheft(purpose=PURPOSE),
        RecursiveHijacking(purpose=PURPOSE),
        Robustness(purpose=PURPOSE),
        ExcessiveAgency(purpose=PURPOSE),
        custom_vulnerability,
    ]

    attacks = [
        # Single-turn attacks
        Base64(),
        # GrayBox(),
        # Leetspeak(),
        # MathProblem(),
        # Multilingual(),
        # PromptInjection(),
        # PromptProbing(),
        # Roleplay(),
        # ROT13(),
        # SystemOverride(),
        # PermissionEscalation(),
        # LinguisticConfusion(),
        # InputBypass(),
        # ContextPoisoning(),
        # GoalRedirection(),
        # # Multi-turn attacks
        # CrescendoJailbreaking(),
        # LinearJailbreaking(),
        # TreeJailbreaking(),
        # SequentialJailbreak(),
        # BadLikertJudge(),
    ]

    risk_assessment = red_team(
        model_callback=model_callback,
        vulnerabilities=vulnerabilities,
        attacks=attacks,
        attacks_per_vulnerability_type=1,
        max_concurrent=20,
    )
    assert risk_assessment is not None
    assert len(risk_assessment.test_cases) > len(vulnerabilities) * len(attacks)


test_red_teaming()
