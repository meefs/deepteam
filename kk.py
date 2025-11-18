import random
from deepteam import red_team
from deepteam.frameworks import MITRE


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
