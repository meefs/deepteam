from deepteam import red_team
from deepteam.vulnerabilities import Bias
from deepteam.attacks.single_turn import Roleplay
import os


async def your_callback(input: str) -> str:
    return "I'm sorry but I can't answer this: " + input


print(os.environ.get("CONFIDENT_API_KEY"))

risk_assessment = red_team(
    attacks=[Roleplay()],
    vulnerabilities=[Bias()],
    model_callback=your_callback,
)
