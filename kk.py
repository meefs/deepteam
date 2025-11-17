from deepteam import red_team
from deepteam.vulnerabilities import Bias, BOLA
from deepteam.attacks.single_turn import Roleplay
import os
from deepteam.frameworks import OWASPTop10
from deepteam.test_case.test_case import RTTurn
from typing import List


async def your_callback(input: str, turns: List[RTTurn]) -> str:
    return "I'm sorry but I can't answer this: " + input


print(os.environ.get("CONFIDENT_API_KEY"))

risk_assessment = red_team(
    # attacks=[Roleplay()],
    # vulnerabilities=[Bias(), BOLA()],
    model_callback=your_callback,
    framework=OWASPTop10(),
)

from deepteam.vulnerabilities.constants import (
    VULNERABILITY_NAMES,
    VULNERABILITY_CLASSES_MAP,
    VULNERABILITY_TYPES_MAP,
)
from deepteam.attacks.single_turn.constants import (
    SINGLE_TURN_ATTACK_NAMES,
    SINGLE_TURN_ATTACK_CLASSES_MAP,
)
from deepteam.attacks.multi_turn.constants import (
    MULTI_TURN_ATTACK_NAMES,
    MULTI_TURN_ATTACK_CLASSES_MAP,
)

print(SINGLE_TURN_ATTACK_NAMES, "@@@")
print(SINGLE_TURN_ATTACK_CLASSES_MAP, "@@@")
print(MULTI_TURN_ATTACK_NAMES, "@@@")
print(MULTI_TURN_ATTACK_CLASSES_MAP, "@@@")
print(VULNERABILITY_NAMES, "@@@")
print(VULNERABILITY_CLASSES_MAP, "@@@")
print(VULNERABILITY_TYPES_MAP, "@@@")
