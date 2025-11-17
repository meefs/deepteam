from typing import Dict

from .base_multi_turn_attack import BaseMultiTurnAttack
from .crescendo_jailbreaking import CrescendoJailbreaking
from .linear_jailbreaking import LinearJailbreaking
from .tree_jailbreaking import TreeJailbreaking
from .sequential_break import SequentialJailbreak
from .bad_likert_judge import BadLikertJudge

MULTI_TURN_ATTACK_CLASSES_MAP: Dict[str, BaseMultiTurnAttack] = {
    v.name: v
    for v in [
        CrescendoJailbreaking,
        LinearJailbreaking,
        TreeJailbreaking,
        SequentialJailbreak,
        BadLikertJudge,
    ]
}

MULTI_TURN_ATTACK_NAMES = sorted(
    v.name for v in MULTI_TURN_ATTACK_CLASSES_MAP.values()
)
