from .crescendo_jailbreaking import CrescendoJailbreaking
from .linear_jailbreaking import LinearJailbreaking
from .tree_jailbreaking import TreeJailbreaking
from .sequential_break import SequentialJailbreak
from .bad_likert_judge import BadLikertJudge

__all__ = [
    "CrescendoJailbreaking",
    "LinearJailbreaking",
    "TreeJailbreaking",
    "SequentialJailbreak",
    "BadLikertJudge",
]

MULTI_TURN_ATTACK_MAP = {
    v.__name__: v
    for v in [
        CrescendoJailbreaking,
        LinearJailbreaking,
        TreeJailbreaking,
        SequentialJailbreak,
        BadLikertJudge,
    ]
}

MULTI_TURN_ATTACK_NAMES = sorted(list(MULTI_TURN_ATTACK_MAP.keys()))
