from typing import Literal, Optional
from deepteam.attacks.single_turn import BaseSingleTurnAttack
from deepteam.attacks.base_attack import Exploitability
from deepteam.attacks.single_turn.context_flooding.template import DEFAULT_PREFIXES

ContextFloodingPrefixType = Literal[
    "enterprise", "logs", "transcript"
]

class ContextFlooding(BaseSingleTurnAttack):
    name = "ContextFlooding"
    exploitability = Exploitability.MEDIUM
    description = "A single-turn attack that floods the LLM's context with long pre-defined prefixes to hit a target token size."

    def __init__(
        self, 
        weight: int = 1,
        target_tokens: int = 4000,
        prefix: Optional[str] = None,
        prefix_type: Optional[ContextFloodingPrefixType] = "enterprise",
    ):
        self.weight = weight
        self.target_tokens = target_tokens
        if prefix is not None:
            if not prefix.strip():
                raise ValueError("Prefix cannot be empty.")
            self.prefix = prefix
            self.prefix_type = None
        else:
            if not prefix_type or prefix_type not in DEFAULT_PREFIXES:
                raise ValueError(
                    f"Invalid prefix_type '{prefix_type}'. Please enter a valid prefix_type: {list(DEFAULT_PREFIXES.keys())}"
                )
            self.prefix = DEFAULT_PREFIXES[prefix_type]
            self.prefix_type = prefix_type

    def _estimate_tokens(self, text: str) -> int:
        # Approximate: 1 token ≈ 4 characters
        return max(1, len(text) // 4)
        
    def _generate_prefix(self) -> str:
        base = self.prefix.strip()
        expanded = base

        while self._estimate_tokens(expanded) < self.target_tokens:
            expanded += "\n\n" + base

        target_chars = self.target_tokens * 4
        trimmed = expanded[:target_chars]

        # Trim to last whitespace to avoid mid-word cut
        if " " in trimmed:
            trimmed = trimmed.rsplit(" ", 1)[0]

        return trimmed


    def enhance(self, attack: str) -> str:
        prefix = self._generate_prefix()
        final_attack = f"{prefix}\n\n{attack}"

        return final_attack.strip()
    
    async def a_enhance(self, attack):
        return self.enhance(attack)

    def get_name(self) -> str:
        return self.name
