from pydantic import BaseModel
from tqdm import tqdm  # Sync version
from tqdm.asyncio import tqdm as async_tqdm_bar  # Async version

from deepeval.models import DeepEvalBaseLLM

from deepteam.attacks import BaseAttack
from deepteam.attacks.single_turn.roleplay_replay.template import (
    RoleplayReplayTemplate,
)
from deepteam.attacks.single_turn.roleplay_replay.schema import (
    EnhancedAttack,
    ComplianceData,
    IsRoleplayReplay,
)
from deepteam.attacks.attack_simulator.utils import (
    generate_schema,
    a_generate_schema,
)


class RoleplayReplay(BaseAttack):

    def __init__(self, weight: int = 1, max_retries: int = 3, persona: str = "1600s Shakespearean scholar", role: str = "learned gentleman of natural philosophy"):
        self.weight = weight
        self.max_retries = max_retries
        self.persona = persona
        self.role = role

    def enhance(self, attack: str, simulator_model: DeepEvalBaseLLM) -> str:
        self.simulator_model = simulator_model
        prompt = RoleplayReplayTemplate.enhance(attack, self.persona, self.role)

        # Progress bar for retries (total count is triple the retries: 1 for generation, 1 for compliance check, 1 for roleplay check)
        with tqdm(
            total=self.max_retries * 3,
            desc="...... 🎭 Roleplay Replay",
            unit="step",
            leave=False,
        ) as pbar:

            for _ in range(self.max_retries):
                # Generate the enhanced attack
                res: EnhancedAttack = self._generate_schema(
                    prompt, EnhancedAttack
                )
                enhanced_attack = res.input
                pbar.update(1)  # Update the progress bar for generation

                # Check for compliance using a compliance template
                compliance_prompt = RoleplayReplayTemplate.non_compliant(
                    res.model_dump()
                )
                compliance_res: ComplianceData = self._generate_schema(
                    compliance_prompt, ComplianceData
                )
                pbar.update(1)  # Update the progress bar for compliance

                # Check if rewritten prompt is a roleplay replay attack
                is_roleplay_replay_prompt = (
                    RoleplayReplayTemplate.is_roleplay_replay(res.model_dump())
                )
                is_roleplay_replay_res: IsRoleplayReplay = self._generate_schema(
                    is_roleplay_replay_prompt, IsRoleplayReplay
                )
                pbar.update(1)  # Update the progress bar

                if (
                    not compliance_res.non_compliant
                    and is_roleplay_replay_res.is_roleplay_replay
                ):
                    # If it's compliant and is a roleplay replay attack, return the enhanced prompt
                    return enhanced_attack

        # If all retries fail, return the original attack
        return attack

    async def a_enhance(
        self, attack: str, simulator_model: DeepEvalBaseLLM
    ) -> str:
        self.simulator_model = simulator_model
        prompt = RoleplayReplayTemplate.enhance(attack, self.persona, self.role)

        # Async progress bar for retries (triple the count to cover generation, compliance check, and roleplay check)
        pbar = async_tqdm_bar(
            total=self.max_retries * 3,
            desc="...... 🎭 Roleplay Replay",
            unit="step",
            leave=False,
        )

        try:
            for _ in range(self.max_retries):
                # Generate the enhanced attack asynchronously
                res: EnhancedAttack = await self._a_generate_schema(
                    prompt, EnhancedAttack
                )
                enhanced_attack = res.input
                pbar.update(1)  # Update the progress bar for generation

                # Check for compliance using a compliance template
                compliance_prompt = RoleplayReplayTemplate.non_compliant(
                    res.model_dump()
                )
                compliance_res: ComplianceData = await self._a_generate_schema(
                    compliance_prompt, ComplianceData
                )
                pbar.update(1)  # Update the progress bar for compliance

                # Check if rewritten prompt is a roleplay replay attack
                is_roleplay_replay_prompt = (
                    RoleplayReplayTemplate.is_roleplay_replay(res.model_dump())
                )
                is_roleplay_replay_res: IsRoleplayReplay = (
                    await self._a_generate_schema(
                        is_roleplay_replay_prompt, IsRoleplayReplay
                    )
                )
                pbar.update(1)  # Update the progress bar

                if (
                    not compliance_res.non_compliant
                    and is_roleplay_replay_res.is_roleplay_replay
                ):
                    # If it's compliant and is a roleplay replay attack, return the enhanced prompt
                    return enhanced_attack

        finally:
            # Close the progress bar after the loop
            pbar.close()

        # If all retries fail, return the original attack
        return attack

    ##################################################
    ### Helper Methods ################################
    ##################################################

    def _generate_schema(self, prompt: str, schema: BaseModel):
        return generate_schema(prompt, schema, self.simulator_model)

    async def _a_generate_schema(self, prompt: str, schema: BaseModel):
        return await a_generate_schema(prompt, schema, self.simulator_model)

    def get_name(self) -> str:
        return "Roleplay Replay" 