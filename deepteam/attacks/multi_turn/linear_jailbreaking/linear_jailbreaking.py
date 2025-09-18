from tqdm import tqdm
from typing import Optional, Union, List


from deepeval.models import DeepEvalBaseLLM
from deepeval.metrics.utils import initialize_model
from deepeval.test_case import Turn

from deepteam.attacks import BaseAttack
from deepteam.attacks.multi_turn.linear_jailbreaking.schema import (
    Improvement,
    Feedback,
)
from deepteam.attacks.multi_turn.linear_jailbreaking.template import (
    JailBreakingTemplate,
)
from deepteam.attacks.attack_simulator.utils import (
    generate,
    a_generate,
)
from deepteam.attacks.multi_turn.types import CallbackType
from deepteam.attacks.multi_turn.utils import update_turn_history
from deepteam.attacks.multi_turn.base_schema import NonRefusal
from deepteam.attacks.multi_turn.base_template import BaseMultiTurnTemplate
from deepteam.errors import ModelRefusalError


class LinearJailbreaking(BaseAttack):
    def __init__(
        self,
        weight: int = 1,
        turns: int = 5,
    ):
        self.weight = weight
        self.turns = turns

    def enhance(
        self,
        attack: str,
        model_callback: CallbackType,
        simulator_model: Optional[Union[DeepEvalBaseLLM, str]] = None,
        turn_history: Optional[List[Turn]] = None,
    ) -> str:
        self.simulator_model, _ = initialize_model(simulator_model)

        pbar = tqdm(
            total=self.turns, desc="...... ⛓️  Linear Jailbreaking", leave=False
        )

        turns = turn_history or []

        current_attack = attack
        for i in range(self.turns):
            target_response = model_callback(current_attack, turns)
            turns = update_turn_history(turns, current_attack, target_response)

            judge_prompt = JailBreakingTemplate.linear_judge(
                attack, current_attack, target_response
            )
            feedback: Feedback = generate(
                judge_prompt, Feedback, self.simulator_model
            )

            if feedback.jailbroken:
                pbar.n = pbar.total
                pbar.close()
                break

            improvement_prompt = JailBreakingTemplate.improvement_prompt(
                turns, feedback.suggestion
            )
            improvement: Improvement = generate(
                improvement_prompt, Improvement, self.simulator_model
            )
            next_attack = improvement.new_prompt

            non_refusal_prompt = BaseMultiTurnTemplate.non_refusal(
                attack, next_attack
            )
            non_refusal_res: NonRefusal = generate(
                non_refusal_prompt, NonRefusal, self.simulator_model
            )
            classification = non_refusal_res.classification
            if classification == "Refusal":
                pbar.n = pbar.total
                pbar.close()
                raise ModelRefusalError(entity=self.get_name())
            else:
                current_attack = next_attack
                if i == self.turns - 1:
                    turns.append(Turn(role="user", content=current_attack))

            pbar.update(1)

        pbar.close()
        return turns

    async def a_enhance(
        self,
        attack: str,
        model_callback: CallbackType,
        simulator_model: Optional[Union[DeepEvalBaseLLM, str]] = None,
        turn_history: Optional[List[Turn]] = None,
    ) -> str:
        self.simulator_model, _ = initialize_model(simulator_model)

        pbar = tqdm(
            total=self.turns, desc="...... ⛓️  Linear Jailbreaking", leave=False
        )

        # Initialize conversation history for tracking attempts
        current_attack = attack
        turns = turn_history or []

        for i in range(self.turns):
            target_response = await model_callback(current_attack, turns)
            turns = update_turn_history(turns, current_attack, target_response)

            judge_prompt = JailBreakingTemplate.linear_judge(
                attack, current_attack, target_response
            )
            feedback: Feedback = await a_generate(
                judge_prompt, Feedback, self.simulator_model
            )

            if feedback.jailbroken:
                pbar.n = pbar.total
                pbar.close()
                break

            improvement_prompt = JailBreakingTemplate.improvement_prompt(
                turns, feedback.suggestion
            )
            improvement: Improvement = await a_generate(
                improvement_prompt, Improvement, self.simulator_model
            )
            next_attack = improvement.new_prompt

            non_refusal_prompt = BaseMultiTurnTemplate.non_refusal(
                attack, next_attack
            )
            non_refusal_res: NonRefusal = await a_generate(
                non_refusal_prompt, NonRefusal, self.simulator_model
            )
            classification = non_refusal_res.classification
            if classification == "Refusal":
                pbar.n = pbar.total
                pbar.close()
                raise ModelRefusalError(entity=self.get_name())
            else:
                current_attack = next_attack
                if i == self.turns - 1:
                    turns.append(Turn(role="user", content=current_attack))

            pbar.update(1)

        pbar.close()

        return turns

    def get_name(self) -> str:
        return "Linear Jailbreaking"
