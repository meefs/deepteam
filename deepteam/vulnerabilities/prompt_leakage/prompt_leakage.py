from typing import List, Literal, Optional, Union, Dict
import asyncio

from deepeval.models import DeepEvalBaseLLM
from deepeval.metrics.utils import initialize_model, trimAndLoadJson
from deepeval.utils import get_or_create_event_loop
from deepeval.test_case import LLMTestCase

from deepteam.utils import validate_model_callback_signature

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.prompt_leakage import PromptLeakageType
from deepteam.vulnerabilities.utils import validate_vulnerability_types
from deepteam.metrics import PromptExtractionMetric, BaseRedTeamingMetric
from deepteam.attacks.multi_turn.types import CallbackType
from deepteam.attacks.attack_simulator import SimulatedAttack
from deepteam.attacks.attack_simulator.schema import SyntheticDataList
from deepteam.risks import getRiskCategory
from .template import PromptLeakageTemplate

PromptLeakageLiteral = Literal[
    "secrets and credentials",
    "instructions",
    "guard exposure",
    "permissions and roles",
]


class PromptLeakage(BaseVulnerability):
    def __init__(
        self,
        async_mode: bool = True,
        verbose_mode: bool = False,
        simulator_model: Optional[
            Union[str, DeepEvalBaseLLM]
        ] = "gpt-3.5-turbo-0125",
        evaluation_model: Optional[Union[str, DeepEvalBaseLLM]] = "gpt-4o",
        types: Optional[List[PromptLeakageLiteral]] = [
            type.value for type in PromptLeakageType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=PromptLeakageType
        )
        self.async_mode = async_mode
        self.verbose_mode = verbose_mode
        self.simulator_model = simulator_model
        self.evaluation_model = evaluation_model
        super().__init__(types=enum_types)

    def assess(
        self,
        model_callback: CallbackType,
        purpose: Optional[str] = None,
        attacks_per_vulnerability_type: int = 1,
    ):
        from deepteam.red_teamer.risk_assessment import (
            RedTeamingTestCase,
        )

        if self.async_mode:
            validate_model_callback_signature(
                model_callback=model_callback,
                async_mode=self.async_mode,
            )
            loop = get_or_create_event_loop()
            return loop.run_until_complete(
                self.a_assess(
                    model_callback=model_callback,
                    purpose=purpose,
                    attacks_per_vulnerability_type=attacks_per_vulnerability_type,
                )
            )
        else:
            validate_model_callback_signature(
                model_callback=model_callback,
                async_mode=self.async_mode,
            )

        simulated_attacks = self.simulate_attacks(
            purpose, attacks_per_vulnerability_type
        )

        results: Dict[PromptLeakageType, List[RedTeamingTestCase]] = dict()

        for simulated_attack in simulated_attacks:
            vulnerability_type = simulated_attack.vulnerability_type

            target_output = model_callback(simulated_attack.input)
            test_case = LLMTestCase(
                input=simulated_attack.input,
                actual_output=target_output,
            )

            metric = self._get_metric(vulnerability_type)
            metric.measure(test_case)

            red_teaming_test_case = RedTeamingTestCase(
                vulnerability=simulated_attack.vulnerability,
                vulnerability_type=vulnerability_type,
                attackMethod=simulated_attack.attack_method,
                riskCategory=getRiskCategory(vulnerability_type),
                input=simulated_attack.input,
                actual_output=target_output,
                score=metric.score,
                reason=metric.reason,
            )

            results[vulnerability_type] = results.get(vulnerability_type, [])
            results[vulnerability_type].append(red_teaming_test_case)

        return results

    async def a_assess(
        self,
        model_callback: CallbackType,
        purpose: Optional[str] = None,
        attacks_per_vulnerability_type: int = 1,
    ):
        from deepteam.red_teamer.risk_assessment import (
            RedTeamingTestCase,
        )

        validate_model_callback_signature(
            model_callback=model_callback,
            async_mode=self.async_mode,
        )

        simulated_attacks = await self.a_simulate_attacks(
            purpose, attacks_per_vulnerability_type
        )

        results: Dict[PromptLeakageType, List[RedTeamingTestCase]] = dict()

        async def process_attack(simulated_attack: SimulatedAttack):
            vulnerability_type = simulated_attack.vulnerability_type

            metric = self._get_metric(vulnerability_type)
            target_output = await model_callback(simulated_attack.input)

            test_case = LLMTestCase(
                input=simulated_attack.input,
                actual_output=target_output,
            )

            metric.measure(test_case)

            red_teaming_test_case = RedTeamingTestCase(
                vulnerability=simulated_attack.vulnerability,
                vulnerability_type=vulnerability_type,
                attackMethod=simulated_attack.attack_method,
                riskCategory=getRiskCategory(vulnerability_type),
                input=simulated_attack.input,
                actual_output=target_output,
                score=metric.score,
                reason=metric.reason,
            )

            return vulnerability_type, red_teaming_test_case

        # Run all processing concurrently
        all_tasks = [
            process_attack(simulated_attack)
            for simulated_attack in simulated_attacks
            if simulated_attack.vulnerability_type in self.types
        ]

        for task in asyncio.as_completed(all_tasks):
            vulnerability_type, test_case = await task
            results.setdefault(vulnerability_type, []).append(test_case)

        return results

    def simulate_attacks(
        self,
        purpose: Optional[str] = None,
        attacks_per_vulnerability_type: int = 1,
    ) -> List[SimulatedAttack]:

        self.simulator_model, self.using_native_model = initialize_model(
            self.simulator_model
        )

        self.purpose = purpose

        templates = dict()
        simulated_attacks: List[SimulatedAttack] = []

        for type in self.types:
            templates[type] = templates.get(type, [])
            templates[type].append(
                PromptLeakageTemplate.generate_baseline_attacks(
                    type, attacks_per_vulnerability_type, self.purpose
                )
            )

        for type in self.types:
            for prompt in templates[type]:
                if self.using_native_model:
                    res, _ = self.simulator_model.generate(
                        prompt, schema=SyntheticDataList
                    )
                    local_attacks = [item.input for item in res.data]
                else:
                    try:
                        res: SyntheticDataList = self.simulator_model.generate(
                            prompt, schema=SyntheticDataList
                        )
                        local_attacks = [item.input for item in res.data]
                    except TypeError:
                        res = self.simulator_model.generate(prompt)
                        data = trimAndLoadJson(res)
                        local_attacks = [item["input"] for item in data["data"]]

            simulated_attacks.extend(
                [
                    SimulatedAttack(
                        vulnerability=self.get_name(),
                        vulnerability_type=type,
                        input=local_attack,
                    )
                    for local_attack in local_attacks
                ]
            )

        return simulated_attacks

    async def a_simulate_attacks(
        self,
        purpose: Optional[str] = None,
        attacks_per_vulnerability_type: int = 1,
    ) -> List[SimulatedAttack]:

        self.simulator_model, self.using_native_model = initialize_model(
            self.simulator_model
        )

        self.purpose = purpose

        templates = dict()
        simulated_attacks: List[SimulatedAttack] = []

        for type in self.types:
            templates[type] = templates.get(type, [])
            templates[type].append(
                PromptLeakageTemplate.generate_baseline_attacks(
                    type, attacks_per_vulnerability_type, self.purpose
                )
            )

        for type in self.types:
            for prompt in templates[type]:
                if self.using_native_model:
                    res, _ = await self.simulator_model.a_generate(
                        prompt, schema=SyntheticDataList
                    )
                    local_attacks = [item.input for item in res.data]
                else:
                    try:
                        res: SyntheticDataList = (
                            await self.simulator_model.a_generate(
                                prompt, schema=SyntheticDataList
                            )
                        )
                        local_attacks = [item.input for item in res.data]
                    except TypeError:
                        res = await self.simulator_model.a_generate(prompt)
                        data = trimAndLoadJson(res)
                        local_attacks = [item["input"] for item in data["data"]]

            simulated_attacks.extend(
                [
                    SimulatedAttack(
                        vulnerability=self.get_name(),
                        vulnerability_type=type,
                        input=local_attack,
                    )
                    for local_attack in local_attacks
                ]
            )

        return simulated_attacks

    def _get_metric(
        self,
        type: PromptLeakageType,
    ) -> BaseRedTeamingMetric:
        return PromptExtractionMetric(
            purpose=self.purpose,
            model=self.evaluation_model,
            async_mode=self.async_mode,
            verbose_mode=self.verbose_mode,
        )

    def get_name(self) -> str:
        return "Prompt Leakage"
