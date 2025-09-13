from typing import List, Literal, Optional, Union, Dict
import inspect
import asyncio

from deepeval.models import DeepEvalBaseLLM
from deepeval.metrics.utils import initialize_model
from deepeval.utils import get_or_create_event_loop
from deepeval.test_case import LLMTestCase

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.bias import BiasType
from deepteam.vulnerabilities.utils import validate_vulnerability_types
from deepteam.metrics import BiasMetric
from deepteam.attacks import BaseAttack
from deepteam.attacks.multi_turn.types import CallbackType
from deepteam.attacks.attack_simulator import AttackSimulator, SimulatedAttack
from deepteam.risks import getRiskCategory

BiasLiteralType = Literal["religion", "politics", "gender", "race"]

class Bias(BaseVulnerability):
    def __init__(
        self,
        purpose: str,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
        simulator_model: Optional[Union[str, DeepEvalBaseLLM]] = "gpt-3.5-turbo-0125",
        evaluation_model: Optional[Union[str, DeepEvalBaseLLM]] = "gpt-4o",
        types: Optional[List[BiasLiteralType]] = [
            type.value for type in BiasType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=BiasType
        )
        self.purpose = purpose
        self.model = model
        self.async_mode = async_mode
        self.verbose_mode = verbose_mode
        self.simulator_model = simulator_model
        self.evaluation_model = evaluation_model
        super().__init__(types=enum_types)

    def assess(
        self,
        model_callback: CallbackType,
        attack: BaseAttack,
        attacks_per_vulnerability_type: int = 1,
        max_concurrent: int = 10,
    ):
        from deepteam.red_teamer.risk_assessment import (
            construct_risk_assessment_overview,
            RedTeamingTestCase,
            RiskAssessment,
        )

        if self.async_mode:
            assert inspect.iscoroutinefunction(
                model_callback
            ), "`model_callback` needs to be async. `async_mode` has been set to True."
            loop = get_or_create_event_loop()
            return loop.run_until_complete(
                self.a_assess(
                    model_callback=model_callback,
                    attack=attack,
                    attacks_per_vulnerability_type=attacks_per_vulnerability_type,
                )
            )
        else:
            assert not inspect.iscoroutinefunction(
                model_callback
            ), "`model_callback` needs to be sync. `async_mode` has been set to False."

        self.simulator_model, _ = initialize_model(self.simulator_model)
        self.evaluation_model, _ = initialize_model(self.evaluation_model)
        self.attack_simulator = AttackSimulator(
            simulator_model=self.simulator_model,
            purpose=self.purpose,
            max_concurrent=max_concurrent,
        )

        self.attack_simulator.model_callback = model_callback
        simulated_attacks: List[SimulatedAttack] = (
            self.attack_simulator.simulate(
                attacks_per_vulnerability_type=attacks_per_vulnerability_type,
                vulnerabilities=[self],
                attacks=[attack],
                ignore_errors=False,
            )
        )
        # Create a mapping of vulnerabilities to attacks
        vulnerability_type_to_attacks_map: Dict[
            BiasType, List[SimulatedAttack]
        ] = {}
        for simulated_attack in simulated_attacks:
            if (
                simulated_attack.vulnerability_type
                not in vulnerability_type_to_attacks_map
            ):
                vulnerability_type_to_attacks_map[
                    simulated_attack.vulnerability_type
                ] = [simulated_attack]
            else:
                vulnerability_type_to_attacks_map[
                    simulated_attack.vulnerability_type
                ].append(simulated_attack)
        
        red_teaming_test_cases: List[RedTeamingTestCase] = []

        for vulnerability_type in self.types:
            for simulated_attack in vulnerability_type_to_attacks_map.get(vulnerability_type, []):

                metric = self._get_metric(
                    vulnerability_type
                )
                red_teaming_test_case = RedTeamingTestCase(
                    vulnerability=simulated_attack.vulnerability,
                    vulnerability_type=vulnerability_type,
                    attackMethod=simulated_attack.attack_method,
                    riskCategory=getRiskCategory(vulnerability_type),
                    input=simulated_attack.input,
                    metadata=simulated_attack.metadata,
                )

                target_output = model_callback(
                    simulated_attack.input
                )
                red_teaming_test_case.actual_output = target_output
                
                test_case = LLMTestCase(
                    input=simulated_attack.input,
                    actual_output=target_output,
                )

                metric.measure(test_case)
                red_teaming_test_case.score = metric.score
                red_teaming_test_case.reason = metric.reason

                red_teaming_test_cases.append(red_teaming_test_case)
            
        self.risk_assessment = RiskAssessment(
            overview=construct_risk_assessment_overview(
                red_teaming_test_cases=red_teaming_test_cases
            ),
            test_cases=red_teaming_test_cases,
        )

        return self.risk_assessment
    
    async def a_assess(
        self,
        model_callback: CallbackType,
        attack: BaseAttack,
        attacks_per_vulnerability_type: int = 1,
        max_concurrent: int = 10,
    ):
        from deepteam.red_teamer.risk_assessment import (
            construct_risk_assessment_overview,
            RedTeamingTestCase,
            RiskAssessment,
        )

        self.simulator_model, _ = initialize_model(self.simulator_model)
        self.evaluation_model, _ = initialize_model(self.evaluation_model)
        self.attack_simulator = AttackSimulator(
            simulator_model=self.simulator_model,
            purpose=self.purpose,
            max_concurrent=max_concurrent,
        )

        self.attack_simulator.model_callback = model_callback
        simulated_attacks: List[SimulatedAttack] = (
            await self.attack_simulator.a_simulate(
                attacks_per_vulnerability_type=attacks_per_vulnerability_type,
                vulnerabilities=[self],
                attacks=[attack],
                ignore_errors=False,
            )
        )

        # Map vulnerabilities to attacks
        vulnerability_type_to_attacks_map: Dict[BiasType, List[SimulatedAttack]] = {}
        for simulated_attack in simulated_attacks:
            if simulated_attack.vulnerability_type not in vulnerability_type_to_attacks_map:
                vulnerability_type_to_attacks_map[simulated_attack.vulnerability_type] = [simulated_attack]
            else:
                vulnerability_type_to_attacks_map[simulated_attack.vulnerability_type].append(simulated_attack)

        semaphore = asyncio.Semaphore(max_concurrent)
        tasks = []

        for vulnerability_type in self.types:
            for simulated_attack in vulnerability_type_to_attacks_map.get(vulnerability_type, []):

                metric = self._get_metric(vulnerability_type)

                red_teaming_test_case = RedTeamingTestCase(
                    vulnerability=simulated_attack.vulnerability,
                    vulnerability_type=vulnerability_type,
                    attackMethod=simulated_attack.attack_method,
                    riskCategory=getRiskCategory(vulnerability_type),
                    input=simulated_attack.input,
                    metadata=simulated_attack.metadata,
                )

                # If there's a simulation error, record and skip evaluation
                if simulated_attack.error:
                    red_teaming_test_case.error = simulated_attack.error
                    tasks.append(asyncio.sleep(0, result=red_teaming_test_case))  # dummy async task
                    continue

                # Create a coroutine task for this test case
                async def run_case(
                    simulated_attack=simulated_attack,
                    red_teaming_test_case=red_teaming_test_case,
                    metric=metric,
                ):
                    async with semaphore:
                        target_output = await model_callback(simulated_attack.input)
                    red_teaming_test_case.actual_output = target_output

                    test_case = LLMTestCase(
                        input=simulated_attack.input,
                        actual_output=target_output,
                    )

                    await metric.a_measure(test_case)
                    red_teaming_test_case.score = metric.score
                    red_teaming_test_case.reason = metric.reason

                    return red_teaming_test_case

                tasks.append(run_case())

        red_teaming_test_cases_all = await asyncio.gather(*tasks)
        red_teaming_test_cases = [tc for tc in red_teaming_test_cases_all if tc is not None]

        self.risk_assessment = RiskAssessment(
            overview=construct_risk_assessment_overview(
                red_teaming_test_cases=red_teaming_test_cases
            ),
            test_cases=red_teaming_test_cases,
        )

        return self.risk_assessment

    def _get_metric(
            self, 
            type: BiasType,
        ):
        return BiasMetric(
            purpose=self.purpose,
            model=self.model,
            async_mode=self.async_mode,
            verbose_mode=self.verbose_mode
        )

    def get_name(self) -> str:
        return "Bias"
