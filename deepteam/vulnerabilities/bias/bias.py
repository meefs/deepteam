from typing import List, Literal, Optional, Union, Dict

from deepeval.models import DeepEvalBaseLLM
from deepeval.metrics.utils import initialize_model
from deepeval.test_case import LLMTestCase

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.bias import BiasType
from deepteam.vulnerabilities.utils import validate_vulnerability_types
from deepteam.metrics import BiasMetric
from deepteam.attacks import BaseAttack
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
        super().__init__(types=enum_types)

    def assess(
        self,
        model_callback,
        attacks: Optional[List[BaseAttack]] = None,
        simulator_model: Optional[Union[str, DeepEvalBaseLLM]] = "gpt-3.5-turbo-0125",
        evaluation_model: Optional[Union[str, DeepEvalBaseLLM]] = "gpt-4o",
        attacks_per_vulnerability_type: int = 1,
        ignore_errors: bool = False,
        reuse_simulated_attacks: bool = False,
        metadata: Optional[dict] = None,
        max_concurrent: int = 10,
    ):
        from deepteam.red_teamer.risk_assessment import (
            construct_risk_assessment_overview,
            RedTeamingTestCase,
            RiskAssessment,
        )
        
        self.simulator_model, _ = initialize_model(simulator_model)
        self.evaluation_model, _ = initialize_model(evaluation_model)
        self.attack_simulator = AttackSimulator(
            simulator_model=self.simulator_model,
            purpose=self.purpose,
            max_concurrent=max_concurrent,
        )

        # Getting the simulated attacks
        if (
            reuse_simulated_attacks
            and self.simulated_attacks is not None
            and len(self.simulated_attacks) > 0
        ):
            simulated_attacks: List[SimulatedAttack] = (
                self.simulated_attacks
            )
        else:
            self.attack_simulator.model_callback = model_callback
            simulated_attacks: List[SimulatedAttack] = (
                self.attack_simulator.simulate(
                    attacks_per_vulnerability_type=attacks_per_vulnerability_type,
                    vulnerabilities=[self],
                    attacks=attacks,
                    ignore_errors=ignore_errors,
                    metadata=metadata,
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
            for simulated_attack in simulated_attacks:

                if simulated_attack.vulnerability_type != vulnerability_type:
                    continue

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

                # this will only go through if ignore_errors == True
                if simulated_attack.error:
                    red_teaming_test_case.error = simulated_attack.error
                    red_teaming_test_cases.append(red_teaming_test_case)
                    continue

                try:
                    target_output = model_callback(
                        simulated_attack.input
                    )
                    red_teaming_test_case.actual_output = target_output
                except Exception:
                    if ignore_errors:
                        red_teaming_test_case.error = (
                            "Error generating output from target LLM"
                        )
                        red_teaming_test_cases.append(
                            red_teaming_test_case
                        )
                        continue
                    else:
                        raise
                
                test_case = LLMTestCase(
                    input=simulated_attack.input,
                    actual_output=target_output,
                )

                try:
                    metric.measure(test_case)
                    red_teaming_test_case.score = metric.score
                    red_teaming_test_case.reason = metric.reason
                except Exception:
                    if ignore_errors:
                        red_teaming_test_case.error = f"Error evaluating target LLM output for the '{vulnerability_type.value}' vulnerability"
                        red_teaming_test_cases.append(
                            red_teaming_test_case
                        )
                        continue
                    else:
                        raise

                red_teaming_test_cases.append(red_teaming_test_case)
            
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
