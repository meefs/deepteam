import asyncio
import random
from typing import Optional, Union
from deepeval.models import DeepEvalBaseLLM
from deepeval.utils import get_or_create_event_loop
from enum import Enum

from deepteam.dataset import (
    BaseRedTeamingDataset, 
    Attack
)
from deepteam.vulnerabilities import BaseVulnerability
from deepteam.test_case import RTTestCase
from deepteam.metrics import DatasetMetric

DATASET="nvidia/Aegis-AI-Content-Safety-Dataset-1.0"

class AegisDataset(BaseVulnerability):
    def __init__(
        self,
        num_attacks: int = 15,
        async_mode: bool = True,
        verbose_mode: bool = False,
        evaluation_model: Optional[Union[str, DeepEvalBaseLLM]] = "gpt-4o",
    ):
        self.num_attacks = num_attacks
        self.async_mode = async_mode
        self.verbose_mode = verbose_mode
        self.evaluation_model = evaluation_model
        self.types = []


    def simulate_attacks(self, purpose=None, attacks_per_vulnerability_type: int = 1,):
        from datasets import load_dataset

        dataset = load_dataset(DATASET, split="train")
        attacks = [row for row in dataset if row.get("text_type") == "user_message" and row.get("labels_0") != "Safe"]

        if len(attacks) < self.num_attacks:
            raise ValueError(f"Requested {self.num_attacks} attacks but only found {len(attacks)} qualifying rows.")

        sampled = random.sample(attacks, k=self.num_attacks)
        self.attacks = [Attack(attack=row["text"], category=[row["labels_0"]]) for row in sampled]
        test_cases = []
        for attack in self.attacks:
            vulnerability = ",".join(attack.category)
            test_case = RTTestCase(
                input=attack.attack,
                vulnerability=vulnerability,
            )
            test_cases.append(test_case)
        return test_cases


    async def a_simulate_attacks(self, purpose=None, attacks_per_vulnerability_type: int = 1,):
        from datasets import load_dataset

        loop = get_or_create_event_loop()

        def _collect():
            dataset = load_dataset(DATASET, split="train")
            attacks = [row for row in dataset if row.get("text_type") == "user_message" and row.get("labels_0") != "Safe"]
            if len(attacks) < self.num_attacks:
                raise ValueError(f"Requested {self.num_attacks} attacks but only found {len(attacks)} qualifying rows.")
            sampled = random.sample(attacks, k=self.num_attacks)
            return [Attack(attack=row["text"], category=[row["labels_0"]]) for row in sampled]

        self.attacks = await loop.run_in_executor(None, _collect)
        return self.attacks
    

    def _get_metric(self, type=None):
        return DatasetMetric(
            model=self.evaluation_model,
            async_mode=self.async_mode,
            verbose_mode=self.verbose_mode,
        )

    def get_name(self):
        return "Aegis"