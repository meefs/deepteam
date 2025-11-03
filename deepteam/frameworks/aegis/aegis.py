import asyncio
import random
from typing import Optional, Union
from deepeval.models import DeepEvalBaseLLM
from deepeval.utils import get_or_create_event_loop

from deepteam.frameworks import AISafetyFramework
from deepteam.frameworks.aegis.types import AegisType
from deepteam.test_case import RTTestCase

class Aegis(AISafetyFramework):
    _DATASET = "nvidia/Aegis-AI-Content-Safety-Dataset-1.0"

    def __init__(
        self, 
        num_attacks: int = 15,
        async_mode: bool = True,
        verbose_mode: bool = False,
        evaluation_model: Optional[Union[str, DeepEvalBaseLLM]] = "gpt-4o",
    ):
        self.name = "Aegis"
        self.description = "Nemotron Content Safety Dataset V1, formerly known as Aegis AI Content Safety Dataset, is an open-source content safety dataset (CC-BY-4.0), which adheres to Nvidia's content safety taxonomy, covering 13 critical risk categories"
        self.num_attacks = num_attacks
        self.async_mode = async_mode
        self.verbose_mode = verbose_mode
        self.evaluation_model = evaluation_model
        self._is_dataset = True
        
    def simulate_attacks(self):
        from datasets import load_dataset

        dataset = load_dataset(self._DATASET, split="train")
        attacks = [row for row in dataset if row.get("text_type") == "user_message" and row.get("labels_0") != "Safe"]

        if len(attacks) < self.num_attacks:
            raise ValueError(f"Please set your 'num_attacks' to less than or equal to {len(attacks)}.")

        sampled = random.sample(attacks, k=self.num_attacks)
        test_cases = [
            RTTestCase(
                input=attack["text"],
                vulnerability=attack["labels_0"],
                vulnerability_type=AegisType.AEGIS
            )
            for attack in sampled
        ]
        return test_cases
    

    async def a_simulate_attacks(self):
        from datasets import load_dataset

        dataset = await asyncio.to_thread(load_dataset, self._DATASET, split="train")
        
        attacks = [
            row for row in dataset
            if row.get("text_type") == "user_message" and row.get("labels_0") != "Safe"
        ]

        if len(attacks) < self.num_attacks:
            raise ValueError(f"Please set your 'num_attacks' to less than or equal to {len(attacks)}.")

        sampled = random.sample(attacks, k=self.num_attacks)

        test_cases = [
            RTTestCase(
                input=attack["text"],
                vulnerability=attack["labels_0"],
                vulnerability_type=AegisType.AEGIS
            )
            for attack in sampled
        ]

        return test_cases
    
    def get_name(self):
        return "Aegis"
