from pydantic import BaseModel
from typing import Optional, List
from deepteam.metrics import BaseRedTeamingMetric
from abc import ABC

class Attack(BaseModel):
    attack: str
    category: List[str]


class BaseRedTeamingDataset(ABC):
    attacks: Optional[List[Attack]] = None
    num_attacks: Optional[int] = None

    def __init__(self):
        """
        Initialize a RedTeamingDataset.
        """
        pass

    def get_name(self) -> str:
        """
        Get the name of Dataset.
        :return: A string representing the name of Dataset
        """
        return self.__class__.__name__

    def assess(self):
        pass

    async def a_assess(self):
        pass

    def simulate_attacks(self):
        pass

    async def a_simulate_attacks(self):
        pass

    def _get_metric(self) -> BaseRedTeamingMetric:
        """
        Get the corresponding metric of the dataset.
        :return: The BaseRedTeamingMetric corresponding to this dataset
        """
        pass

    def get_name(self) -> str:
        return self.__class__.__name__

    def __repr__(self):
        """
        Represent the class by listing the Enum types.
        :return: String representation of the Vulnerability class.
        """
        return f"{self.__class__.__name__} (types={self.types})"

