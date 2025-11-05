from deepteam.attacks.base_attack import BaseAttack
from deepteam.vulnerabilities.base_vulnerability import BaseVulnerability
from deepteam.attacks.multi_turn.types import CallbackType
from typing import Optional, List, Dict
from deepteam.test_case import RTTurn
from deepteam.vulnerabilities.types import VulnerabilityType


class BaseMultiTurnAttack(BaseAttack):
    def progress(
        self,
        vulnerability: BaseVulnerability,
        model_callback: CallbackType,
        turns: Optional[List[RTTurn]] = None,
        **kwargs,
    ) -> Dict[VulnerabilityType, List[RTTurn]]:
        pass

    async def a_progress(
        self,
        vulnerability: BaseVulnerability,
        model_callback: CallbackType,
        turns: Optional[List[RTTurn]] = None,
        **kwargs,
    ) -> Dict[VulnerabilityType, List[RTTurn]]:
        pass
