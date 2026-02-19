from __future__ import annotations

from enum import Enum
from typing import Dict, Union


class LLMRiskCategories(Enum):
    RESPONSIBLE_AI = "Responsible AI"
    ILLEGAL = "Illegal"
    BRAND_IMAGE = "Brand Image"
    DATA_PRIVACY = "Data Privacy"
    UNAUTHORIZED_ACCESS = "Unauthorized Access"


def getRiskCategory(
    vulnerability_type: Union[Enum],
) -> LLMRiskCategories:
    # Import lazily to avoid circular import with vulnerabilities.types
    # (types.py -> exploit_tool_agent -> risks.py -> types.py)
    from deepteam.vulnerabilities.bias import BiasType
    from deepteam.vulnerabilities.toxicity import ToxicityType
    from deepteam.vulnerabilities.illegal_activity import IllegalActivityType
    from deepteam.vulnerabilities.graphic_content import GraphicContentType
    from deepteam.vulnerabilities.personal_safety import PersonalSafetyType
    from deepteam.vulnerabilities.misinformation import MisinformationType
    from deepteam.vulnerabilities.excessive_agency import ExcessiveAgencyType
    from deepteam.vulnerabilities.robustness import RobustnessType
    from deepteam.vulnerabilities.intellectual_property import IntellectualPropertyType
    from deepteam.vulnerabilities.competition import CompetitionType
    from deepteam.vulnerabilities.prompt_leakage import PromptLeakageType
    from deepteam.vulnerabilities.pii_leakage import PIILeakageType
    from deepteam.vulnerabilities.bfla.types import BFLAType
    from deepteam.vulnerabilities.bola.types import BOLAType
    from deepteam.vulnerabilities.rbac import RBACType
    from deepteam.vulnerabilities.debug_access.types import DebugAccessType
    from deepteam.vulnerabilities.shell_injection.types import ShellInjectionType
    from deepteam.vulnerabilities.sql_injection.types import SQLInjectionType
    from deepteam.vulnerabilities.ssrf.types import SSRFType

    risk_category_map: Dict[Enum, LLMRiskCategories] = {
        # Responsible AI
        **{bias: LLMRiskCategories.RESPONSIBLE_AI for bias in BiasType},
        **{
            toxicity: LLMRiskCategories.RESPONSIBLE_AI
            for toxicity in ToxicityType
        },
        # Illegal
        **{
            illegal: LLMRiskCategories.ILLEGAL
            for illegal in IllegalActivityType
        },
        **{
            graphic: LLMRiskCategories.ILLEGAL for graphic in GraphicContentType
        },
        **{safety: LLMRiskCategories.ILLEGAL for safety in PersonalSafetyType},
        # Brand Image
        **{
            misinfo: LLMRiskCategories.BRAND_IMAGE
            for misinfo in MisinformationType
        },
        **{
            agency: LLMRiskCategories.BRAND_IMAGE
            for agency in ExcessiveAgencyType
        },
        **{robust: LLMRiskCategories.BRAND_IMAGE for robust in RobustnessType},
        **{
            ip: LLMRiskCategories.BRAND_IMAGE for ip in IntellectualPropertyType
        },
        **{comp: LLMRiskCategories.BRAND_IMAGE for comp in CompetitionType},
        # Data Privacy
        **{
            prompt: LLMRiskCategories.DATA_PRIVACY
            for prompt in PromptLeakageType
        },
        **{pii: LLMRiskCategories.DATA_PRIVACY for pii in PIILeakageType},
        # Unauthorized Access
        **{
            unauth: LLMRiskCategories.UNAUTHORIZED_ACCESS for unauth in BFLAType
        },
        **{
            unauth: LLMRiskCategories.UNAUTHORIZED_ACCESS for unauth in BOLAType
        },
        **{
            unauth: LLMRiskCategories.UNAUTHORIZED_ACCESS for unauth in RBACType
        },
        **{
            unauth: LLMRiskCategories.UNAUTHORIZED_ACCESS
            for unauth in DebugAccessType
        },
        **{
            unauth: LLMRiskCategories.UNAUTHORIZED_ACCESS
            for unauth in ShellInjectionType
        },
        **{
            unauth: LLMRiskCategories.UNAUTHORIZED_ACCESS
            for unauth in SQLInjectionType
        },
        **{
            unauth: LLMRiskCategories.UNAUTHORIZED_ACCESS for unauth in SSRFType
        },
    }

    return risk_category_map.get(
        vulnerability_type, "Others"
    )  # Returns None if not found
