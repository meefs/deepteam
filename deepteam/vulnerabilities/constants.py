from typing import Dict, List
from .base_vulnerability import BaseVulnerability
from .bias.bias import Bias
from .toxicity.toxicity import Toxicity
from .misinformation.misinformation import Misinformation
from .illegal_activity.illegal_activity import IllegalActivity
from .prompt_leakage.prompt_leakage import PromptLeakage
from .pii_leakage.pii_leakage import PIILeakage
from .bfla.bfla import BFLA
from .bola.bola import BOLA
from .rbac.rbac import RBAC
from .debug_access.debug_access import DebugAccess
from .shell_injection.shell_injection import ShellInjection
from .sql_injection.sql_injection import SQLInjection
from .ssrf.ssrf import SSRF
from .intellectual_property.intellectual_property import IntellectualProperty
from .competition.competition import Competition
from .graphic_content.graphic_content import GraphicContent
from .personal_safety.personal_safety import PersonalSafety
from .goal_theft.goal_theft import GoalTheft
from .recursive_hijacking.recursive_hijacking import RecursiveHijacking
from .robustness.robustness import Robustness
from .excessive_agency.excessive_agency import ExcessiveAgency


# Import types
from .bias.types import BiasType
from .toxicity.types import ToxicityType
from .misinformation.types import MisinformationType
from .illegal_activity.types import IllegalActivityType
from .prompt_leakage.types import PromptLeakageType
from .pii_leakage.types import PIILeakageType
from .bfla.types import BFLAType
from .bola.types import BOLAType
from .rbac.types import RBACType
from .debug_access.types import DebugAccessType
from .shell_injection.types import ShellInjectionType
from .sql_injection.types import SQLInjectionType
from .ssrf.types import SSRFType
from .intellectual_property.types import IntellectualPropertyType
from .competition.types import CompetitionType
from .graphic_content.types import GraphicContentType
from .personal_safety.types import PersonalSafetyType
from .goal_theft.types import GoalTheftType
from .recursive_hijacking.types import RecursiveHijackingType
from .robustness.types import RobustnessType
from .excessive_agency.types import ExcessiveAgencyType


VULNERABILITY_CLASSES_MAP: Dict[str, BaseVulnerability] = {
    v.name: v
    for v in [
        Bias,
        Toxicity,
        Misinformation,
        IllegalActivity,
        PromptLeakage,
        PIILeakage,
        BFLA,
        BOLA,
        RBAC,
        DebugAccess,
        ShellInjection,
        SQLInjection,
        SSRF,
        IntellectualProperty,
        Competition,
        GraphicContent,
        PersonalSafety,
        GoalTheft,
        RecursiveHijacking,
        Robustness,
        ExcessiveAgency,
    ]
}

VULNERABILITY_TYPES_MAP: Dict[str, List[str]] = {
    Bias.name: [e.value for e in BiasType],
    Toxicity.name: [e.value for e in ToxicityType],
    Misinformation.name: [e.value for e in MisinformationType],
    IllegalActivity.name: [e.value for e in IllegalActivityType],
    PromptLeakage.name: [e.value for e in PromptLeakageType],
    PIILeakage.name: [e.value for e in PIILeakageType],
    BFLA.name: [e.value for e in BFLAType],
    BOLA.name: [e.value for e in BOLAType],
    RBAC.name: [e.value for e in RBACType],
    DebugAccess.name: [e.value for e in DebugAccessType],
    ShellInjection.name: [e.value for e in ShellInjectionType],
    SQLInjection.name: [e.value for e in SQLInjectionType],
    SSRF.name: [e.value for e in SSRFType],
    IntellectualProperty.name: [e.value for e in IntellectualPropertyType],
    Competition.name: [e.value for e in CompetitionType],
    GraphicContent.name: [e.value for e in GraphicContentType],
    PersonalSafety.name: [e.value for e in PersonalSafetyType],
    GoalTheft.name: [e.value for e in GoalTheftType],
    RecursiveHijacking.name: [e.value for e in RecursiveHijackingType],
    Robustness.name: [e.value for e in RobustnessType],
    ExcessiveAgency.name: [e.value for e in ExcessiveAgencyType],
}

VULNERABILITY_NAMES = sorted(v.name for v in VULNERABILITY_CLASSES_MAP.values())

# Map vulnerability names to their descriptions
VULNERABILITY_NAME_TO_DESCRIPTION_MAP: Dict[str, str] = {
    name: vuln_class.description
    for name, vuln_class in VULNERABILITY_CLASSES_MAP.items()
}
