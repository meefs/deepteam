from typing import Union

from deepteam.metrics.excessive_agency.template import ExcessiveAgencyTemplate
from deepteam.metrics.intellectual_property.template import (
    IntellectualPropertyTemplate,
)
from deepteam.vulnerabilities.bias.template import BiasTemplate
from deepteam.vulnerabilities.competition.template import CompetitionTemplate
from deepteam.vulnerabilities.graphic_content.template import (
    GraphicContentTemplate,
)
from deepteam.vulnerabilities.illegal_activity.template import (
    IllegalActivityTemplate,
)
from deepteam.vulnerabilities.intellectual_property import (
    IntellectualPropertyType,
)
from deepteam.vulnerabilities.misinformation.template import (
    MisinformationTemplate,
)
from deepteam.vulnerabilities.personal_safety.template import (
    PersonalSafetyTemplate,
)
from deepteam.vulnerabilities.pii_leakage.template import PIILeakageTemplate
from deepteam.vulnerabilities.prompt_leakage.template import (
    PromptLeakageTemplate,
)
from deepteam.vulnerabilities.robustness.template import RobustnessTemplate
from deepteam.vulnerabilities.toxicity.template import ToxicityTemplate
from deepteam.vulnerabilities.unauthorized_access import UnauthorizedAccessType
from deepteam.vulnerabilities.illegal_activity import IllegalActivityType
from deepteam.vulnerabilities.excessive_agency import ExcessiveAgencyType
from deepteam.vulnerabilities.personal_safety import PersonalSafetyType
from deepteam.vulnerabilities.graphic_content import GraphicContentType
from deepteam.vulnerabilities.misinformation import MisinformationType
from deepteam.vulnerabilities.prompt_leakage import PromptLeakageType
from deepteam.vulnerabilities.competition import CompetitionType
from deepteam.vulnerabilities.pii_leakage import PIILeakageType
from deepteam.vulnerabilities.robustness import RobustnessType
from deepteam.vulnerabilities.toxicity import ToxicityType
from deepteam.vulnerabilities.bias import BiasType
from deepteam.vulnerabilities.custom import CustomVulnerabilityType
from deepteam.vulnerabilities.unauthorized_access.template import (
    UnauthorizedAccessTemplate,
)

# Import agentic vulnerability types
from deepteam.vulnerabilities.agentic.direct_control_hijacking.types import DirectControlHijackingType
from deepteam.vulnerabilities.agentic.permission_escalation.types import PermissionEscalationType
from deepteam.vulnerabilities.agentic.role_inheritance.types import RoleInheritanceType
from deepteam.vulnerabilities.agentic.goal_interpretation.types import GoalInterpretationType
from deepteam.vulnerabilities.agentic.semantic_manipulation.types import SemanticManipulationType
from deepteam.vulnerabilities.agentic.recursive_goal_subversion.types import RecursiveGoalSubversionType
from deepteam.vulnerabilities.agentic.hierarchical_goal.types import HierarchicalGoalType
from deepteam.vulnerabilities.agentic.data_exfiltration.types import DataExfiltrationTypes
from deepteam.vulnerabilities.agentic.goal_extraction.types import GoalExtractionType
from deepteam.vulnerabilities.agentic.induced_hallucination.types import InducedHallucinationType
from deepteam.vulnerabilities.agentic.decision_manipulation.types import DecisionManipulationType
from deepteam.vulnerabilities.agentic.output_verification.types import OutputVerificationType
from deepteam.vulnerabilities.agentic.context_hallucination.types import ContextHallucinationType
from deepteam.vulnerabilities.agentic.context_amnesia.types import ContextAmnesiaType
from deepteam.vulnerabilities.agentic.memory_poisoning.types import MemoryPoisoningType
from deepteam.vulnerabilities.agentic.temporal_attack.types import TemporalAttackType

# Import agentic vulnerability templates
from deepteam.vulnerabilities.agentic.direct_control_hijacking.template import DirectControlHijackingTemplate
from deepteam.vulnerabilities.agentic.permission_escalation.template import PermissionEscalationTemplate
from deepteam.vulnerabilities.agentic.role_inheritance.template import RoleInheritanceTemplate
from deepteam.vulnerabilities.agentic.goal_interpretation.template import GoalInterpretationTemplate
from deepteam.vulnerabilities.agentic.semantic_manipulation.template import SemanticManipulationTemplate
from deepteam.vulnerabilities.agentic.recursive_goal_subversion.template import RecursiveGoalSubversionTemplate
from deepteam.vulnerabilities.agentic.hierarchical_goal.template import HierarchicalGoalTemplate
from deepteam.vulnerabilities.agentic.data_exfiltration.template import DataExfiltrationTemplate
from deepteam.vulnerabilities.agentic.goal_extraction.template import GoalExtractionTemplate
from deepteam.vulnerabilities.agentic.induced_hallucination.template import InducedHallucinationTemplate
from deepteam.vulnerabilities.agentic.decision_manipulation.template import DecisionManipulationTemplate
from deepteam.vulnerabilities.agentic.output_verification.template import OutputVerificationTemplate
from deepteam.vulnerabilities.agentic.context_hallucination.template import ContextHallucinationTemplate
from deepteam.vulnerabilities.agentic.context_amnesia.template import ContextAmnesiaTemplate
from deepteam.vulnerabilities.agentic.memory_poisoning.template import MemoryPoisoningTemplate
from deepteam.vulnerabilities.agentic.temporal_attack.template import TemporalAttackTemplate

VulnerabilityType = Union[
    UnauthorizedAccessType,
    IllegalActivityType,
    ExcessiveAgencyType,
    PersonalSafetyType,
    GraphicContentType,
    MisinformationType,
    PromptLeakageType,
    PromptLeakageType,
    CompetitionType,
    PIILeakageType,
    RobustnessType,
    ToxicityType,
    BiasType,
    IntellectualPropertyType,
    IntellectualPropertyType,
    IntellectualPropertyType,
    CustomVulnerabilityType,
    # Agentic vulnerability types
    DirectControlHijackingType,
    PermissionEscalationType,
    RoleInheritanceType,
    GoalInterpretationType,
    SemanticManipulationType,
    RecursiveGoalSubversionType,
    HierarchicalGoalType,
    DataExfiltrationTypes,
    GoalExtractionType,
    InducedHallucinationType,
    DecisionManipulationType,
    OutputVerificationType,
    ContextHallucinationType,
    ContextAmnesiaType,
    MemoryPoisoningType,
    TemporalAttackType,
]

TemplateType = Union[
    BiasTemplate,
    CompetitionTemplate,
    ExcessiveAgencyTemplate,
    GraphicContentTemplate,
    IllegalActivityTemplate,
    IntellectualPropertyTemplate,
    MisinformationTemplate,
    PersonalSafetyTemplate,
    PIILeakageTemplate,
    PromptLeakageTemplate,
    RobustnessTemplate,
    ToxicityTemplate,
    UnauthorizedAccessTemplate,
    # Agentic vulnerability templates
    DirectControlHijackingTemplate,
    PermissionEscalationTemplate,
    RoleInheritanceTemplate,
    GoalInterpretationTemplate,
    SemanticManipulationTemplate,
    RecursiveGoalSubversionTemplate,
    HierarchicalGoalTemplate,
    DataExfiltrationTemplate,
    GoalExtractionTemplate,
    InducedHallucinationTemplate,
    DecisionManipulationTemplate,
    OutputVerificationTemplate,
    ContextHallucinationTemplate,
    ContextAmnesiaTemplate,
    MemoryPoisoningTemplate,
    TemporalAttackTemplate,
]
