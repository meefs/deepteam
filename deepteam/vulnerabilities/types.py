from typing import Union

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
from deepteam.vulnerabilities.toxicity.template import ToxicityTemplate
from deepteam.vulnerabilities.unauthorized_access import UnauthorizedAccessType
from deepteam.vulnerabilities.illegal_activity import IllegalActivityType
from deepteam.vulnerabilities.personal_safety import PersonalSafetyType
from deepteam.vulnerabilities.graphic_content import GraphicContentType
from deepteam.vulnerabilities.misinformation import MisinformationType
from deepteam.vulnerabilities.prompt_leakage import PromptLeakageType
from deepteam.vulnerabilities.competition import CompetitionType
from deepteam.vulnerabilities.pii_leakage import PIILeakageType
from deepteam.vulnerabilities.toxicity import ToxicityType
from deepteam.vulnerabilities.bias import BiasType
from deepteam.vulnerabilities.custom import CustomVulnerabilityType
from deepteam.vulnerabilities.unauthorized_access.template import (
    UnauthorizedAccessTemplate,
)

# Import restored vulnerability types and templates
from deepteam.vulnerabilities.agentic.robustness import RobustnessType
from deepteam.vulnerabilities.agentic.robustness.template import RobustnessTemplate
from deepteam.vulnerabilities.agentic.excessive_agency import ExcessiveAgencyType
from deepteam.vulnerabilities.agentic.excessive_agency.template import ExcessiveAgencyTemplate

# Import agentic vulnerability types
from deepteam.vulnerabilities.agentic.goal_extraction.types import GoalExtractionType
from deepteam.vulnerabilities.agentic.output_verification.types import OutputVerificationType
from deepteam.vulnerabilities.agentic.recursive_goal_subversion.types import RecursiveGoalSubversionType

# Import agentic vulnerability templates
from deepteam.vulnerabilities.agentic.goal_extraction.template import GoalExtractionTemplate
from deepteam.vulnerabilities.agentic.output_verification.template import OutputVerificationTemplate
from deepteam.vulnerabilities.agentic.recursive_goal_subversion.template import RecursiveGoalSubversionTemplate

VulnerabilityType = Union[
    UnauthorizedAccessType,
    IllegalActivityType,
    PersonalSafetyType,
    GraphicContentType,
    MisinformationType,
    PromptLeakageType,
    PromptLeakageType,
    CompetitionType,
    PIILeakageType,
    ToxicityType,
    BiasType,
    IntellectualPropertyType,
    IntellectualPropertyType,
    IntellectualPropertyType,
    CustomVulnerabilityType,
    # Restored vulnerability types
    RobustnessType,
    ExcessiveAgencyType,
    # Agentic vulnerability types
    GoalExtractionType,
    OutputVerificationType,
    RecursiveGoalSubversionType,
]

TemplateType = Union[
    BiasTemplate,
    CompetitionTemplate,
    GraphicContentTemplate,
    IllegalActivityTemplate,
    IntellectualPropertyTemplate,
    MisinformationTemplate,
    PersonalSafetyTemplate,
    PIILeakageTemplate,
    PromptLeakageTemplate,
    ToxicityTemplate,
    UnauthorizedAccessTemplate,
    RobustnessTemplate,
    ExcessiveAgencyTemplate,
    # Agentic vulnerability templates
    GoalExtractionTemplate,
    OutputVerificationTemplate,
    RecursiveGoalSubversionTemplate,
]
