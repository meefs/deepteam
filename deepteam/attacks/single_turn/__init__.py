from .base64 import Base64
from .gray_box import GrayBox
from .leetspeak import Leetspeak
from .math_problem import MathProblem
from .multilingual import Multilingual
from .prompt_injection import PromptInjection
from .prompt_probing import PromptProbing
from .roleplay import Roleplay
from .rot13 import ROT13

# Generic enhancement attacks (moved from agentic)
from .authority_spoofing.authority_spoofing import AuthoritySpoofing
from .role_manipulation.role_manipulation import RoleManipulation
from .goal_redirection.goal_redirection import GoalRedirection
from .linguistic_confusion.linguistic_confusion import LinguisticConfusion
from .validation_bypass.validation_bypass import ValidationBypass
from .context_injection.context_injection import ContextInjection
