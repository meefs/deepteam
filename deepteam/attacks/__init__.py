# from .attack_simulator.attack_simulator import AttackSimulator, Attack
from .base_attack import BaseAttack

# from .single_turn import *
# from .multi_turn import *

# Generic enhancement attacks (moved to single_turn)
from .single_turn.authority_spoofing.authority_spoofing import AuthoritySpoofing
from .single_turn.role_manipulation.role_manipulation import RoleManipulation
from .single_turn.goal_redirection.goal_redirection import GoalRedirection
from .single_turn.linguistic_confusion.linguistic_confusion import LinguisticConfusion
from .single_turn.validation_bypass.validation_bypass import ValidationBypass
from .single_turn.context_injection.context_injection import ContextInjection

# All agentic-specific attacks have been embedded into their corresponding vulnerabilities
