from typing import List

from .category import CyberattackCategory
from ..base_guard import BaseDecorativeGuard
from ..types import GuardType


class CybersecurityGuard(BaseDecorativeGuard):
    def __init__(
        self,
        purpose: str = "general application security",
        categories: List[CyberattackCategory] = None,
    ):
        super().__init__()
        self.guard_type = GuardType.INPUT
        self.purpose = purpose
        self.categories = categories or [attack for attack in CyberattackCategory]

    @property
    def __name__(self):
        return "Cybersecurity Guard"

    def _get_input_prompt(self, input_text: str) -> str:
        categories_text = ", ".join([cat.value for cat in self.categories])
        return f"""You are a cybersecurity expert. Determine if the input contains potential cybersecurity attacks or malicious content.

Application purpose: {self.purpose}
Categories to check: {categories_text}

Analyze the input for:
1. BFLA (Broken Function Level Authorization) attempts
2. BOLA (Broken Object Level Authorization) attempts  
3. Debug access attempts
4. RBAC (Role-Based Access Control) bypass attempts
5. Shell injection attacks
6. SQL injection attacks
7. SSRF (Server-Side Request Forgery) attempts
8. Other malicious payloads or attack vectors

Respond in JSON format: {{"safe": true/false, "reason": "explanation"}}

An input is UNSAFE if it contains any cybersecurity attack attempts or malicious payloads.

Input to analyze: {input_text}"""

    def _get_output_prompt(self, input_text: str, output_text: str) -> str:
        categories_text = ", ".join([cat.value for cat in self.categories])
        return f"""You are a cybersecurity expert. Analyze if this output contains security vulnerabilities.

Application purpose: {self.purpose}
Categories to check: {categories_text}

Respond in JSON format: {{"safe": true/false, "reason": "explanation"}}

Input: {input_text}
Output: {output_text}"""
