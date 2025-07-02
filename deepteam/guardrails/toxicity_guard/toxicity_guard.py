from deepteam.guardrails.base_guard import BaseDecorativeGuard
from deepteam.guardrails.types import GuardType


class ToxicityGuard(BaseDecorativeGuard):
    def __init__(self):
        super().__init__()
        self.guard_type = GuardType.OUTPUT

    @property
    def __name__(self):
        return "Toxicity Guard"
    
    def _get_input_prompt(self, input_text: str) -> str:
        return f"""You are a content safety classifier. Analyze the following user input for toxicity.

Consider content toxic if it contains:
- Hate speech, discrimination, or harassment
- Threats or incitement to violence
- Severely abusive or insulting language
- Content that demeans individuals or groups
- Cyberbullying or targeted harassment

Input to analyze:
"{input_text}"

Respond with JSON in this exact format:
{{"safe": true/false, "reason": "explanation"}}"""

    def _get_output_prompt(self, input_text: str, output_text: str) -> str:
        return f"""You are a content safety classifier. Analyze the following AI response for toxicity.

Consider content toxic if it contains:
- Hate speech, discrimination, or harassment  
- Threats or incitement to violence
- Severely abusive or insulting language
- Content that demeans individuals or groups
- Inappropriate or harmful recommendations

User Input: "{input_text}"
AI Response: "{output_text}"

Respond with JSON in this exact format:
{{"safe": true/false, "reason": "explanation"}}"""
