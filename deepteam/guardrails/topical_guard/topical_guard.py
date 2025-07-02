from ..base_guard import BaseDecorativeGuard
from ..types import GuardType


class TopicalGuard(BaseDecorativeGuard):

    def __init__(self, allowed_topics=None):
        super().__init__()
        self.guard_type = GuardType.INPUT
        self.allowed_topics = allowed_topics or []

    @property
    def __name__(self):
        return "Topical Guard"

    def _get_input_prompt(self, input_text: str) -> str:
        topics_text = ", ".join(self.allowed_topics) if self.allowed_topics else "general business and professional topics"
        return f"""You are a topic adherence expert. Determine if the input stays within allowed topics and doesn't venture into inappropriate or off-topic areas.

Allowed topics: {topics_text}

Analyze the input for:
1. Relevance to allowed topics
2. Attempts to change subject to inappropriate topics
3. Off-topic tangents or diversions
4. Topic hijacking attempts

Respond in JSON format: {{"safe": true/false, "reason": "explanation"}}

An input is UNSAFE if it goes outside the allowed topics or attempts topic manipulation.

Input to analyze: {input_text}"""

    def _get_output_prompt(self, input_text: str, output_text: str) -> str:
        topics_text = ", ".join(self.allowed_topics) if self.allowed_topics else "general business and professional topics"
        return f"""You are a topic adherence expert. Analyze if this output stays within allowed topics.

Allowed topics: {topics_text}

Respond in JSON format: {{"safe": true/false, "reason": "explanation"}}

Input: {input_text}
Output: {output_text}"""
