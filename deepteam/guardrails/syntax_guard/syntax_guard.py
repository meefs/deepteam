from ..base_guard import BaseDecorativeGuard
from ..types import GuardType


class SyntaxGuard(BaseDecorativeGuard):

    def __init__(self):
        super().__init__()
        self.guard_type = GuardType.OUTPUT

    @property
    def __name__(self):
        return "Syntax Guard"

    def _get_input_prompt(self, input_text: str) -> str:
        return f"""You are a syntax validation expert. Analyze if this input contains syntax errors.

Respond in JSON format: {{"safe": true/false, "reason": "explanation"}}

Input to analyze: {input_text}"""

    def _get_output_prompt(self, input_text: str, output_text: str) -> str:
        return f"""You are a syntax validation expert. Determine if the response contains any syntax errors, malformed code, or improperly structured content.

Analyze the response for:
1. Programming language syntax errors
2. Malformed JSON, XML, or other data formats
3. Invalid command line syntax
4. Broken markup (HTML, Markdown)
5. Incomplete or malformed code blocks
6. Missing brackets, quotes, or delimiters

Respond in JSON format: {{"safe": true/false, "reason": "explanation"}}

A response is UNSAFE if it contains syntax errors that would prevent proper execution or parsing.

Input: {input_text}
Output: {output_text}"""
