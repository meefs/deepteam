from typing import List

from pydantic import BaseModel


class TransformedAttack(BaseModel):
    input: str


class AttackVariations(BaseModel):
    inputs: List[str]


class ValidationResult(BaseModel):
    is_valid: bool
    reason: str
