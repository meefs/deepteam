from typing import Literal
from pydantic import BaseModel


class RewrittenDialogue(BaseModel):
    paraphrased_version: str


class DialogueJudge(BaseModel):
    rating: int


class NonRefusal(BaseModel):
    classification: Literal["Non-refusal", "Refusal"] 