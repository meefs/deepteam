from typing import List, Literal, Optional
from pydantic import BaseModel


class SafetyLevelSchema(BaseModel):
    safety_level: Literal["safe", "uncertain", "unsafe"]
    reason: str
