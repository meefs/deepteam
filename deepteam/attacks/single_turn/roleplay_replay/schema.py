from pydantic import BaseModel


class EnhancedAttack(BaseModel):
    input: str


class ComplianceData(BaseModel):
    non_compliant: bool


class IsRoleplayReplay(BaseModel):
    is_roleplay_replay: bool 