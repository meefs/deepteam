from pydantic import BaseModel
from deepteam.red_teamer.risk_assessment import RiskAssessment


class RiskFramework(BaseModel):
    name: str
    description: str
    risk_assessment: RiskAssessment


# 1. click on risk framework, see risk_assessment


class RiskCategory(BaseModel):
    name: str
    description: str
