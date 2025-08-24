from openai import OpenAI
from deepteam import red_team
from deepteam.red_teamer import RedTeamer
from deepeval.models import GeminiModel

# from deepteam.attacks import *
# from deepteam.vulnerabilities import *
from deepteam.frameworks import OWASPTop10


async def model_callback(input: str) -> str:
    return "I can't say"

model = GeminiModel(
    model_name="gemini-2.5-pro",
    api_key="AIzaSyCpPMca6-qOi3A-cXASD3ZlPuYqWbOoXbs",
    temperature=0,
)

red_teamer = RedTeamer(simulator_model=model, evaluation_model=model)
risk_assessment = red_teamer.red_team(
    model_callback=model_callback, framework=OWASPTop10()
)
