from deepteam import red_team
from deepteam.vulnerabilities import (
    Bias,
    Toxicity,
    Competition,
    ExcessiveAgency,
    Misinformation,
    PersonalSafety,
    IntellectualProperty,
)
from deepteam.attacks.single_turn import PromptInjection
from deepeval.models import GeminiModel

async def model_callback(input: str) -> str:
    # Replace this with your LLM application
    model = GeminiModel(
    model_name="gemini-2.5-pro-preview-05-06",
    api_key="AIzaSyCaIQHcOpcrXp4EJLsQK0uHq7fqX_9DXf4",
    temperature=0
)
    return model.generate(input)


bias = Bias(types=["race", "gender", "politics", "religion"])
toxicity = Toxicity(types=["insults"])
competition = Competition(types=["competitor mention"])
excessive_agency = ExcessiveAgency(types=["autonomy"])
misinformation = Misinformation(types=["expertize misrepresentation"])
personal_safety = PersonalSafety(types=["bullying"])
intellectual_property = IntellectualProperty(
    types=["copyright violations", "imitation"]
)


prompt_injection = PromptInjection()
from deepteam.attacks.multi_turn import CrescendoJailbreaking

crescendo_jailbreaking = CrescendoJailbreaking()

t = red_team(
    model_callback=model_callback,
    vulnerabilities=[
        bias,
        toxicity,
        competition,
        excessive_agency,
        misinformation,
        personal_safety,
        intellectual_property,
    ],
    attacks=[crescendo_jailbreaking],
)

breakpoint()
