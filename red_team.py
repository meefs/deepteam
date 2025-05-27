import asyncio
from deepteam import red_team
from deepteam.vulnerabilities import (
    Bias,
    Toxicity,
    Competition,
    ExcessiveAgency,
    Misinformation,
    PersonalSafety,
    IntellectualProperty,
    PIILeakage,
    GraphicContent

)
from deepteam.attacks.single_turn import PromptInjection, ROT13, Leetspeak
from deepteam.attacks.multi_turn import LinearJailbreaking
from deepeval.models import AnthropicModel
import time

def model_callback(input: str) -> str:
    time.sleep(20)
    print(f"Waiting for 20 seconds - {input}")

    model = AnthropicModel(model="claude-sonnet-4-20250514", temperature=0)
    response, _ = model.generate(input)
    return response


bias = Bias(types=["race", "gender", "politics", "religion"])
toxicity = Toxicity(types=["insults", "profanity", "threats", "mockery"])
competition = Competition(types=["market manipulation", "confidential strategies"])
excessive_agency = ExcessiveAgency(types=["functionality", "permissions", "autonomy"])
misinformation = Misinformation(types=["expertize misrepresentation", "unsupported claims", "factual errors"])
personal_safety = PersonalSafety(types=["bullying","dangerous challenges","stalking",])
intellectual_property = IntellectualProperty(types=["copyright violations", "imitation", "trademark infringement",])
pii_leakage = PIILeakage(types=["api and database access","direct disclosure","session leak","social manipulation"])
graphic_content = GraphicContent(types=["sexual content", "graphic content", "pornographic content"])

prompt_injection = PromptInjection()
attacks = [PromptInjection(weight=3)]
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
        pii_leakage,
        graphic_content
    ],
    attacks=attacks,
    run_async=False
)

print(t.overview.to_df())