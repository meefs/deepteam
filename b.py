from deepteam.attacks.multi_turn import LinearJailbreaking
from deepteam.attacks.single_turn import PromptInjection
from deepteam import red_team
from deepteam.vulnerabilities import Bias
from openai import AsyncOpenAI


async def model_callback(attack, turn_history):
    response = await AsyncOpenAI().chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": attack}],
    )
    return response.choices[0].message.content


red_team(
    attacks=[LinearJailbreaking(turns=2)],
    vulnerabilities=[Bias(types=["race"])],
    model_callback=model_callback,
    ignore_errors=True,
)
