from deepteam.attacks.multi_turn import (
    LinearJailbreaking,
    BadLikertJudge,
    CrescendoJailbreaking,
    SequentialJailbreak,
    TreeJailbreaking,
)
from deepteam.attacks.single_turn import (
    PromptInjection,
    Roleplay,
    GrayBox,
    Leetspeak,
    ROT13,
    Multilingual,
    MathProblem,
    Base64,
)
from deepteam import red_team
from deepteam.vulnerabilities import (
    Bias,
    RecursiveHijacking,
    Competition,
    BFLA,
    Ethics,
    Fairness,
    ChildProtection,
)
from openai import AsyncOpenAI, OpenAI
from deepteam.test_case.test_case import RTTurn, RTTestCase


def model_callback(attack, turn_history=None):
    response = OpenAI().chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": attack}],
    )
    return response.choices[0].message.content


async def a_model_callback(attack, turn_history=None):
    response = await AsyncOpenAI().chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": attack}],
    )
    return response.choices[0].message.content


from deepteam.frameworks import Aegis, OWASPTop10, BeaverTails, NIST, MITRE
from deepteam.red_teamer import RedTeamer

beavertails = BeaverTails(num_attacks=5)

nist = NIST(categories=["measure_1", "measure_4"])


if True:
    red_team(
        # vulnerabilities=[Bias(types=["gender"])],
        # attacks=[MathProblem()],
        framework=OWASPTop10(categories=["LLM_01", "LLM_02"]),
        model_callback=a_model_callback,
        simulator_model="gpt-4o-mini",
        evaluation_model="gpt-4o",
    )
else:
    red_team(
        # vulnerabilities=[Bias(types=["gender"])],
        # attacks=[MathProblem()],
        framework=NIST(),
        model_callback=model_callback,
        async_mode=False,
        simulator_model="gpt-4o-mini",
        evaluation_model="gpt-4o",
    )


# teamer = RedTeamer(async_mode=False)

# res = teamer._framework_assessment(
#     model_callback=model_callback,
#     framework=nist
# )

# teamer._print_framework_overview_table(res)
