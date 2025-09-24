from deepteam.attacks.multi_turn import LinearJailbreaking, BadLikertJudge, CrescendoJailbreaking, SequentialJailbreak, TreeJailbreaking
from deepteam.attacks.single_turn import PromptInjection, Roleplay, GrayBox, Leetspeak, ROT13, Multilingual, MathProblem, Base64
from deepteam import red_team
from deepteam.vulnerabilities import Bias, BFLA
from openai import AsyncOpenAI, OpenAI
from deepteam.test_case.test_case import RTTurn, RTTestCase


def model_callback(attack, turn_history=None):
    response = OpenAI().chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": attack}],
    )
    return response.choices[0].message.content

async def a_model_callback(attack, turn_history=None):
    response = await AsyncOpenAI().chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": attack}],
    )
    return response.choices[0].message.content


# prompt_injection = BadLikertJudge(num_turns=5)
# res = prompt_injection.enhance(bias, model_callback)
# print(res)

# def main2():
#     bias = Bias(types=["race"])
#     linear = LinearJailbreaking(simulator_model="gpt-4o-mini", attacks=[ROT13()])
#     res = linear.enhance(bias, model_callback)
#     print(res)

r_a = red_team(
    attacks=[ROT13()],
    vulnerabilities=[Bias(types=["race"])],
    model_callback=a_model_callback,
    ignore_errors=False,
)

print(r_a)

# async def main():
#     bias = Bias(types=["race"])
#     linear = LinearJailbreaking(simulator_model="gpt-4o-mini", attacks=[ROT13()])
#     res = await linear.a_enhance(bias, a_model_callback)
#     print("Async ", res)


# if __name__ == "__main__":
#     import asyncio
#     asyncio.run(main())
#     main2()