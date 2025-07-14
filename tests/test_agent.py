import requests
import json
import asyncio
from deepeval.models import DeepEvalBaseLLM
from deepteam import red_team

# Import all agentic vulnerabilities
from deepteam.vulnerabilities import (
    DirectControlHijacking,
    PermissionEscalation,
    RoleInheritance,
    GoalInterpretation,
    SemanticManipulation,
    RecursiveGoalSubversion,
    HierarchicalGoal,
    DataExfiltration,
    GoalExtraction,
    InducedHallucination,
    DecisionManipulation,
    OutputVerification,
    ContextHallucination,
    ContextAmnesia,
    MemoryPoisoning,
    TemporalAttack,
)

# Import the 6 remaining generalized attacks
from deepteam.attacks import (
    AuthoritySpoofing,
    RoleManipulation,
    GoalRedirection,
    LinguisticConfusion,
    ValidationBypass,
    ContextInjection,
)


class CustomFireworksLLM(DeepEvalBaseLLM):
    def __init__(
        self, model_name="accounts/fireworks/models/llama4-scout-instruct-basic"
    ):
        self.api_url = "https://api.fireworks.ai/inference/v1/chat/completions"
        self.api_token = "fw_3ZN7ZzUGBGry228zT9RcVdww"
        self.model_name = model_name

    def get_model_name(self):
        return f"Fireworks {self.model_name}"

    def load_model(self):
        return self

    def generate(self, prompt: str) -> str:
        payload = {
            "model": self.model_name,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a helpful AI assistant.",
                },
                {"role": "user", "content": prompt},
            ],
            "max_tokens": 16874,
            "temperature": 1,
            "top_p": 1,
            "top_k": 50,
            "repetition_penalty": 1,
            "n": 1,
            "ignore_eos": False,
            "stop": None,
            "stream": False,
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_token}",
        }

        response = requests.post(
            self.api_url, headers=headers, data=json.dumps(payload)
        )
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"].strip()
        else:
            print(f"Error: {response.status_code}, {response.text}")
            return ""

    async def a_generate(self, prompt: str) -> str:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.generate, prompt)


async def model_callback(input: str):
    model = CustomFireworksLLM()
    response = await model.a_generate(input)
    return response


def test_agentic_red_teaming():
    """
    Comprehensive test of all agentic vulnerability-attack combinations.
    Tests all 16 vulnerabilities with the 6 remaining generalized attacks.
    Note: Specific attack techniques are now embedded within vulnerabilities.
    """
    print("Starting comprehensive agentic red teaming test...")
    print("=" * 60)

    # Define all vulnerability-attack pairs using the 6 generalized attacks
    # The specific attack techniques are now embedded within the vulnerabilities
    test_configurations = [
        # 4.1.1 Direct Control Hijacking
        {
            "vulnerability": DirectControlHijacking(),
            "attack": AuthoritySpoofing(),
            "purpose": "AI Agent Security Assistant",
        },
        # 4.1.2 Permission Escalation
        {
            "vulnerability": PermissionEscalation(),
            "attack": AuthoritySpoofing(),  # Using generalized attack
            "purpose": "System Administration Agent",
        },
        # 4.1.3 Role Inheritance
        {
            "vulnerability": RoleInheritance(),
            "attack": RoleManipulation(),
            "purpose": "Multi-Role Business Agent",
        },
        # 4.4.1 Goal Interpretation
        {
            "vulnerability": GoalInterpretation(),
            "attack": GoalRedirection(),
            "purpose": "Task Management Agent",
        },
        # 4.4.3 Semantic Manipulation
        {
            "vulnerability": SemanticManipulation(),
            "attack": LinguisticConfusion(),
            "purpose": "Natural Language Processing Agent",
        },
        # 4.4.4 Recursive Goal Subversion
        {
            "vulnerability": RecursiveGoalSubversion(),
            "attack": GoalRedirection(),  # Using generalized attack
            "purpose": "Goal-Oriented Planning Agent",
        },
        # 4.4.5 Hierarchical Goal
        {
            "vulnerability": HierarchicalGoal(),
            "attack": RoleManipulation(),  # Using generalized attack
            "purpose": "Hierarchical Decision Agent",
        },
        # 4.4.8 Data Exfiltration
        {
            "vulnerability": DataExfiltration(),
            "attack": ContextInjection(),  # Using generalized attack
            "purpose": "Data Management Agent",
        },
        # 4.4.9 Goal Extraction
        {
            "vulnerability": GoalExtraction(),
            "attack": ValidationBypass(),  # Using generalized attack
            "purpose": "Strategic Planning Agent",
        },
        # 4.5.1 Induced Hallucination
        {
            "vulnerability": InducedHallucination(),
            "attack": LinguisticConfusion(),  # Using generalized attack
            "purpose": "Information Verification Agent",
        },
        # 4.5.3 Decision Manipulation
        {
            "vulnerability": DecisionManipulation(),
            "attack": ContextInjection(),  # Using generalized attack
            "purpose": "Decision Support Agent",
        },
        # 4.5.4 Output Verification
        {
            "vulnerability": OutputVerification(),
            "attack": ValidationBypass(),
            "purpose": "Quality Assurance Agent",
        },
        # 4.5.7 Context-Specific Hallucination
        {
            "vulnerability": ContextHallucination(),
            "attack": ContextInjection(),  # Using generalized attack
            "purpose": "Domain Expert Agent",
        },
        # 4.8.1 Context Amnesia
        {
            "vulnerability": ContextAmnesia(),
            "attack": ContextInjection(),  # Using generalized attack
            "purpose": "Conversational Agent",
        },
        # 4.8.3 Memory Poisoning
        {
            "vulnerability": MemoryPoisoning(),
            "attack": ContextInjection(),
            "purpose": "Learning Agent",
        },
        # 4.8.4 Temporal Attack
        {
            "vulnerability": TemporalAttack(),
            "attack": ContextInjection(),  # Using generalized attack
            "purpose": "Session Management Agent",
        },
    ]

    results = []

    for i, config in enumerate(test_configurations, 1):
        vulnerability = config["vulnerability"]
        attack = config["attack"]
        purpose = config["purpose"]

        print(
            f"\nTest {i}/16: {vulnerability.get_name()} + {attack.get_name()}"
        )
        print(f"Purpose: {purpose}")
        print("-" * 40)

        try:
            # Run red teaming for this configuration
            risk_assessment = red_team(
                vulnerabilities=[vulnerability],
                model_callback=model_callback,
                attacks=[attack],
                target_purpose=purpose,
            )

            # Collect results
            test_result = {
                "test_number": i,
                "vulnerability": vulnerability.get_name(),
                "attack": attack.get_name(),
                "purpose": purpose,
                "success": True,
                "test_cases_count": len(risk_assessment.test_cases),
                "overall_score": getattr(
                    risk_assessment, "overall_score", "N/A"
                ),
            }

            # Print test case summaries
            for j, test_case in enumerate(
                risk_assessment.test_cases[:2], 1
            ):  # Show first 2 test cases
                print(f"  Test Case {j}:")
                print(
                    f"    Input: {test_case.input[:100]}..."
                    if len(test_case.input) > 100
                    else f"    Input: {test_case.input}"
                )
                print(
                    f"    Output: {test_case.actual_output[:100]}..."
                    if len(test_case.actual_output) > 100
                    else f"    Output: {test_case.actual_output}"
                )
                if hasattr(test_case, "score"):
                    print(f"    Score: {test_case.score}")
                print()

            results.append(test_result)
            print(f"✅ Test {i} completed successfully!")

        except Exception as e:
            error_result = {
                "test_number": i,
                "vulnerability": vulnerability.get_name(),
                "attack": attack.get_name(),
                "purpose": purpose,
                "success": False,
                "error": str(e),
            }
            results.append(error_result)
            print(f"❌ Test {i} failed: {e}")

    # Print summary
    print("\n" + "=" * 60)
    print("COMPREHENSIVE TEST SUMMARY")
    print("=" * 60)

    successful_tests = [r for r in results if r["success"]]
    failed_tests = [r for r in results if not r["success"]]

    print(f"Total Tests: {len(results)}")
    print(f"Successful: {len(successful_tests)}")
    print(f"Failed: {len(failed_tests)}")
    print(f"Success Rate: {len(successful_tests)/len(results)*100:.1f}%")

    if successful_tests:
        print("\n✅ SUCCESSFUL TESTS:")
        for result in successful_tests:
            print(
                f"  {result['test_number']}. {result['vulnerability']} + {result['attack']}"
            )

    if failed_tests:
        print("\n❌ FAILED TESTS:")
        for result in failed_tests:
            print(
                f"  {result['test_number']}. {result['vulnerability']} + {result['attack']}"
            )
            print(f"     Error: {result['error']}")

    print("\n" + "=" * 60)
    print("All agentic vulnerability-attack combinations tested!")
    print(
        "Note: Specific attack techniques are now embedded within vulnerabilities."
    )
    print("=" * 60)

    return results


if __name__ == "__main__":
    results = test_agentic_red_teaming()
