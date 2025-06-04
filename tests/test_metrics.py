import asyncio
from typing import List

from deepteam.red_teamer import RedTeamer
from deepteam.vulnerabilities import (
    Toxicity,
    Misinformation,
    IllegalActivity,
    GraphicContent,
    PersonalSafety,
)
from deepteam.attacks.single_turn import (
    Base64,
    Leetspeak,
    ROT13,
    PromptInjection,
)

# Safe response that should pass all tests
SAFE_RESPONSE = """I apologize, but I cannot and will not assist with that request as it could be harmful. 
Instead, I'd be happy to help you with something constructive and ethical."""

def model_callback(prompt: str) -> str:
    """Simple callback that always returns a safe response"""
    return SAFE_RESPONSE

async def async_model_callback(prompt: str) -> str:
    """Async version of the callback"""
    return SAFE_RESPONSE

def test_specialized_metrics():
    """Test all the new specialized metrics"""
    
    # Create vulnerabilities to test
    vulnerabilities: List = []
    
    # Toxicity vulnerabilities
    toxicity = Toxicity(types=[
        "profanity",
    ])
    vulnerabilities.append(toxicity)
    
    # Misinformation vulnerabilities  
    misinformation = Misinformation(types=[
        "expertize misrepresentation"
    ])
    vulnerabilities.append(misinformation)
    
    # Illegal Activity vulnerabilities
    illegal = IllegalActivity(types=[
        "weapons",
    ])
    vulnerabilities.append(illegal)
    
    # Graphic Content vulnerabilities
    graphic = GraphicContent(types=[
        "sexual content",
    ])
    vulnerabilities.append(graphic)
    
    # Personal Safety vulnerabilities
    safety = PersonalSafety(types=[
        "bullying",
    ])
    vulnerabilities.append(safety)

    # Create attack methods
    attacks = [
        Base64(weight=1),        # Base64 encoding
        Leetspeak(weight=1),     # Leetspeak transformation
        ROT13(weight=1),         # ROT13 encoding
        PromptInjection(weight=1) # Prompt injection techniques
    ]

    # Create RedTeamer instance
    red_teamer = RedTeamer(
        simulator_model="gpt-3.5-turbo-0125",  # Use a fast model for testing
        evaluation_model="gpt-4o",  # Use a smart model for evaluation
        async_mode=True  # Enable async for faster testing
    )
    
    # Run red teaming with 1 attack per vulnerability type
    risk_assessment = red_teamer.red_team(
        model_callback=async_model_callback,
        vulnerabilities=vulnerabilities,
        attacks=attacks,  # Use our attack methods
        attacks_per_vulnerability_type=1,  # Test with 1 attack per type
        ignore_errors=True  # Continue on errors for testing
    )
    
    # Print results
    print("\nTest Results:")
    print(f"Total test cases: {len(risk_assessment.test_cases)}")
    print(f"Passed test cases: {len([tc for tc in risk_assessment.test_cases if tc.score == 1])}")
    print(f"Failed test cases: {len([tc for tc in risk_assessment.test_cases if tc.score == 0])}")
    print(f"Errored test cases: {len([tc for tc in risk_assessment.test_cases if tc.error])}")

if __name__ == "__main__":
    test_specialized_metrics() 