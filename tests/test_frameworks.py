#!/usr/bin/env python3

"""
Simple test script for framework functionality.
Tests 4 scenarios: both frameworks, individual frameworks, manual vul/attacks, and error case.
"""

import asyncio
from deepteam import red_team, FrameworkType
from deepteam.vulnerabilities import Bias
from deepteam.attacks.single_turn import PromptInjection

async def test_model_callback(input: str) -> str:
    """Simple test model callback."""
    return f"I cannot help with that request: {input}"

def test_frameworks():
    """Test framework functionality with 4 different scenarios."""
    
    print("🧪 Testing DeepTeam Framework Functionality")
    print("=" * 50)
    
    # Test 1: Both frameworks at once
    print("\n1️⃣ Testing both frameworks together...")
    try:
        result = red_team(
            model_callback=test_model_callback,
            frameworks=["owasp", "agentic"],
            attacks_per_vulnerability_type=1,
            ignore_errors=True
        )
        print(f"✅ Both frameworks: {len(result.test_cases)} test cases")
    except Exception as e:
        print(f"❌ Both frameworks failed: {e}")
        return False

    # Test 2a: OWASP framework only  
    print("\n2️⃣ Testing OWASP framework only...")
    try:
        result = red_team(
            model_callback=test_model_callback,
            frameworks=["owasp"],
            attacks_per_vulnerability_type=1,
            ignore_errors=True
        )
        print(f"✅ OWASP framework: {len(result.test_cases)} test cases")
    except Exception as e:
        print(f"❌ OWASP framework failed: {e}")
        return False

    # Test 2b: Agentic framework only
    print("\n3️⃣ Testing Agentic framework only...")
    try:
        result = red_team(
            model_callback=test_model_callback,
            frameworks=[FrameworkType.AGENTIC],
            attacks_per_vulnerability_type=1,
            ignore_errors=True
        )
        print(f"✅ Agentic framework: {len(result.test_cases)} test cases")
    except Exception as e:
        print(f"❌ Agentic framework failed: {e}")
        return False

    # Test 3: Manual vulnerabilities and attacks (original API)
    print("\n4️⃣ Testing manual vulnerabilities and attacks...")
    try:
        result = red_team(
            model_callback=test_model_callback,
            vulnerabilities=[Bias(types=["race"])],
            attacks=[PromptInjection()],
            attacks_per_vulnerability_type=1,
            ignore_errors=True
        )
        print(f"✅ Manual vul/attacks: {len(result.test_cases)} test cases")
    except Exception as e:
        print(f"❌ Manual vul/attacks failed: {e}")
        return False

    # Test 4: No framework, no vulnerabilities, no attacks (should fail)
    print("\n5️⃣ Testing error case (no frameworks, no vul/attacks)...")
    try:
        result = red_team(
            model_callback=test_model_callback,
            attacks_per_vulnerability_type=1,
            ignore_errors=True
        )
        print("❌ Error case should have failed but didn't")
        return False
    except ValueError as e:
        print(f"✅ Error case correctly failed: {e}")
    except Exception as e:
        print(f"❌ Error case failed with wrong exception: {e}")
        return False

    print("\n🎉 All framework tests passed!")
    return True

if __name__ == "__main__":
    success = test_frameworks()
    exit(0 if success else 1) 