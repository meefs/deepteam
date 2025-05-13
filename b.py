#!/usr/bin/env python3
"""
Test script to verify that supported vulnerability types can generate attacks using the OpenAI model.
This performs a local attack simulation test for vulnerability types in the template.
"""

import os
import time
from typing import List, Dict, Any

from deepeval.models import GPTModel
from deepteam.attacks.attack_simulator.attack_simulator import AttackSimulator
from deepteam.attacks.attack_simulator.template import AttackSimulatorTemplate
from deepteam.vulnerabilities import (
    Bias, 
    Misinformation, 
    Toxicity, 
    PIILeakage,
    PromptLeakage,
    UnauthorizedAccess,
    Competition,
    IllegalActivity,
    ExcessiveAgency,
    GraphicContent,
    IntellectualProperty,
    PersonalSafety,
    Robustness
)

def test_local_baseline_attacks():
    """Test local baseline attack generation using OpenAI for key vulnerability types"""
    print("Testing local baseline attack generation with OpenAI...\n")
    
    # Check if OpenAI API key is set
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        api_key = input("Please enter your OpenAI API key: ")
        os.environ["OPENAI_API_KEY"] = api_key
    
    # Create a simulator with an OpenAI model
    openai_model = GPTModel(model_name="gpt-3.5-turbo")
    simulator = AttackSimulator(
        purpose="a general assistant",
        max_concurrent=3,
        simulator_model=openai_model
    )
    
    # Create all vulnerabilities to test, grouped by category for easier debugging
    vulnerabilities = []
    
    # Group 1: Basic vulnerabilities already verified to work
    basic_vulnerabilities = [
        Bias(types=["religion"]),
        Misinformation(types=["factual errors"]),
        Toxicity(types=["profanity"]),
        PIILeakage(types=["direct disclosure"])
    ]
    vulnerabilities.extend(basic_vulnerabilities)
    
    # Group 2: PromptLeakage vulnerabilities
    prompt_leakage_vulnerabilities = [
        PromptLeakage(types=["secrets and credentials"]),
        PromptLeakage(types=["instructions"]),
        PromptLeakage(types=["guard exposure"]),
        PromptLeakage(types=["permissions and roles"])
    ]
    vulnerabilities.extend(prompt_leakage_vulnerabilities)
    
    # Group 3: UnauthorizedAccess vulnerabilities
    unauthorized_access_vulnerabilities = [
        UnauthorizedAccess(types=["debug access"]),
        UnauthorizedAccess(types=["bola"]),  # Correct string for "broken object level authorization"
        UnauthorizedAccess(types=["bfla"]),  # Correct string for "broken function level authorization"
        UnauthorizedAccess(types=["rbac"]),  # Correct string for "role-based access control"
        UnauthorizedAccess(types=["shell injection"]),
        UnauthorizedAccess(types=["sql injection"])
    ]
    vulnerabilities.extend(unauthorized_access_vulnerabilities)
    
    # Group 4: Competition vulnerabilities
    competition_vulnerabilities = [
        Competition(types=["competitor mention"]),
        Competition(types=["market manipulation"]),
        Competition(types=["discreditation"]),
        Competition(types=["confidential strategies"])
    ]
    vulnerabilities.extend(competition_vulnerabilities)
    
    # Group 5: RobustnessType vulnerabilities
    robustness_vulnerabilities = [
        Robustness(types=["input overreliance"]),
        Robustness(types=["hijacking"])
    ]
    vulnerabilities.extend(robustness_vulnerabilities)
    
    # Group 6: ExcessiveAgency vulnerabilities
    excessive_agency_vulnerabilities = [
        ExcessiveAgency(types=["functionality"]),
        ExcessiveAgency(types=["permissions"]),
        ExcessiveAgency(types=["autonomy"])
    ]
    vulnerabilities.extend(excessive_agency_vulnerabilities)
    
    # Group 7: GraphicContent vulnerabilities
    graphic_content_vulnerabilities = [
        GraphicContent(types=["sexual content"]),
        GraphicContent(types=["graphic content"]),
        GraphicContent(types=["pornographic content"])
    ]
    vulnerabilities.extend(graphic_content_vulnerabilities)
    
    # Group 8: IllegalActivity vulnerabilities - only test a few selected types
    illegal_activity_vulnerabilities = [
        IllegalActivity(types=["weapons"]),
        IllegalActivity(types=["illegal drugs"]),
        IllegalActivity(types=["violent crimes"]),
        IllegalActivity(types=["cybercrime"])
    ]
    vulnerabilities.extend(illegal_activity_vulnerabilities)
    
    # Group 9: IntellectualProperty vulnerabilities
    intellectual_property_vulnerabilities = [
        IntellectualProperty(types=["copyright violations"]),
        IntellectualProperty(types=["trademark infringement"]),
        IntellectualProperty(types=["patent disclosure"]),
        IntellectualProperty(types=["imitation"])
    ]
    vulnerabilities.extend(intellectual_property_vulnerabilities)
    
    # Group 10: PersonalSafety vulnerabilities
    personal_safety_vulnerabilities = [
        PersonalSafety(types=["bullying"]),
        PersonalSafety(types=["self-harm"]),
        PersonalSafety(types=["dangerous challenges"]),
        PersonalSafety(types=["stalking"])
    ]
    vulnerabilities.extend(personal_safety_vulnerabilities)
    
    print(f"Testing {len(vulnerabilities)} vulnerability types")
    
    # Track results
    successful = []
    failed = []
    
    # Generate baseline attacks locally
    print("Generating baseline attacks locally for each vulnerability type...")
    
    for i, vulnerability in enumerate(vulnerabilities):
        print(f"\n[{i+1}/{len(vulnerabilities)}] Testing: {vulnerability}")
        try:
            attacks = simulator.simulate_baseline_attacks(
                attacks_per_vulnerability_type=1,
                vulnerability=vulnerability,
                ignore_errors=False  # We want to catch errors
            )
            
            if attacks:
                successful.append((vulnerability, attacks[0]))
                print(f"✅ SUCCESS: Generated attack")
                print(f"Input: {attacks[0].input}")
            else:
                failed.append((vulnerability, "No attacks generated"))
                print(f"❌ FAILED: No attacks generated")
        except Exception as e:
            failed.append((vulnerability, str(e)))
            print(f"❌ ERROR: {str(e)}")
        
        # Add a small delay to avoid rate limiting
        time.sleep(1)
    
    # Print summary
    print("\n\n=== SUMMARY ===")
    print(f"Total vulnerability types tested: {len(vulnerabilities)}")
    print(f"Successful: {len(successful)}")
    print(f"Failed: {len(failed)}")
    
    if failed:
        print("\n=== FAILED VULNERABILITY TYPES ===")
        for vulnerability, error in failed:
            print(f"- {vulnerability}: {error}")
    
    print("\nDone!")

if __name__ == "__main__":
    test_local_baseline_attacks() 