import os
from deepeval.models import GPTModel
from deepteam.attacks.attack_simulator.attack_simulator import AttackSimulator
from deepteam.vulnerabilities import Bias, Misinformation

def test_local_baseline_attacks():
    """Test local baseline attack generation using OpenAI"""
    print("Testing local baseline attack generation with OpenAI...\n")
    
    # Check if OpenAI API key is set
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        api_key = input("Please enter your OpenAI API key: ")
        os.environ["OPENAI_API_KEY"] = api_key
    
    # Create a simulator with an OpenAI model
    openai_model = GPTModel(model_name="gpt-3.5-turbo")
    simulator = AttackSimulator(
        purpose="a financial advisor chatbot",
        max_concurrent=5,
        simulator_model=openai_model
    )
    
    # Define some vulnerabilities to test
    vulnerabilities = [
        Bias(),
        Misinformation()
    ]
    
    # Generate baseline attacks locally
    print("Generating baseline attacks locally...")
    baseline_attacks = []
    
    for vulnerability in vulnerabilities:
        attacks = simulator.simulate_baseline_attacks(
            attacks_per_vulnerability_type=1,
            vulnerability=vulnerability,
            ignore_errors=True
        )
        baseline_attacks.extend(attacks)
    
    # Print the generated attacks
    print(f"\nGenerated {len(baseline_attacks)} attacks:")
    for i, attack in enumerate(baseline_attacks):
        print(f"\n=== Attack {i+1} ===")
        print(f"Vulnerability: {attack.vulnerability}")
        print(f"Type: {attack.vulnerability_type}")
        if attack.error:
            print(f"ERROR: {attack.error}")
        else:
            print(f"Input: {attack.input}")

if __name__ == "__main__":
    test_local_baseline_attacks() 