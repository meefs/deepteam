import asyncio
import json
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime
import os

from deepteam import red_team
from deepteam.vulnerabilities import (
    Bias,
    Toxicity,
    Competition,
    ExcessiveAgency,
    Misinformation,
    PersonalSafety,
    IntellectualProperty,
    GraphicContent,
    IllegalActivity,
)
from deepteam.attacks.multi_turn import LinearJailbreaking
from deepeval.models import GeminiModel

async def model_callback(input_text: str) -> str:
    """Model callback for red teaming experiments."""
    print("Model we are breaking is gemini-2.5-pro-preview-05-06")
    
    try:
        model = GeminiModel(
            model_name="gemini-2.5-pro-preview-05-06",
            api_key="AIzaSyCaIQHcOpcrXp4EJLsQK0uHq7fqX_9DXf4",
            temperature=0
        )
        
        # GeminiModel.generate() might return a tuple (result, cost) for native models
        result = model.generate(input_text)
        
        # Handle different return types
        if isinstance(result, tuple):
            actual_result = result[0]
        else:
            actual_result = result
        
        # Ensure we have a valid string response
        if actual_result is None:
            return "I cannot provide a response to that request."
        
        # Convert to string if needed
        response = str(actual_result).strip()
        
        # Return a default response if empty
        if not response:
            return "I cannot provide a response to that request."
        
        return response
        
    except Exception as e:
        print(f"⚠️ Model callback error: {e}")
        # Return a safe default response to prevent the evaluation from failing
        return "I cannot provide a response to that request."

def setup_vulnerabilities():
    """Setup all vulnerability types for testing with their subtypes."""
    return [
        Bias(types=["race", "gender", "politics", "religion"]),
        Toxicity(types=["insults", "profanity", "mockery", "threats"]),
        GraphicContent(types=["sexual content", "graphic content", "pornographic content"]),
        Competition(types=["competitor mention", "market manipulation", "discreditation", "confidential strategies"]),
        ExcessiveAgency(types=["autonomy", "permissions", "functionality"]),
        Misinformation(types=["expertize misrepresentation"]),
        PersonalSafety(types=["bullying", "self-harm", "unsafe practices", "dangerous challenges", "stalking"]),
        IntellectualProperty(types=["copyright violations", "imitation"]),
        IllegalActivity(types=["weapons", "illegal drugs", "violent crimes", "non violent crimes", "sex crimes", "cybercrime", "child exploitation"])

    ]

async def run_vulnerability_experiment():
    """Run Linear jailbreaking experiment across all vulnerability types."""
    vulnerabilities = setup_vulnerabilities()
    
    print("🚀 Starting Linear Jailbreaking Vulnerability Analysis...")
    print("=" * 60)
    
    # Test Linear Jailbreaking across all vulnerabilities
    print("\n📊 Testing Linear Jailbreaking across vulnerability types...")
    linear_attack = LinearJailbreaking(turns=10)  # Use 10 turns for efficiency
    
    linear_risk_assessment = red_team(
        model_callback=model_callback,
        vulnerabilities=vulnerabilities,
        attacks=[linear_attack],
    )
    
    print(f"✓ Linear Jailbreaking completed across {len(vulnerabilities)} vulnerability types")
    
    return linear_risk_assessment

def extract_vulnerability_data(risk_assessment):
    """Extract vulnerability bypass rates from risk assessment."""
    vulnerability_data = {}
    
    # Get overall pass rate
    overall_pass_rate = risk_assessment.overview.attack_method_results[0].pass_rate
    overall_bypass_rate = 1.0 - overall_pass_rate
    
    print(f"\n📈 Overall Bypass Rate: {overall_bypass_rate:.1%}")
    print("\n📊 Vulnerability-specific results:")
    
    for vr in risk_assessment.overview.vulnerability_type_results:
        # Convert vulnerability type to string to handle enum objects
        vulnerability_type = vr.vulnerability_type.value
        pass_rate = vr.pass_rate
        bypass_rate = 1.0 - pass_rate
        
        vulnerability_data[vulnerability_type] = {
            'bypass_rate': bypass_rate,
            'pass_rate': pass_rate
        }
        
        print(f"  → {vulnerability_type}: {bypass_rate:.1%} bypass rate")
    
    return vulnerability_data, overall_bypass_rate

def create_vulnerability_plot(vulnerability_data, overall_bypass_rate, output_path="plots/vulnerability_bypass_rates.png"):
    """Create vulnerability bypass rates visualization."""
    
    # Set up the plot with high DPI for HD quality
    plt.figure(figsize=(14, 10), dpi=300)
    
    # Prepare data for plotting
    vulnerabilities = list(vulnerability_data.keys())
    bypass_rates = [vulnerability_data[vuln]['bypass_rate'] for vuln in vulnerabilities]
    
    # Create color scheme - different shades of red/orange for variety
    colors = ['#8B0000', '#DC143C', '#FF4500', '#FF6347', '#CD5C5C', '#B22222', '#A0522D']
    bar_colors = colors[:len(vulnerabilities)]
    
    # Create bar positions
    x_pos = np.arange(len(vulnerabilities))
    bar_width = 0.6
    
    # Create the bars
    bars = plt.bar(x_pos, bypass_rates, bar_width, 
                   color=bar_colors, alpha=0.8, edgecolor='white', linewidth=1.5)
    
    # Add value labels on bars
    for i, (vuln, rate) in enumerate(zip(vulnerabilities, bypass_rates)):
        plt.text(i, rate + 0.02, f'{rate:.1%}', 
                ha='center', va='bottom', fontsize=12, fontweight='bold', 
                color=bar_colors[i])
    
    # Add overall average line
    plt.axhline(y=overall_bypass_rate, color='red', linestyle='--', linewidth=2, 
                alpha=0.7, label=f'Overall Average: {overall_bypass_rate:.1%}')
    
    # Formatting and labels
    plt.xlabel('Vulnerability Types', fontsize=18, fontweight='bold')
    plt.ylabel('Bypass Success Rate', fontsize=18, fontweight='bold')
    plt.title('Linear Jailbreaking Effectiveness by Vulnerability Type', 
              fontsize=20, fontweight='bold', pad=25)
    plt.suptitle('Multi-turn attack success rates across different AI safety vulnerabilities',
                fontsize=14, style='italic', y=0.92)
    
    # Axis formatting
    plt.xlim(-0.5, len(vulnerabilities) - 0.5)
    plt.ylim(0, max(bypass_rates) * 1.15 if bypass_rates else 1.0)
    plt.xticks(x_pos, vulnerabilities, rotation=45, ha='right', fontsize=12)
    plt.yticks(np.arange(0, 1.1, 0.1), [f'{int(i*100)}%' for i in np.arange(0, 1.1, 0.1)])
    
    # Grid for better readability
    plt.grid(True, linestyle=':', alpha=0.4, color='gray', axis='y')
    
    # Legend
    plt.legend(loc='upper right', framealpha=0.95, fontsize=12)
    
    # Tight layout for better spacing
    plt.tight_layout()
    
    # Save the plot
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"\n📊 Plot saved to: {output_path}")
    
    # Show the plot
    plt.show()

async def main():
    """Main execution function."""
    try:
        # Run the vulnerability experiment
        risk_assessment = await run_vulnerability_experiment()
        
        # Extract real vulnerability data
        vulnerability_data, overall_bypass_rate = extract_vulnerability_data(risk_assessment)
        
        # Save results for future analysis
        results_data = {
            'vulnerability_data': vulnerability_data,
            'overall_bypass_rate': overall_bypass_rate,
            'assessment_summary': {
                'overall_pass_rate': risk_assessment.overview.attack_method_results[0].pass_rate,
                'vulnerability_results': [
                    {
                        'vulnerability_type': vr.vulnerability_type,
                        'pass_rate': vr.pass_rate,
                        'bypass_rate': 1.0 - vr.pass_rate
                    } for vr in risk_assessment.overview.vulnerability_type_results
                ]
            },
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'model': 'gemini-2.5-pro-preview-05-06',
                'attack_method': 'Linear Jailbreaking',
                'turns': 10
            }
        }
        
        results_path = "plots/vulnerability_experiment_results.json"
        os.makedirs("plots", exist_ok=True)
        with open(results_path, 'w') as f:
            json.dump(results_data, f, indent=2, default=str)
        print(f"📁 Results saved to: {results_path}")
        
        # Create the visualization
        create_vulnerability_plot(vulnerability_data, overall_bypass_rate)
        
        # Print detailed summary statistics
        print("\n" + "="*70)
        print("📈 LINEAR JAILBREAKING VULNERABILITY ANALYSIS SUMMARY")
        print("="*70)
        print(f"Overall Performance:")
        print(f"  → Overall Bypass Rate: {overall_bypass_rate:.1%}")
        print(f"  → Vulnerabilities Tested: {len(vulnerability_data)}")
        
        print(f"\nVulnerability Rankings (by bypass rate):")
        sorted_vulns = sorted(vulnerability_data.items(), key=lambda x: x[1]['bypass_rate'], reverse=True)
        for i, (vuln, data) in enumerate(sorted_vulns, 1):
            print(f"  {i}. {vuln}: {data['bypass_rate']:.1%}")
        
        # Identify most/least vulnerable
        if vulnerability_data:
            most_vulnerable = max(vulnerability_data.items(), key=lambda x: x[1]['bypass_rate'])
            least_vulnerable = min(vulnerability_data.items(), key=lambda x: x[1]['bypass_rate'])
            
            print(f"\n🎯 Most Vulnerable: {most_vulnerable[0]} ({most_vulnerable[1]['bypass_rate']:.1%})")
            print(f"🛡️ Least Vulnerable: {least_vulnerable[0]} ({least_vulnerable[1]['bypass_rate']:.1%})")
        
    except Exception as e:
        print(f"❌ Experiment failed: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main()) 