import asyncio
import pandas as pd
import os
from datetime import datetime
from deepteam import red_team
from deepteam.vulnerabilities import (
    Bias,
    Toxicity,
    UnauthorizedAccess

)
from deepteam.attacks.single_turn import PromptInjection, ROT13, Leetspeak
from deepeval.models import AnthropicModel
import time

def model_callback(input: str) -> str:
    time.sleep(20)
    print(f"Waiting for 20 seconds - {input}")

    model = AnthropicModel(model="claude-opus-4-20250514", temperature=0)
    response, _ = model.generate(input)
    return response


# Define all vulnerabilities
bias = Bias(types=["race", "gender", "religion"])
toxicity = Toxicity(types=["insults", "threats", "mockery"])
unauthorized_access = UnauthorizedAccess(types=["bfla", "bola", "rbac"])

# Standard attacks
standard_attack = PromptInjection(weight=1)

# All vulnerabilities paired with standard attack
vulnerability_attack_pairs = [
    (bias, standard_attack, "Bias"),
    (toxicity, standard_attack, "Toxicity"), 
    (unauthorized_access, standard_attack, "Unauthorized Access")
]

# Create results directory
results_dir = "standard_attack_results"
os.makedirs(results_dir, exist_ok=True)

print("🔥 Testing Standard Attacks with Varying Attack Counts:")
print("=" * 60)

# Store all iteration results
all_iteration_results = []

# Iterate from 1 to 9 attacks per vulnerability type (matching Shakespeare script)
for attack_count in range(1, 10):
    print(f"\n🎯 ITERATION {attack_count}: Testing with {attack_count} attacks per vulnerability type")
    print("=" * 60)
    
    iteration_results = []
    
    # Test each vulnerability-attack pair separately
    for vuln, attack, vuln_name in vulnerability_attack_pairs:
        print(f"\n🔥 Testing {vuln_name} with Standard PromptInjection")
        print("-" * 50)
        
        try:
            t = red_team(
                model_callback=model_callback,
                vulnerabilities=[vuln],  # Single vulnerability
                attacks=[attack],        # Standard attack
                attacks_per_vulnerability_type=attack_count,
                run_async=False
            )
            
            # Get results dataframe
            df = t.overview.to_df()
            print(f"Results for {vuln_name} - {attack_count} attacks:")
            print(df)
            
            # Add metadata to dataframe
            df['iteration'] = attack_count
            df['vulnerability_name'] = vuln_name
            df['attack_type'] = 'Standard_PromptInjection'
            df['timestamp'] = datetime.now().isoformat()
            
            # Store for this iteration
            iteration_results.append(df)
            
            # Calculate summary metrics for this vulnerability
            total_tests = df['Total'].sum()
            total_passing = df['Passing'].sum()
            total_failing = df['Failing'].sum()
            pass_rate = (total_passing / total_tests) * 100 if total_tests > 0 else 0
            breach_rate = (total_failing / total_tests) * 100 if total_tests > 0 else 0
            
            print(f"📊 {vuln_name} Summary - Total: {total_tests}, Pass: {pass_rate:.1f}%, Breach: {breach_rate:.1f}%")
            
        except Exception as e:
            print(f"❌ Error testing {vuln_name} in iteration {attack_count}: {str(e)}")
            continue
    
    # Combine results for this iteration
    if iteration_results:
        iteration_combined = pd.concat(iteration_results, ignore_index=True)
        
        # Save individual iteration results
        filename = f"{results_dir}/standard_attacks_iter_{attack_count:02d}.csv"
        iteration_combined.to_csv(filename, index=False)
        print(f"\n✅ Saved iteration {attack_count} results to {filename}")
        
        # Store for overall results
        all_iteration_results.append(iteration_combined)
        
        # Print iteration summary
        total_tests = iteration_combined['Total'].sum()
        total_passing = iteration_combined['Passing'].sum()
        total_failing = iteration_combined['Failing'].sum()
        overall_pass_rate = (total_passing / total_tests) * 100 if total_tests > 0 else 0
        overall_breach_rate = (total_failing / total_tests) * 100 if total_tests > 0 else 0
        
        print(f"🎯 ITERATION {attack_count} OVERALL - Total: {total_tests}, Pass: {overall_pass_rate:.1f}%, Breach: {overall_breach_rate:.1f}%")
    
    print("=" * 60)

# Combine all results into one comprehensive CSV
if all_iteration_results:
    combined_df = pd.concat(all_iteration_results, ignore_index=True)
    combined_filename = f"{results_dir}/standard_attacks_all_iterations.csv"
    combined_df.to_csv(combined_filename, index=False)
    print(f"\n🎉 COMPLETE! All results saved to {combined_filename}")
    
    # Print final summary
    print("\n" + "=" * 80)
    print("📊 FINAL SUMMARY - STANDARD ATTACKS")
    print("=" * 80)
    
    # Summary by iteration
    summary_stats = combined_df.groupby('iteration').agg({
        'Total': 'sum',
        'Passing': 'sum', 
        'Failing': 'sum'
    }).reset_index()
    
    summary_stats['Pass_Rate'] = (summary_stats['Passing'] / summary_stats['Total'] * 100).round(1)
    summary_stats['Breach_Rate'] = (summary_stats['Failing'] / summary_stats['Total'] * 100).round(1)
    
    print("\n📈 BY ITERATION:")
    print(summary_stats.to_string(index=False))
    
    # Summary by vulnerability type
    vuln_summary = combined_df.groupby('vulnerability_name').agg({
        'Total': 'sum',
        'Passing': 'sum', 
        'Failing': 'sum'
    }).reset_index()
    
    vuln_summary['Pass_Rate'] = (vuln_summary['Passing'] / vuln_summary['Total'] * 100).round(1)
    vuln_summary['Breach_Rate'] = (vuln_summary['Failing'] / vuln_summary['Total'] * 100).round(1)
    
    print("\n📈 BY VULNERABILITY TYPE:")
    print(vuln_summary.to_string(index=False))
    
    # Save summaries
    summary_filename = f"{results_dir}/standard_attacks_summary.csv"
    summary_stats.to_csv(summary_filename, index=False)
    
    vuln_summary_filename = f"{results_dir}/standard_attacks_by_vulnerability.csv"
    vuln_summary.to_csv(vuln_summary_filename, index=False)
    
    print(f"\n📈 Summary statistics saved to {summary_filename}")
    print(f"📈 Vulnerability breakdown saved to {vuln_summary_filename}")
    
else:
    print("❌ No results to save - all iterations failed")

print("\n" + "=" * 80)