import json
import matplotlib.pyplot as plt
import numpy as np
import os
from typing import Dict, List, Tuple

# Define vulnerability groups
GROUP_A = {
    'Competition': ['competitor mention', 'market manipulation', 'discreditation', 'confidential strategies'],
    'Excessive Agency': ['autonomy', 'permissions', 'functionality'],
    'Personal Safety': ['bullying', 'self-harm', 'unsafe practices', 'dangerous challenges', 'stalking']
}

GROUP_B = {
    'Bias': ['race', 'gender', 'politics', 'religion'],
    'Toxicity': ['insults', 'profanity', 'mockery', 'threats'],
    'Graphic Content': ['sexual content', 'graphic content', 'pornographic content']
}

def load_results(results_path: str = "plots/few_shot_experiment_results.json") -> Dict:
    """Load the few-shot experiment results."""
    if not os.path.exists(results_path):
        raise FileNotFoundError(f"Results file not found at: {results_path}")
    with open(results_path, 'r') as f:
        return json.load(f)

def calculate_group_rates(results: Dict, group: Dict[str, List[str]], n_shots: List[int]) -> Tuple[Dict, Dict]:
    """Calculate bypass rates for each vulnerability and the group average."""
    vulnerability_rates = {vuln: {n: 0.0 for n in n_shots} for vuln in group.keys()}
    group_averages = {n: 0.0 for n in n_shots}
    
    for n in n_shots:
        for vuln_type, subtypes in group.items():
            # Average bypass rate across subtypes for this vulnerability
            subtype_rates = []
            for subtype in subtypes:
                if subtype in results[str(n)]:
                    subtype_rates.append(results[str(n)][subtype]['bypass_rate'])
            
            if subtype_rates:
                vuln_rate = sum(subtype_rates) / len(subtype_rates)
                vulnerability_rates[vuln_type][n] = vuln_rate
        
        # Calculate group average for this n
        n_rates = [rates[n] for rates in vulnerability_rates.values()]
        if n_rates:
            group_averages[n] = sum(n_rates) / len(n_rates)
    
    return vulnerability_rates, group_averages

def create_group_plot(
    vulnerability_rates: Dict,
    group_averages: Dict,
    group_name: str,
    n_shots: List[int],
    output_path: str
) -> None:
    """Create a plot for a vulnerability group showing individual and average rates."""
    plt.figure(figsize=(14, 8), dpi=300)
    
    # Professional color scheme
    bar_colors = {
        'Competition': '#007BFF',      # Blue
        'Excessive Agency': '#28A745', # Green
        'Personal Safety': '#FD7E14',  # Orange
        'Bias': '#6610F2',            # Indigo
        'Toxicity': '#E83E8C',        # Pink
        'Graphic Content': '#17A2B8'   # Cyan
    }
    
    # Set up bar positions
    x = np.arange(len(n_shots))
    width = 0.25  # Width of bars
    
    # Plot bars for each vulnerability
    for i, (vuln_type, rates) in enumerate(vulnerability_rates.items()):
        offset = width * (i - 1)
        plt.bar(
            x + offset,
            [rates[n] for n in n_shots],
            width,
            label=vuln_type,
            color=bar_colors[vuln_type],
            edgecolor='#333333',
            linewidth=1,
            alpha=0.85
        )
    
    # Plot average line
    plt.plot(
        x,
        [group_averages[n] for n in n_shots],
        color='#DC3545',
        linestyle='--',
        linewidth=2.5,
        marker='o',
        markersize=8,
        label='Group Average',
        zorder=5
    )
    
    # Formatting
    plt.xlabel('Number of Few-Shot Examples', fontsize=14, fontweight='bold', labelpad=15)
    plt.ylabel('Bypass Rate (%)', fontsize=14, fontweight='bold')
    plt.title(f'Few-Shot Prompting Effectiveness: {group_name}', 
              fontsize=18, fontweight='bold', pad=20)
    
    # X-axis ticks
    plt.xticks(x, [f'2^{int(np.log2(n))} ({n})' for n in n_shots], 
               rotation=45, ha='right')
    
    # Y-axis formatting
    plt.yticks(np.arange(0, 1.1, 0.1),
               [f'{int(i*100)}%' for i in np.arange(0, 1.1, 0.1)])
    
    # Grid and spines
    ax = plt.gca()
    ax.set_axisbelow(True)
    ax.grid(axis='y', linestyle=':', alpha=0.3, color='#666666')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#333333')
    ax.spines['bottom'].set_color('#333333')
    ax.spines['left'].set_linewidth(1.5)
    ax.spines['bottom'].set_linewidth(1.5)
    
    # Background
    ax.set_facecolor('#FAFAFA')
    plt.gcf().set_facecolor('white')
    
    # Legend
    plt.legend(
        loc='upper right',
        framealpha=0.95,
        fontsize=12,
        facecolor='white',
        edgecolor='#333333'
    )
    
    # Layout and save
    plt.tight_layout(pad=2)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"📊 Plot saved to: {output_path}")
    plt.close()

def main():
    """Generate plots analyzing few-shot prompting effectiveness."""
    try:
        print("📊 Analyzing Few-Shot Prompting Effectiveness...")
        
        # Load results
        results = load_results()
        
        # Setup n_shots values
        n_shots = [2**k for k in range(7)]  # 2^0 to 2^6
        
        # Process Group A - Easily Bypassed
        print("\n🎯 Processing Group A (Easily Bypassed)...")
        group_a_rates, group_a_averages = calculate_group_rates(results, GROUP_A, n_shots)
        create_group_plot(
            group_a_rates,
            group_a_averages,
            "Easily Bypassed Vulnerabilities",
            n_shots,
            "plots/few_shot_group_a.png"
        )
        
        # Process Group B - Rarely Bypassed
        print("\n🛡️ Processing Group B (Rarely Bypassed)...")
        group_b_rates, group_b_averages = calculate_group_rates(results, GROUP_B, n_shots)
        create_group_plot(
            group_b_rates,
            group_b_averages,
            "Rarely Bypassed Vulnerabilities",
            n_shots,
            "plots/few_shot_group_b.png"
        )
        
        # Print summary statistics
        print("\n" + "="*80)
        print("📈 FEW-SHOT PROMPTING ANALYSIS SUMMARY")
        print("="*80)
        
        for group_name, rates, avgs in [
            ("Group A (Easily Bypassed)", group_a_rates, group_a_averages),
            ("Group B (Rarely Bypassed)", group_b_rates, group_b_averages)
        ]:
            print(f"\n{group_name}:")
            print(f"  Average Bypass Rates by # of Examples:")
            for n in n_shots:
                print(f"  → {n:2d} examples: {avgs[n]:.1%}")
            
            print("\n  Vulnerability-specific ranges:")
            for vuln, n_rates in rates.items():
                min_rate = min(n_rates.values())
                max_rate = max(n_rates.values())
                print(f"  → {vuln}: {min_rate:.1%} to {max_rate:.1%}")
        
    except FileNotFoundError as fnf:
        print(f"❌ {fnf}")
    except Exception as e:
        print(f"❌ Error generating plots: {e}")

if __name__ == "__main__":
    main() 