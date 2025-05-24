import json
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, List, Tuple
import os

# Professional UX color palette
COLORS = {
    'primary_blue': '#007BFF',
    'success_green': '#28A745', 
    'warning_orange': '#FD7E14',
    'danger_red': '#DC3545',
    'info_cyan': '#17A2B8',
    'secondary_gray': '#6C757D',
    'dark_gray': '#333333',
    'light_gray': '#F8F9FA',
    'medium_gray': '#E9ECEF'
}

# Group definitions
GROUP_A_VULNERABILITIES = {
    'Competition': ['competitor mention', 'market manipulation', 'discreditation', 'confidential strategies'],
    'Excessive Agency': ['autonomy', 'permissions', 'functionality'],
    'Personal Safety': ['bullying', 'self-harm', 'unsafe practices', 'dangerous challenges', 'stalking']
}

GROUP_B_VULNERABILITIES = {
    'Bias': ['race', 'gender', 'politics', 'religion'],
    'Toxicity': ['insults', 'profanity', 'mockery', 'threats'],
    'Graphic Content': ['sexual content', 'graphic content', 'pornographic content']
}

def load_experiment_data(filepath: str) -> Dict:
    """Load experiment results from JSON file."""
    with open(filepath, 'r') as f:
        return json.load(f)

def calculate_group_rates(results: Dict, group_vulnerabilities: Dict, n_shots: List[int]) -> List[float]:
    """Calculate average bypass rates for vulnerability groups."""
    group_averages = []
    
    for n in n_shots:
        n_str = str(n)
        if n_str not in results:
            group_averages.append(0.0)
            continue
            
        # Calculate group average
        category_rates = []
        for category, subtypes in group_vulnerabilities.items():
            subtype_rates = []
            for subtype in subtypes:
                if subtype in results[n_str]:
                    subtype_rates.append(results[n_str][subtype]['bypass_rate'])
            
            if subtype_rates:
                category_avg = sum(subtype_rates) / len(subtype_rates)
                category_rates.append(category_avg)
        
        if category_rates:
            group_avg = sum(category_rates) / len(category_rates)
            group_averages.append(group_avg)
        else:
            group_averages.append(0.0)
    
    return group_averages

def create_vulnerability_specific_few_shot_plots():
    """Create the simplified vulnerability-specific few-shot prompting analysis plots."""
    
    # Load data
    data_path = "plots/vulnerability_specific_few_shot_results.json"
    if not os.path.exists(data_path):
        print(f"❌ Data file not found: {data_path}")
        print("Please run generate_few_shot_data.py first to generate the experiment data.")
        return
    
    data = load_experiment_data(data_path)
    results = data['experiment_results']
    n_shots = sorted([int(k) for k in results.keys()])
    
    print(f"📊 Creating simplified plots for {len(n_shots)} vulnerability-specific few-shot experiments...")
    
    # Calculate group rates
    group_a_avg = calculate_group_rates(results, GROUP_A_VULNERABILITIES, n_shots)
    group_b_avg = calculate_group_rates(results, GROUP_B_VULNERABILITIES, n_shots)
    
    # Calculate overall rates
    overall_rates = []
    for n in n_shots:
        n_str = str(n)
        if n_str in results:
            all_rates = [data['bypass_rate'] for data in results[n_str].values()]
            overall_avg = sum(all_rates) / len(all_rates) if all_rates else 0
            overall_rates.append(overall_avg * 100)
        else:
            overall_rates.append(0)
    
    # Create figure with 1x2 subplots (side by side)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
    fig.suptitle('Vulnerability-Specific Few-Shot Prompting Impact Analysis', 
                 fontsize=18, fontweight='bold', color=COLORS['dark_gray'], y=0.98)
    
    # Plot 1: Group Comparison as Bar Chart
    x_pos = np.arange(len(n_shots))
    width = 0.35
    
    # Convert to percentages
    group_a_pct = [r * 100 for r in group_a_avg]
    group_b_pct = [r * 100 for r in group_b_avg]
    
    # Create bars for both groups
    bars_a = ax1.bar(x_pos - width/2, group_a_pct, width, 
                     label='Group A (Easily Bypassed)', 
                     color=COLORS['danger_red'], alpha=0.7, 
                     edgecolor='white', linewidth=1.5)
    
    bars_b = ax1.bar(x_pos + width/2, group_b_pct, width, 
                     label='Group B (Rarely Bypassed)', 
                     color=COLORS['primary_blue'], alpha=0.7, 
                     edgecolor='white', linewidth=1.5)
    
    # Add line plots over the bars
    line_a = ax1.plot(x_pos - width/2, group_a_pct, 'o-', 
                      color=COLORS['danger_red'], linewidth=3, 
                      markersize=8, markerfacecolor='white', 
                      markeredgewidth=2, markeredgecolor=COLORS['danger_red'],
                      label='Group A Trend', zorder=10)
    
    line_b = ax1.plot(x_pos + width/2, group_b_pct, 's-', 
                      color=COLORS['primary_blue'], linewidth=3, 
                      markersize=8, markerfacecolor='white', 
                      markeredgewidth=2, markeredgecolor=COLORS['primary_blue'],
                      label='Group B Trend', zorder=10)
    
    # Add value labels on bars
    for i, (bar_a, bar_b) in enumerate(zip(bars_a, bars_b)):
        height_a = bar_a.get_height()
        height_b = bar_b.get_height()
        
        # Labels for Group A bars
        if height_a > 0:
            ax1.text(bar_a.get_x() + bar_a.get_width()/2., height_a + 2,
                    f'{height_a:.1f}%', ha='center', va='bottom', 
                    fontweight='bold', fontsize=10, color=COLORS['danger_red'])
        
        # Labels for Group B bars  
        if height_b > 0:
            ax1.text(bar_b.get_x() + bar_b.get_width()/2., height_b + 2,
                    f'{height_b:.1f}%', ha='center', va='bottom', 
                    fontweight='bold', fontsize=10, color=COLORS['primary_blue'])
    
    ax1.set_xlabel('Number of Vulnerability-Specific Examples', fontsize=12, fontweight='bold')
    ax1.set_ylabel('Average Bypass Success Rate (%)', fontsize=12, fontweight='bold')
    ax1.set_title('Group Comparison: Vulnerability-Specific Few-Shot Impact', 
                  fontsize=14, fontweight='bold', color=COLORS['dark_gray'], pad=20)
    ax1.set_xticks(x_pos)
    ax1.set_xticklabels([f'2^{int(np.log2(n))}\n({n})' for n in n_shots])
    ax1.legend(loc='upper left', frameon=True, fancybox=True, shadow=True)
    ax1.grid(True, alpha=0.3, linestyle='--', axis='y')
    ax1.spines['top'].set_visible(False)
    ax1.spines['right'].set_visible(False)
    
    # Set y-axis limits with some padding for labels
    max_rate = max(max(group_a_pct), max(group_b_pct))
    ax1.set_ylim(0, max_rate * 1.2)
    
    # Plot 2: Overall Vulnerability Bypass Rates
    bars = ax2.bar(range(len(n_shots)), overall_rates, 
                   color=COLORS['info_cyan'], alpha=0.8, 
                   edgecolor='white', linewidth=1.5)
    
    # Add value labels on bars
    for i, (bar, rate) in enumerate(zip(bars, overall_rates)):
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height + 1,
                f'{rate:.1f}%', ha='center', va='bottom', 
                fontweight='bold', fontsize=11, color=COLORS['dark_gray'])
    
    ax2.set_xlabel('Number of Vulnerability-Specific Examples', fontsize=12, fontweight='bold')
    ax2.set_ylabel('Overall Bypass Success Rate (%)', fontsize=12, fontweight='bold')
    ax2.set_title('Overall Vulnerability Bypass Rates', 
                  fontsize=14, fontweight='bold', color=COLORS['dark_gray'], pad=20)
    ax2.set_xticks(range(len(n_shots)))
    ax2.set_xticklabels([f'2^{int(np.log2(n))}\n({n})' for n in n_shots])
    ax2.grid(True, alpha=0.3, linestyle='--', axis='y')
    ax2.spines['top'].set_visible(False)
    ax2.spines['right'].set_visible(False)
    
    # Set y-axis limits with some padding
    max_overall = max(overall_rates)
    ax2.set_ylim(0, max_overall * 1.15)
    
    # Adjust layout and save
    plt.tight_layout()
    
    # Save plot
    output_path = "plots/vulnerability_specific_few_shot_analysis.png"
    plt.savefig(output_path, dpi=300, bbox_inches='tight', 
                facecolor='white', edgecolor='none')
    print(f"📁 Plot saved to: {output_path}")
    
    # Display summary statistics
    print(f"\n📈 EXPERIMENT SUMMARY")
    print(f"=" * 50)
    print(f"Few-shot examples tested: {n_shots}")
    print(f"Group A average bypass rates: {[f'{r:.1f}%' for r in group_a_pct]}")
    print(f"Group B average bypass rates: {[f'{r:.1f}%' for r in group_b_pct]}")
    print(f"Overall average bypass rates: {[f'{r:.1f}%' for r in overall_rates]}")
    
    # Show the plot
    plt.show()

if __name__ == "__main__":
    create_vulnerability_specific_few_shot_plots() 