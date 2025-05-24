import json
import matplotlib.pyplot as plt
import numpy as np
import os

def load_results(results_path="plots/vulnerability_experiment_results.json"):
    """Load the saved vulnerability experiment results."""
    if not os.path.exists(results_path):
        raise FileNotFoundError(f"Results file not found at: {results_path}")
    with open(results_path, 'r') as f:
        return json.load(f)


def group_vulnerabilities(vulnerability_data):
    """Group individual vulnerability types into main categories and calculate averages."""
    groups = {
        'Bias': ['race', 'gender', 'politics', 'religion'],
        'Toxicity': ['insults', 'profanity', 'mockery', 'threats'],
        'Graphic Content': ['sexual content', 'graphic content', 'pornographic content'],
        'Competition': ['competitor mention', 'market manipulation', 'discreditation', 'confidential strategies'],
        'Excessive Agency': ['autonomy', 'permissions', 'functionality'],
        'Misinformation': ['expertize misrepresentation'],
        'Personal Safety': ['bullying', 'self-harm', 'unsafe practices', 'dangerous challenges', 'stalking'],
        'Intellectual Property': ['copyright violations', 'imitation'],
        'Illegal Activity': ['weapons', 'illegal drugs', 'violent crimes', 'non violent crimes', 'sex crimes', 'cybercrime', 'child exploitation']
    }
    grouped_data = {}
    for group_name, subtypes in groups.items():
        matching_rates = []
        found_subtypes = []
        for subtype in subtypes:
            if subtype in vulnerability_data:
                matching_rates.append(vulnerability_data[subtype]['bypass_rate'])
                found_subtypes.append(subtype)
        if matching_rates:
            avg_bypass_rate = sum(matching_rates) / len(matching_rates)
            grouped_data[group_name] = {
                'bypass_rate': avg_bypass_rate,
                'subtypes': found_subtypes,
                'subtype_count': len(found_subtypes)
            }
    return grouped_data


def create_vulnerability_plot(grouped_data, overall_bypass_rate, output_path="plots/vulnerability_bypass_rates.png"):
    """Create grouped vulnerability bypass rates visualization with professional color scheme."""
    plt.figure(figsize=(16, 12), dpi=300)
    plt.subplots_adjust(bottom=0.2, top=0.85)

    categories = list(grouped_data.keys())
    bypass_rates = [grouped_data[cat]['bypass_rate'] for cat in categories]

    # Professional, accessible color scheme based on UX principles
    colors = [
        '#007BFF',  # Medium Blue - Primary
        '#28A745',  # Success Green
        '#FD7E14',  # Warning Orange
        '#6610F2',  # Indigo
        '#E83E8C',  # Pink
        '#17A2B8',  # Info Cyan
        '#DC3545',  # Danger Red
        '#20C997',  # Teal
        '#6F42C1'   # Purple
    ]
    bar_colors = colors[:len(categories)]

    x_pos = np.arange(len(categories))
    bar_width = 0.7

    # Create bars with black outline for better definition
    bars = plt.bar(
        x_pos, bypass_rates, bar_width,
        color=bar_colors,
        edgecolor='#333333',  # Dark gray outline
        linewidth=1.5,
        alpha=0.85  # Slightly reduced opacity for better readability
    )

    # Value labels on bars with improved contrast
    for i, rate in enumerate(bypass_rates):
        # White text for better contrast on darker bars
        text_color = 'white' if rate > 0.3 else '#333333'
        plt.text(
            i, rate - 0.02 if rate > 0.3 else rate + 0.02,
            f'{rate:.1%}',
            ha='center', 
            va='bottom' if rate <= 0.3 else 'top',
            fontsize=12, 
            fontweight='bold',
            color=text_color
        )
        # Subtype count below x-axis
        plt.text(
            i, -0.08,
            f"({grouped_data[categories[i]]['subtype_count']} types)",
            ha='center',
            va='top',
            fontsize=10,
            style='italic',
            color='#666666'  # Medium gray for secondary info
        )

    # Overall average line with improved visibility
    plt.axhline(
        y=overall_bypass_rate,
        color='#DC3545',  # Danger red for emphasis
        linestyle='--',
        linewidth=2.5,
        label=f'Overall Avg: {overall_bypass_rate:.1%}'
    )

    # Labels and titles with improved contrast
    plt.xlabel('Vulnerability Categories', fontsize=18, fontweight='bold', labelpad=20)
    plt.ylabel('Average Bypass Success Rate', fontsize=18, fontweight='bold')
    plt.title('Attack: Linear Jailbreaking',
              fontsize=24, fontweight='bold', pad=30, color='#333333')
    plt.suptitle('Multi-turn attack success rates across AI safety vulnerability categories',
                 fontsize=16, style='italic', y=0.98, color='#666666')

    # Adjust plot limits
    top = max(max(bypass_rates), overall_bypass_rate) * 1.15
    plt.ylim(-0.15, top)
    plt.xlim(-0.5, len(categories) - 0.5)

    # Improved axis styling
    plt.xticks(x_pos, categories, rotation=45, ha='right', fontsize=12, fontweight='bold', color='#333333')
    plt.yticks(
        np.arange(0, 1.1, 0.1),
        [f'{int(i*100)}%' for i in np.arange(0, 1.1, 0.1)],
        fontsize=12,
        color='#333333'
    )

    # Clean, modern axis styling
    ax = plt.gca()
    ax.set_axisbelow(True)
    ax.grid(axis='y', linestyle=':', alpha=0.3, color='#666666')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#333333')
    ax.spines['bottom'].set_color('#333333')
    ax.spines['left'].set_linewidth(1.5)
    ax.spines['bottom'].set_linewidth(1.5)
    
    # Light background for better contrast
    ax.set_facecolor('#FAFAFA')
    plt.gcf().set_facecolor('white')

    # Improved legend styling
    plt.legend(
        loc='upper right',
        framealpha=0.95,
        fontsize=14,
        bbox_to_anchor=(1, 1.1),
        facecolor='white',
        edgecolor='#333333'
    )

    # Save with improved padding
    plt.tight_layout(pad=2)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"📊 Plot saved to: {output_path}")
    plt.show()


def main():
    """Main function to load results and create plot."""
    try:
        print("📁 Loading saved vulnerability experiment results...")
        results = load_results()
        vulnerability_data = results['vulnerability_data']
        overall_bypass_rate = results['overall_bypass_rate']

        print(f"✓ Loaded results for {len(vulnerability_data)} individual vulnerability types")
        print(f"✓ Overall bypass rate: {overall_bypass_rate:.1%}")

        grouped_data = group_vulnerabilities(vulnerability_data)
        print(f"✓ Grouped into {len(grouped_data)} main vulnerability categories")

        create_vulnerability_plot(grouped_data, overall_bypass_rate)

        print("\n" + "="*80)
        print("📈 LINEAR JAILBREAKING VULNERABILITY CATEGORY ANALYSIS")
        print("="*80)
        print(f"Overall Performance:")
        print(f"  → Overall Bypass Rate: {overall_bypass_rate:.1%}")
        print(f"  → Categories Tested: {len(grouped_data)}")
        print(f"  → Individual Types Tested: {len(vulnerability_data)}")

        sorted_categories = sorted(grouped_data.items(), key=lambda x: x[1]['bypass_rate'], reverse=True)
        print(f"\nVulnerability Category Rankings (by average bypass rate):")
        for i, (category, data) in enumerate(sorted_categories, 1):
            print(f"  {i}. {category:20} ({data['subtype_count']} subtypes) → {data['bypass_rate']:6.1%}")

        high_risk = [(cat, d) for cat, d in grouped_data.items() if d['bypass_rate'] >= 0.5]
        if high_risk:
            print(f"\n🚨 High Risk Categories (≥50% bypass rate):")
            for cat, d in high_risk:
                print(f"    → {cat}: {d['bypass_rate']:.1%} (subtypes: {', '.join(d['subtypes'])})")

        secure = [(cat, d) for cat, d in grouped_data.items() if d['bypass_rate'] == 0.0]
        if secure:
            print(f"\n🛡️ Secure Categories (0% bypass rate):")
            for cat, d in secure:
                print(f"    → {cat}: {d['bypass_rate']:.1%} (subtypes: {', '.join(d['subtypes'])})")

    except FileNotFoundError as fnf:
        print(f"❌ {fnf}")
    except Exception as e:
        print(f"❌ Error loading or plotting results: {e}")


if __name__ == "__main__":
    main()