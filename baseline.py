# Fix the TypeError by converting bars (a BarContainer) to a list before concatenation
import matplotlib.pyplot as plt
import numpy as np


# Recreate the scenarios data after kernel reset
rounds = [1, 2, 3]
scenarios = {
    'No Attack - Baseline': {'time': 162.34},
    'Attack - 1 Node - ND33': {'time': 202.62},
    'Attack - 3 Nodes - ND33': {'time': 376.27},
    'Rate Limiting - 1 Node - ND33': {'time': 330.02},
    'Rate Limiting - 3 Nodes - ND33': {'time': 153.44},
    'Anycast - 1 Node - ND33': {'time': 360.05},
    'Anycast - 3 Nodes - ND33': {'time': 274.46},
    'All Defenses - 1 Node - ND33': {'time': 323.03},
    'All Defenses - 3 Nodes - ND33': {'time': 180.55},
    'Attack - 1 Node - ND66': {'time': 228.32},
    'Attack - 3 Nodes - ND66': {'time': 426.73},
    'Rate Limiting - 1 Node - ND66': {'time': 379.18},
    'Rate Limiting - 3 Nodes - ND66': {'time': 282.18},
    'Anycast - 1 Node - ND66': {'time': 328.29},
    'Anycast - 3 Nodes - ND66': {'time': 256.45},
    'All Defenses - 1 Node - ND66': {'time': 379.31},
    'All Defenses - 3 Nodes - ND66': {'time': 179.24},
}

# Split into nd33 and nd66 sets with baseline included
nd33_scenarios = {
    k: v for k, v in scenarios.items() if 'ND33' in k or 'Baseline' in k
}
nd66_scenarios = {
    k: v for k, v in scenarios.items() if 'ND66' in k or 'Baseline' in k
}

colors = [
    '#1f77b4', '#2ca02c', '#ff7f0e',
    '#d62728', '#8c564b', '#e377c2',
    '#9467bd', '#17becf', '#bcbd22'
]

# Baseline time
baseline_name = 'No Attack - Baseline'
baseline_time = scenarios['No Attack - Baseline']['time']

# Fix the TypeError by converting bars (a BarContainer) to a list before concatenation
def plot_scenarios_with_baseline(scenarios_subset, title, filename, color_offset=0):
    fig, ax = plt.subplots(figsize=(12, 8))
    names = list(scenarios_subset.keys())
    times = [scenarios_subset[k]['time'] for k in names]
    
    bars = ax.bar(names, times, 
                  color=colors[color_offset:] * (len(names)//len(colors)+1), 
                  alpha=0.8)

    # Plot horizontal baseline line
    ax.axhline(y=baseline_time, color='#1f77b4', linestyle='--', linewidth=2)
    ax.text(len(names)-0.5, baseline_time,
        f'Baseline', color='#1f77b4', fontsize=12,
        ha='right', va='top', fontweight='bold')

    # Remove x-tick labels
    ax.set_xticks([])
    ax.set_xlabel('')
    ax.set_ylabel('Time (seconds)', fontsize=16)
    ax.grid(axis='y', linestyle='--', alpha=0.6)
    ax.tick_params(axis='y', labelsize=14)
    
    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + 5,
                f'{h:.2f}s', ha='center', va='bottom', fontsize=16)

    # Combine bar handles and baseline line for legend
    handles = list(bars) + [plt.Line2D([0], [0], color='gray', linestyle='--', linewidth=2)]
    labels = names
    
    plt.legend(
        handles, labels,
        loc='lower center',
        ncol=3,
        fontsize=14,
        frameon=True,
        bbox_to_anchor=(0.5, -0.25)
    )

    plt.tight_layout()
    plt.savefig(filename, bbox_inches='tight')
    plt.show()

# Plot again with corrected function
plot_scenarios_with_baseline(nd33_scenarios, 'Training Times - ND33 Scenarios', 'fl_training_times_nd33_baseline.pdf')
plot_scenarios_with_baseline(nd66_scenarios, 'Training Times - ND66 Scenarios', 'fl_training_times_nd66_baseline.pdf')
