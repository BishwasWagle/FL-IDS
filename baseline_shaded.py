# Fix the TypeError by converting bars (a BarContainer) to a list before concatenation
import matplotlib.pyplot as plt
import numpy as np


# Recreate the scenarios data after kernel reset
rounds = [1, 2, 3]
scenarios = {
    'No Defense - Baseline': {'time': 162.34},
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
baseline_name = 'No Defense - Baseline'
baseline_time = scenarios['No Defense - Baseline']['time']

def plot_shaded_bars(scenarios_subset, filename):
    fig, ax = plt.subplots(figsize=(12, 6))
    names = list(scenarios_subset.keys())
    times = [scenarios_subset[k]['time'] for k in names]
    
    x = np.arange(len(names))
    bar_width = 0.6

    # Shade up to baseline
    for i, (name, time) in enumerate(zip(names, times)):
        if time > baseline_time:
            ax.bar(x[i], baseline_time, width=bar_width, color=colors[i % len(colors)], alpha=0.4)
            ax.bar(x[i], time - baseline_time, bottom=baseline_time, width=bar_width, color=colors[i % len(colors)], alpha=0.8)
        else:
            ax.bar(x[i], time, width=bar_width, color=colors[i % len(colors)], alpha=0.4)

    ax.axhline(y=baseline_time, color='#1f77b4', linestyle='--', linewidth=2)
    ax.text(len(names)-0.5, baseline_time + 3,
        f'Baseline ({baseline_time:.2f}s)', color='#1f77b4', fontsize=16,
        ha='right', va='bottom', fontweight='bold')
    ax.set_ylabel('Time (seconds)', fontsize=16)
    ax.set_xticks([])
    ax.set_xlabel('')
    ax.grid(axis='y', linestyle='--', alpha=0.6)
    ax.tick_params(axis='y', labelsize=14)

    for i, time in enumerate(times):
        ax.text(x[i], time + 5, f'{time:.2f}s', ha='center', va='bottom', fontsize=16)

    # Legend
    handles = [plt.Rectangle((0,0),1,1, color=colors[i % len(colors)], alpha=0.8) for i in range(len(names))]
    labels = names
    handles.append(plt.Line2D([0], [0], color='gray', linestyle='--', linewidth=1.5))
    # labels.append('Baseline (162.34s)')

    plt.legend(handles, labels, loc='lower center', ncol=3, fontsize=12, frameon=True, bbox_to_anchor=(0.5, -0.35))

    plt.tight_layout()
    plt.savefig(filename, bbox_inches='tight')
    plt.show()

# Plot for ND33 scenarios
plot_shaded_bars(nd33_scenarios, 'fl_training_times_nd33_shaded.pdf')

# Plot for ND66 scenarios
plot_shaded_bars(nd66_scenarios, 'fl_training_times_nd66_shaded.pdf')
