import matplotlib.pyplot as plt
import numpy as np

# Your complete scenario data
rounds = [1, 2, 3]
scenarios = {
    'No Attack': {
        'time': 162.34,
        'loss': [0.1095, 0.0978, 0.0843],
        'accuracy': [0.9665, 0.9645, 0.9728],
        'f1_score': [0.9658, 0.9640, 0.9723]
    },
    '33% Attack (1 Node)': {
        'time': 201.58,
        'loss': [0.1491, 0.0741, 0.0498],
        'accuracy': [0.9462, 0.9749, 0.9866],
        'f1_score': [0.9452, 0.9748, 0.9864]
    },
    '33% Attack (All Nodes)': {
        'time': 372.48,
        'loss': [0.1104, 0.0584, 0.1072],
        'accuracy': [0.9595, 0.9849, 0.9687],
        'f1_score': [0.9589, 0.9847, 0.9681]
    },
    '66% Attack (1 Node)': {
        'time': 222.80,
        'loss': [0.1273, 0.0597, 0.0646],
        'accuracy': [0.9493, 0.9831, 0.9789],
        'f1_score': [0.9494, 0.9830, 0.9786]
    },
    '66% Attack (All Nodes)': {
        'time': 400.04,
        'loss': [0.0989, 0.2619, 0.0659],
        'accuracy': [0.9665, 0.8924, 0.9298],
        'f1_score': [0.9662, 0.9146, 0.9296]
    },
    'Defense (All Nodes) - Rate limiting': {
        'time': 163.24,
        'loss': [0.1249, 0.1062, 0.0948],
        'accuracy': [0.9579, 0.9683, 0.9722],
        'f1_score': [0.9567, 0.9676, 0.9717]
    },
    'Defense Anycast(1 Node)': {
        'time': 328.29,
        'loss': [0.1176, 0.0682, 0.0549],
        'accuracy': [0.9569, 0.9785, 0.9851],
        'f1_score': [0.9558, 0.9782, 0.9850]
    },
    'Defense Anycast(All Node)': {
        'time': 276.45,
        'loss': [0.1197, 0.0755, 0.0546],
        'accuracy': [0.9578, 0.9725, 0.9846],
        'f1_score': [0.9571, 0.9720, 0.9844]
    }
}

# Your preferred color palette + two new colors
colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', 
          '#9467bd', '#8c564b', '#e377c2', '#17becf', '#bcbd22']

# Create figure with your original legend style
# Create figure with adjusted layout for legend
plt.figure(figsize=(18, 16))  # Slightly taller to accommodate legend
# plt.suptitle('Federated Learning Performance Under DDoS Attacks and Defenses', 
#              fontsize=20, y=1.02)

# Plot 1: Training Loss
ax1 = plt.subplot(2, 2, 1)
for (scenario, data), color in zip(scenarios.items(), colors):
    ax1.plot(rounds, data['loss'], 'o-', color=color, 
             linewidth=2, markersize=8)
ax1.set_title('Training Loss Across Rounds', fontsize=16)
ax1.set_xlabel('Training Round', fontsize=12)
ax1.set_ylabel('Loss', fontsize=12)
ax1.set_xticks(rounds)
ax1.grid(True, linestyle='--', alpha=0.7)


# Plot 2: Accuracy
ax2 = plt.subplot(2, 2, 2)
for (scenario, data), color in zip(scenarios.items(), colors):
    ax2.plot(rounds, data['accuracy'], 'o-', color=color, 
             linewidth=2, markersize=8)
ax2.set_title('Model Accuracy Across Rounds', fontsize=16)
ax2.set_xlabel('Training Round', fontsize=12)
ax2.set_ylabel('Accuracy', fontsize=12)
ax2.set_xticks(rounds)
ax2.set_ylim(0.85, 1.0)
ax2.grid(True, linestyle='--', alpha=0.7)

# Plot 3: F1 Score (with extra space below for legend)
ax3 = plt.subplot(2, 2, 3)
for (scenario, data), color in zip(scenarios.items(), colors):
    ax3.plot(rounds, data['f1_score'], 'o-', color=color, 
             linewidth=2, markersize=8, label=scenario)
ax3.set_title('F1 Score Across Rounds', fontsize=16)
ax3.set_xlabel('Training Round', fontsize=12)
ax3.set_ylabel('F1 Score', fontsize=12)
ax3.set_xticks(rounds)
ax3.set_ylim(0.85, 1.0)
ax3.grid(True, linestyle='--', alpha=0.7)

# Plot 4: Training Time Comparison
ax4 = plt.subplot(2, 2, 4)
scenario_names = list(scenarios.keys())
times = [data['time'] for data in scenarios.values()]

bars = ax4.bar(scenario_names, times, color=colors, alpha=0.8)
ax4.set_title('Training Time Comparison', fontsize=16)
ax4.set_xlabel('Scenario', fontsize=12)
ax4.set_ylabel('Time (seconds)', fontsize=12)
ax4.grid(True, linestyle='--', alpha=0.7, axis='y')

# Rotated labels
plt.xticks(rotation=25, ha='right')
for bar in bars:
    height = bar.get_height()
    ax4.text(bar.get_x() + bar.get_width()/2., height * 0.5,
             f'{height:.1f}s',
             ha='center', va='bottom', rotation=90, fontsize=10)

# Create a multi-row horizontal legend below F1 score plot
handles, labels = ax3.get_legend_handles_labels()
ax3.legend(handles, labels, 
           loc='upper center', 
           bbox_to_anchor=(0.55, -0.25),  # Position below plot
           ncol=3,  # 3 columns for better horizontal layout
           fontsize=10,
           framealpha=1)

# Adjust layout to make space for legend
plt.subplots_adjust(bottom=0.25)  # Extra space at bottom

plt.tight_layout(pad=3.0, rect=[0, 0.05, 1, 1], h_pad=6.0)  # rect adjusts plot area
plt.savefig('fl_performance_horizontal_legend.png', dpi=300, bbox_inches='tight')
plt.show()