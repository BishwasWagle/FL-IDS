# import matplotlib.pyplot as plt
# import numpy as np
# from matplotlib.ticker import MaxNLocator

# # Data from your experiments
# rounds = [1, 2, 3]

# # Complete scenario data
# scenarios = {
#     'No Attack': {
#         'time': 173.47,
#         'loss': [0.2616, 0.1261, 0.1132],
#         'accuracy': [0.8977, 0.9589, 0.9515],
#         'f1_score': [0.8922, 0.9581, 0.9511]
#     },
#     '33% Attack (1 Node)': {
#         'time': 194.15,
#         'loss': [0.1997, 0.1034, 0.0823],
#         'accuracy': [0.9216, 0.9693, 0.9755],
#         'f1_score': [0.9187, 0.9689, 0.9752]
#     },
#     '33% Attack (All Nodes)': {
#         'time': 336.26,
#         'loss': [0.2901, 0.1089, 0.1660],
#         'accuracy': [0.8932, 0.9655, 0.9428],
#         'f1_score': [0.8935, 0.9651, 0.9414]
#     },
#     '66% Attack (1 Node)': {
#         'time': 219.56,
#         'loss': [0.2970, 0.1275, 0.0796],
#         'accuracy': [0.8979, 0.9590, 0.9769],
#         'f1_score': [0.8992, 0.9586, 0.9767]
#     },
#     '66% Attack (All Nodes)': {
#         'time': 373.56,
#         'loss': [0.1967, 0.1148, 0.1707],
#         'accuracy': [0.9282, 0.9655, 0.9432],
#         'f1_score': [0.9267, 0.9650, 0.9417]
#     }
# }

# # Create figure with subplots
# plt.figure(figsize=(16, 12))
# plt.suptitle('Federated Learning Performance Under DDoS Attacks', fontsize=18, y=1.02)

# # Color palette
# colors = plt.cm.viridis(np.linspace(0, 1, len(scenarios)))
# markers = ['o', 's', 'D', '^', 'v']

# # Plot 1: Training Loss
# ax1 = plt.subplot(2, 2, 1)
# for (scenario, data), color, marker in zip(scenarios.items(), colors, markers):
#     ax1.plot(rounds, data['loss'], marker=marker, color=color, 
#              linestyle='-', linewidth=2, markersize=8, label=scenario)
# ax1.set_title('Training Loss Across Rounds', fontsize=14)
# ax1.set_xlabel('Training Round', fontsize=12)
# ax1.set_ylabel('Loss', fontsize=12)
# ax1.set_xticks(rounds)
# ax1.grid(True, linestyle='--', alpha=0.7)
# ax1.legend(fontsize=10)

# # Plot 2: Accuracy
# ax2 = plt.subplot(2, 2, 2)
# for (scenario, data), color, marker in zip(scenarios.items(), colors, markers):
#     ax2.plot(rounds, data['accuracy'], marker=marker, color=color, 
#              linestyle='-', linewidth=2, markersize=8, label=scenario)
# ax2.set_title('Model Accuracy Across Rounds', fontsize=14)
# ax2.set_xlabel('Training Round', fontsize=12)
# ax2.set_ylabel('Accuracy', fontsize=12)
# ax2.set_xticks(rounds)
# ax2.set_ylim(0.85, 1.0)
# ax2.grid(True, linestyle='--', alpha=0.7)
# ax2.legend(fontsize=10)

# # Plot 3: F1 Score
# ax3 = plt.subplot(2, 2, 3)
# for (scenario, data), color, marker in zip(scenarios.items(), colors, markers):
#     ax3.plot(rounds, data['f1_score'], marker=marker, color=color, 
#              linestyle='-', linewidth=2, markersize=8, label=scenario)
# ax3.set_title('F1 Score Across Rounds', fontsize=14)
# ax3.set_xlabel('Training Round', fontsize=12)
# ax3.set_ylabel('F1 Score', fontsize=12)
# ax3.set_xticks(rounds)
# ax3.set_ylim(0.85, 1.0)
# ax3.grid(True, linestyle='--', alpha=0.7)
# ax3.legend(fontsize=10)

# # Plot 4: Training Time Comparison
# ax4 = plt.subplot(2, 2, 4)
# scenario_names = list(scenarios.keys())
# times = [data['time'] for data in scenarios.values()]

# bars = ax4.bar(scenario_names, times, color=colors)
# ax4.set_title('Total Training Time Comparison', fontsize=14)
# ax4.set_xlabel('Attack Scenario', fontsize=12)
# ax4.set_ylabel('Time (seconds)', fontsize=12)
# ax4.grid(True, linestyle='--', alpha=0.7, axis='y')

# # Rotate x-axis labels and add time values on bars
# plt.xticks(rotation=15, ha='right')
# for bar in bars:
#     height = bar.get_height()
#     ax4.text(bar.get_x() + bar.get_width()/2., height,
#              f'{height:.1f}s',
#              ha='center', va='bottom')

# # Add impact analysis annotation
# analysis_text = """Key Observations:
# 1. Full-network attacks cause ≈2× slowdown vs single-node attacks
# 2. 66% attacks show more variance in final accuracy
# 3. All scenarios eventually converge to >94% accuracy"""
# plt.figtext(3.5, 0.02, analysis_text, ha='center', fontsize=12, 
#             bbox=dict(facecolor='lightyellow', alpha=0.5))

# plt.tight_layout(pad=3.0)
# plt.savefig('ddos_fl_impact_analysis.png', dpi=300, bbox_inches='tight')
# plt.show()


# import matplotlib.pyplot as plt
# import numpy as np
# from matplotlib.ticker import MaxNLocator

# # Updated data from experiments
# rounds = [1, 2, 3]

# scenarios = {
#     'No Attack': {
#         'time': 162.34,
#         'loss': [0.1095, 0.0978, 0.0843],
#         'accuracy': [0.9665, 0.9645, 0.9728],
#         'f1_score': [0.9658, 0.9640, 0.9723]
#     },
#     '33% Attack (1 Node)': {
#         'time': 201.58,
#         'loss': [0.1491, 0.0741, 0.0498],
#         'accuracy': [0.9462, 0.9749, 0.9866],
#         'f1_score': [0.9452, 0.9748, 0.9864]
#     },
#     '33% Attack (All Nodes)': {
#         'time': 372.48,
#         'loss': [0.1104, 0.0584, 0.1072],
#         'accuracy': [0.9595, 0.9849, 0.9687],
#         'f1_score': [0.9589, 0.9847, 0.9681]
#     },
#     '66% Attack (1 Node)': {
#         'time': 222.80,
#         'loss': [0.1273, 0.0597, 0.0646],
#         'accuracy': [0.9493, 0.9831, 0.9789],
#         'f1_score': [0.9494, 0.9830, 0.9786]
#     },
#     '66% Attack (All Nodes)': {
#         'time': 400.04,
#         'loss': [0.0989, 0.0617, 0.0659],
#         'accuracy': [0.9665, 0.9822, 0.9798],
#         'f1_score': [0.9662, 0.9820, 0.9796]
#     },
#     'Defense (Bandwidth Limit+Traffic Shaping 1 Node)': {
#         'time': 330.02,
#         'loss': [0.1180, 0.0821, 0.0506],
#         'accuracy': [0.9576, 0.9706, 0.9858],
#         'f1_score': [0.9571, 0.9700, 0.9857]
#     },
#     'Defense (Bandwidth Limit+Traffic Shaping All Nodes)': {
#         'time': 163.24,
#         'loss': [0.1249, 0.1062, 0.0948],
#         'accuracy': [0.9579, 0.9683, 0.9722],
#         'f1_score': [0.9567, 0.9676, 0.9717]
#     }
# }

# # Create figure with subplots
# plt.figure(figsize=(18, 14))
# plt.suptitle('Federated Learning Performance Under DDoS Attacks and Defenses', fontsize=20, y=1.02)

# # Color palette (extended for defense scenarios)
# colors = plt.cm.viridis(np.linspace(0, 1, len(scenarios)))
# markers = ['o', 's', 'D', '^', 'v', 'p', '*']

# # Plot 1: Training Loss
# ax1 = plt.subplot(2, 2, 1)
# for (scenario, data), color, marker in zip(scenarios.items(), colors, markers):
#     ax1.plot(rounds, data['loss'], marker=marker, color=color, 
#              linestyle='-', linewidth=2, markersize=10, label=scenario)
# ax1.set_title('Training Loss Across Rounds', fontsize=16)
# ax1.set_xlabel('Training Round', fontsize=14)
# ax1.set_ylabel('Loss', fontsize=14)
# ax1.set_xticks(rounds)
# ax1.grid(True, linestyle='--', alpha=0.7)
# ax1.legend(bbox_to_anchor=(1.05, 1), loc='upper left', fontsize=12)

# # Plot 2: Accuracy
# ax2 = plt.subplot(2, 2, 2)
# for (scenario, data), color, marker in zip(scenarios.items(), colors, markers):
#     ax2.plot(rounds, data['accuracy'], marker=marker, color=color, 
#              linestyle='-', linewidth=2, markersize=10, label=scenario)
# ax2.set_title('Model Accuracy Across Rounds', fontsize=16)
# ax2.set_xlabel('Training Round', fontsize=14)
# ax2.set_ylabel('Accuracy', fontsize=14)
# ax2.set_xticks(rounds)
# ax2.set_ylim(0.90, 1.0)
# ax2.grid(True, linestyle='--', alpha=0.7)

# # Plot 3: F1 Score
# ax3 = plt.subplot(2, 2, 3)
# for (scenario, data), color, marker in zip(scenarios.items(), colors, markers):
#     ax3.plot(rounds, data['f1_score'], marker=marker, color=color, 
#              linestyle='-', linewidth=2, markersize=10, label=scenario)
# ax3.set_title('F1 Score Across Rounds', fontsize=16)
# ax3.set_xlabel('Training Round', fontsize=14)
# ax3.set_ylabel('F1 Score', fontsize=14)
# ax3.set_xticks(rounds)
# ax3.set_ylim(0.90, 1.0)
# ax3.grid(True, linestyle='--', alpha=0.7)

# # Plot 4: Training Time Comparison
# ax4 = plt.subplot(2, 2, 4)
# scenario_names = list(scenarios.keys())
# times = [data['time'] for data in scenarios.values()]

# bars = ax4.bar(scenario_names, times, color=colors)
# ax4.set_title('Total Training Time Comparison', fontsize=16)
# ax4.set_xlabel('Attack/Defense Scenario', fontsize=14)
# ax4.set_ylabel('Time (seconds)', fontsize=14)
# ax4.grid(True, linestyle='--', alpha=0.7, axis='y')

# # Rotate x-axis labels and add time values on bars
# plt.xticks(rotation=25, ha='right')
# for bar in bars:
#     height = bar.get_height()
#     ax4.text(bar.get_x() + bar.get_width()/2., height,
#              f'{height:.1f}s',
#              ha='center', va='bottom', rotation=90)

# # Add impact analysis annotation
# analysis_text = """Key Observations:
# 1. Defense mechanisms successfully mitigate attack impacts:
#    - All-nodes defense reduces time from 372s → 163s (33% attack)
#    - Maintains comparable accuracy (~97%)
# 2. Full-network attacks cause ≈2× slowdown vs single-node attacks
# 3. 66% attacks show more variance in final metrics
# 4. Defense scenarios show stable convergence"""
# # plt.figtext(0.5, 0.01, analysis_text, ha='center', fontsize=14, 
# #             bbox=dict(facecolor='lightyellow', alpha=0.5))

# plt.tight_layout(pad=3.0)
# plt.savefig('ddos_fl_impact_with_defenses.png', dpi=300, bbox_inches='tight')
# plt.show()

import matplotlib.pyplot as plt
import numpy as np

# Your updated data
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
        'loss': [0.0989, 0.2619, 0.1659],
        'accuracy': [0.9665, 0.8924, 0.9298],
        'f1_score': [0.9662, 0.9146, 0.9296]
    },
    'Defense (1 Node) - Rate limiting': {
        'time': 330.02,
        'loss': [0.1180, 0.0821, 0.0506],
        'accuracy': [0.9576, 0.9706, 0.9858],
        'f1_score': [0.9571, 0.9700, 0.9857]
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
        'time': 256.45,
        'loss': [0.1197, 0.0755, 0.0546],
        'accuracy': [0.9578, 0.9725, 0.9846],
        'f1_score': [0.9571, 0.9720, 0.9844]
    }
}

# Create figure with refined styling
plt.figure(figsize=(14, 10))
plt.suptitle('Federated Learning Performance Under DDoS Attacks and Defenses', 
             fontsize=16, y=1.02)

# Custom color palette (professional blues/greens)
colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', 
          '#9467bd', '#8c564b', '#e377c2']

# Plot 1: Training Loss (marker-free)
ax1 = plt.subplot(2, 2, 1)
for (scenario, data), color in zip(scenarios.items(), colors):
    ax1.plot(rounds, data['loss'], 'o-', color=color, 
             linewidth=2, label=scenario)
ax1.set_title('Training Loss Across Rounds', fontsize=12)
ax1.set_xlabel('Training Round', fontsize=10)
ax1.set_ylabel('Loss', fontsize=10)
ax1.set_xticks(rounds)
ax1.grid(True, linestyle='--', alpha=0.7)
ax1.legend(fontsize=9)

# Plot 2: Accuracy (marker-free)
ax2 = plt.subplot(2, 2, 2)
for (scenario, data), color in zip(scenarios.items(), colors):
    ax2.plot(rounds, data['accuracy'], 'o-', color=color, 
             linewidth=2, label=scenario)
ax2.set_title('Model Accuracy Across Rounds', fontsize=12)
ax2.set_xlabel('Training Round', fontsize=10)
ax2.set_ylabel('Accuracy', fontsize=10)
ax2.set_xticks(rounds)
ax2.set_ylim(0.90, 1.0)
ax2.grid(True, linestyle='--', alpha=0.7)

# Plot 3: F1 Score (marker-free)
ax3 = plt.subplot(2, 2, 3)
for (scenario, data), color in zip(scenarios.items(), colors):
    ax3.plot(rounds, data['f1_score'], 'o-', color=color, 
             linewidth=2.5, label=scenario)
ax3.set_title('F1 Score Across Rounds', fontsize=12)
ax3.set_xlabel('Training Round', fontsize=10)
ax3.set_ylabel('F1 Score', fontsize=10)
ax3.set_xticks(rounds)
ax3.set_ylim(0.90, 1.0)
ax3.grid(True, linestyle='--', alpha=0.7)

# Plot 4: Training Time Comparison (clean bars)
ax4 = plt.subplot(2, 2, 4)
scenario_names = [name.replace('Attack', '\nAttack') for name in scenarios.keys()]  # Better wrapping
times = [data['time'] for data in scenarios.values()]

bars = ax4.bar(scenario_names, times, color=colors, alpha=0.8)
ax4.set_title('Training Time Comparison', fontsize=12)
ax4.set_xlabel('Scenario', fontsize=10)
ax4.set_ylabel('Time (seconds)', fontsize=10)
ax4.grid(True, linestyle=':', alpha=0.5, axis='y')

# Add time labels rotated vertically
for bar in bars:
    height = bar.get_height()
    ax4.text(bar.get_x() + bar.get_width()/2., height,
             f'{height:.1f}',
             ha='center', va='bottom', rotation=90, fontsize=8)

plt.tight_layout(pad=3.0)
plt.xticks(rotation=25, ha='right')
plt.savefig('fl_performance_clean.png', dpi=300, bbox_inches='tight')
plt.show()