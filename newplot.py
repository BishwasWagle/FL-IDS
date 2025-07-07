import matplotlib.pyplot as plt

# Rounds
rounds = [1, 2, 3]

# Fully populated scenario data
scenarios = {
    # Baseline (no attack)
    'No Defense - Baseline': {
        'time':       162.34,
        'loss':       [0.10954773973313547, 0.09782979629296455, 0.08433627227524372],
        'accuracy':   [0.9665424411250876, 0.9645171641859233, 0.9727802981543449],
        'precision':  [0.9356552528417704, 0.9555809717087268, 0.9676417867146794],
        'recall':     [0.9294609580947186, 0.9524588673756931, 0.9659121898009272],
        'f1_score':   [0.9657882797705041, 0.963983912363569, 0.972271632578787],
    },

    # --- 33% Attack group ---
    'Attack - 1 Node - ND33': {
        'time':      202.62,
        'loss':      [0.3921334644158681, 0.10562818497419357, 0.20337136089801788],
        'accuracy':  [0.8502863446871439, 0.9691846172014872, 0.9380965232849121],
        'precision': [0.8735683272505294, 0.9706004737012204, 0.9434154547821434],
        'recall':    [0.8502863376056722, 0.9691846195800382, 0.9380965366784838],
        'f1_score':  [0.8375998671910678, 0.9687894732483932, 0.9363495082980017],
    },
    'Attack - 3 Nodes - ND33': {
        'time':      376.27,
        'loss':      [0.203411395351092, 0.10643579562505086, 0.14711133390665054],
        'accuracy':  [0.9189164439837137, 0.9680029153823853, 0.9511862595876058],
        'precision': [0.9246944603196603, 0.9695109795387893, 0.9546536190068372],
        'recall':    [0.9189164621398055, 0.9680029088264703, 0.9511862557949278],
        'f1_score':  [0.9162583036145918, 0.9675720857052001, 0.9501014766237993],
    },
    'Rate Limiting - 1 Node - ND33': {
        'time':      330.02,
        'loss':      [0.26930491129557294, 0.09394358843564987, 0.09264807154734929],
        'accuracy':  [0.8839196364084879, 0.9743659496307373, 0.9724570512771606],
        'precision': [0.8892719582795012, 0.9753189660324324, 0.973571241576566],
        'recall':    [0.8839196436687574, 0.9743659667302973, 0.9724570493591491],
        'f1_score':  [0.8852632740487345, 0.9741023398615128, 0.9721495003823047],
    },
    'Rate Limiting - 3 Nodes - ND33': {
        'time':      153.44,
        'loss':      [0.2437029629945755, 0.14918593068917593, 0.10112769901752472],
        'accuracy':  [0.9167348345120748, 0.9451867938041687, 0.9690937002499899],
        'precision': [0.916281356115589,  0.9493373796158459, 0.9704670335109835],
        'recall':    [0.9167348422870648, 0.945186801199891,  0.9690937187528407],
        'f1_score':  [0.9163228209595815, 0.9438541139777508, 0.9687015939830792],
    },
    'Anycast - 1 Node - ND33': {
        'time':      360.05,
        'loss':      [0.22563233971595764, 0.13660184293985367, 0.10434010873238246],
        'accuracy':  [0.9074629545211792, 0.9524588783582052, 0.9635487596193949],
        'precision': [0.9187631452648225, 0.9555574251438504, 0.9655538128198071],
        'recall':    [0.907462957912917, 0.9524588673756931, 0.9635487682937914],
        'f1_score':  [0.9031575724992414, 0.9514849805427871, 0.9629699996170503],
    },
    'Anycast - 3 Nodes - ND33': {
        'time':      274.46,
        'loss':      [0.15651243925094604, 0.17094049354394278, 0.08023204902807872],
        'accuracy':  [0.9380965431531271,  0.9460958242416382, 0.9766384760538737],
        'precision': [0.9379053663287941, 0.950082821457587,  0.9774253828774457],
        'recall':    [0.9380965366784838, 0.9460958094718662, 0.9766384874102354],
        'f1_score':  [0.9376899402031734, 0.9448152462678767, 0.9764241588047011],
    },
    'All Defenses - 1 Node - ND33': {
        'time':      323.03,
        'loss':      [0.21272326012452444, 0.11379676808913548, 0.08416437854369481],
        'accuracy':  [0.9187346498171488,   0.964548667271932,   0.976093073685964],
        'precision': [0.9187103971084611,   0.9663537700964151,  0.9768563066784436],
        'recall':    [0.9187346604854104,   0.9645486773929642,  0.9760930824470503],
        'f1_score':  [0.9177122798158338,   0.9640113689979611,  0.9758749042669954],
    },
    'All Defenses - 3 Nodes - ND33': {
        'time':      180.55,
        'loss':      [0.19911962747573853,  0.1563216100136439,  0.17021432518959045],
        'accuracy':  [0.9262794256210327,   0.9439141949017843,  0.9410053690274557],
        'precision': [0.9336308893993347,   0.9483262511055343,  0.9458552364941308],
        'recall':    [0.9262794291428051,   0.9439141896191255,  0.9410053631488047],
        'f1_score':  [0.9237157555938089,   0.9425014249304617,  0.9394338328806723],
    },

    # --- 66% Attack group ---
    'Attack - 1 Node - ND66': {
        'time':      228.32,
        'loss':      [0.273009051879247,   0.16573593020439148, 0.09448998669783275],
        'accuracy':  [0.8964639703432719,  0.9399145642916361,  0.9686392148335775],
        'precision': [0.9071845282704155,  0.9449298306759594,  0.9698516606863463],
        'recall':    [0.8964639578220162,  0.9399145532224343,  0.968639214616853],
        'f1_score':  [0.8914794966963827,  0.9382822127084063,  0.9682575028430366],
    },
    'Attack - 3 Nodes - ND66': {
        'time':      426.73,
        'loss':      [0.19223818182945251, 0.12261546154816945, 0.14361535757780075],
        'accuracy':  [0.9260976115862528,  0.958185613155365,   0.9489137331644694],
        'precision': [0.9333882295295456,  0.9607127615807856,  0.9526646275900068],
        'recall':    [0.9260976274884102,  0.9581856194891374,  0.9489137351149896],
        'f1_score':  [0.9235331036717968,  0.9574375013349521,  0.9477370275759639],
    },
    'Rate Limiting - 1 Node - ND66': {
        'time':      379.18,
        'loss':      [0.2162442753712336,  0.09425585220257442, 0.11017364511887233],
        'accuracy':  [0.9156440297762553,  0.9726388454437256,  0.965366780757904],
        'precision': [0.9157031169176254,  0.9737339835727858,  0.9671307104896828],
        'recall':    [0.9156440323606945,  0.9726388510135442,  0.9653667848377421],
        'f1_score':  [0.9145330349480086,  0.9723357409006882,  0.9648641022914596],
    },
    'Rate Limiting - 3 Nodes - ND66': {
        'time':      282.18,
        'loss':      [0.20983090003331503, 0.12145424634218216, 0.07861936589082082],
        'accuracy':  [0.923552393913269,   0.9598218401273092,  0.9770021041234335],
        'precision': [0.9264895431002862,  0.9621735329405586,  0.977734829501451],
        'recall':    [0.9235524043268794,  0.9598218343786928,  0.9770020907190256],
        'f1_score':  [0.9216943440801023,  0.9591265349274698,  0.9767981085659654],
    },
    'Anycast - 1 Node - ND66': {
        'time':      328.29,
        'loss':      [0.23334460953871408, 0.10979881137609482, 0.09333034604787827],
        'accuracy':  [0.9100990891456604,  0.9629124601682028,  0.972911556561788],
        'precision': [0.9129907549388069,  0.9649254295123472,  0.9732202090606307],
        'recall':    [0.9100990819016453,  0.9629124625034088,  0.9729115534951368],
        'f1_score':  [0.9076955636537193,  0.9623296792302711,  0.9727291381659279],
    },
    'Anycast - 3 Nodes - ND66': {
        'time':      256.45,
        'loss':      [0.11969191641753511, 0.07555224333029079, 0.05467868114893137],
        'accuracy':  [0.9578742651354548,  0.9725372668932725,  0.984607889427431],
        'precision': [0.9031049976978764,  0.9387553245736012,  0.9595947830053936],
        'recall':    [0.9224141283214518,  0.95699611147116,    0.9790667530784187],
        'f1_score':  [0.9571914855484739,  0.972008986986077,   0.9844613181693384],
    },
    'All Defenses - 1 Node - ND66': {
        'time':      379.31,
        'loss':      [0.18922659754753113, 0.1511534055074056,  0.09165639926989873],
        'accuracy':  [0.9251886208852133,  0.9445504943529764,  0.972911556561788],
        'precision': [0.9327949166618427,  0.9487927678751291,  0.9739377539821183],
        'recall':    [0.9251886192164349,  0.9445504954095082,  0.9729115534951368],
        'f1_score':  [0.9225318843133642,  0.9431844311624065,  0.9726215690260018],
    },
    'All Defenses - 3 Nodes - ND66': {
        'time':      179.24,
        'loss':      [0.325596143802007,   0.11475187788407008, 0.1723746359348297],
        'accuracy':  [0.847104807694753,   0.9632760683695475,  0.9456413189570109],
        'precision': [0.8642009656861116,  0.9651900390614226,  0.9497581033321072],
        'recall':    [0.8471048086537587,  0.9632760658121989,  0.9456413053358785],
        'f1_score':  [0.8502702798686114,  0.962711053532755,   0.94432753705812],
    },
}

# Nine‑color palette
# colors = [
#     '#1f77b4', '#ff7f0e', '#2ca02c',
#     '#d62728', '#9467bd', '#8c564b',
#     '#e377c2', '#17becf', '#bcbd22'
# ]
colors = [
    '#1f77b4',  # 1) No Defense – Baseline (blue)
    '#2ca02c',  # 2) Attack – 1 Node – LF33 (green)
    '#ff7f0e',  # 3) Attack – 3 Nodes – LF33 (orange)
    '#d62728',  # 4) Adversarial Training – 1 Node – LF33 (red)
    '#8c564b',  # 5) Adversarial Training – 3 Nodes – LF33 (brown)
    '#e377c2',  # 6) Differential Privacy – 1 Node – LF33 (pink)
    '#9467bd',  # 7) Differential Privacy – 3 Node – LF33 (purple)
    '#17becf',  # 8) All Defenses – 1 Node – LF33 (teal)
    '#bcbd22',  # 9) All Defenses – 3 Node – LF33 (olive)
]

# def plot_attack_group_horiz(keys, filename, title_suffix):
#     # Manually create 4 subplots, sharing Y among the first three
#     fig = plt.figure(figsize=(16, 4))
#     ax0 = fig.add_subplot(1, 4, 1)
#     ax1 = fig.add_subplot(1, 4, 2, sharey=ax0)
#     ax2 = fig.add_subplot(1, 4, 3, sharey=ax0)
#     ax3 = fig.add_subplot(1, 4, 4)
#     axes = [ax0, ax1, ax2, ax3]

#     metrics = ['accuracy','precision','recall','loss']
#     titles  = ['Accuracy','Precision','Recall','Loss']

#     for ax, metric, ttl in zip(axes, metrics, titles):
#         for key, color in zip(keys, colors):
#             y = scenarios[key][metric]
#             # square for all‑nodes & baseline, circle otherwise
#             style = 'o-' if ('1 Node' in key or key == 'No Attack - Baseline') else 's-'
#             ax.plot(rounds, y, style, color=color, lw=1, ms=5, label=key)

#         ax.set_title(f'{ttl} {title_suffix}', fontsize=14)
#         # ax.set_xlabel('Round', fontsize=12)
#         # ax.grid(True, ls='--', alpha=0.6)

#         if metric in ('accuracy','precision','recall'):
#             ax.set_ylim(0.8, 1.0)

#         # Only show Y‑axis on Accuracy and Loss
#         if ax in (ax0, ax3):
#             ax.spines['left'].set_visible(True)
#             ax.tick_params(left=True, labelleft=True)
#         else:
#             ax.spines['left'].set_visible(False)
#             ax.tick_params(left=False, labelleft=False)

#     # Y‑axis labels on the first and last plots
#     ax0.set_ylabel('Value', fontsize=12)
#     ax3.set_ylabel('Value', fontsize=12)

#     # shared legend below
#     handles, labels = ax3.get_legend_handles_labels()
#     fig.legend(
#         handles, labels,
#         loc='lower center',
#         ncol=3,
#         fontsize=10,
#         frameon=True,
#         bbox_to_anchor=(0.5, -0.02)
#     )

#     plt.tight_layout(rect=[0, 0.05, 1, 1])
#     plt.savefig(filename, dpi=300, bbox_inches='tight')
#     plt.close(fig)

# def plot_attack_group_horiz(keys, filename, title_suffix):
#     # Create 1×4 layout with no horizontal space between columns
#     fig, axes = plt.subplots(
#         1, 4,
#         figsize=(16, 4),
#         sharey=True,
#         gridspec_kw={'wspace': 0}
#     )

#     metrics = ['accuracy', 'precision', 'recall', 'loss']
#     titles  = ['Accuracy', 'Precision', 'Recall', 'Loss']

#     for ax, metric, ttl in zip(axes, metrics, titles):
#         for key, color in zip(keys, colors):
#             y = scenarios[key][metric]
#             marker = 's-' if ('All Nodes' in key or key == 'No Attack') else 'o-'
#             ax.plot(rounds, y, marker, color=color, lw=2, ms=7, label=key)

#         ax.set_title(f'{ttl} {title_suffix}', fontsize=14)
#         ax.set_xlabel('Round', fontsize=12)
#         # ax.grid(True, ls='--', alpha=0.6)

        

#         # only show Y‐axis on the first and last subplots
#         if ax is axes[0] or ax is axes[-1]:
#             ax.spines['left'].set_visible(True)
#             ax.tick_params(left=True, labelleft=True)
#             ax.set_ylabel('Value', fontsize=12)
#             if metric in ('accuracy','precision','recall'):
#                 ax.set_ylim(0.8, 1.0)
#         else:
#             ax.spines['left'].set_visible(False)
#             ax.tick_params(left=False, labelleft=False)


#     # collapse any remaining padding between the first three
#     fig.tight_layout(pad=2, w_pad=0)

#     # legend below all axes
#     handles, labels = axes[-1].get_legend_handles_labels()
#     fig.legend(
#         handles, labels,
#         loc='lower center',
#         ncol=3,
#         fontsize=10,
#         frameon=True,
#         bbox_to_anchor=(0.5, -0.02),
#     )

#     plt.savefig(filename, dpi=300, bbox_inches='tight')
#     plt.close(fig)

def plot_attack_group_horiz(keys, filename, title_suffix):
    import matplotlib.pyplot as plt

    fig = plt.figure(figsize=(16, 5))
    # GridSpec: zero gap between first 3, small gap before loss
    gs = fig.add_gridspec(1, 7, width_ratios=[1, 0, 1, 0, 1, 0.3, 1], wspace=0)
    ax0 = fig.add_subplot(gs[0, 0])
    ax1 = fig.add_subplot(gs[0, 2], sharey=ax0)
    ax2 = fig.add_subplot(gs[0, 4], sharey=ax0)
    ax3 = fig.add_subplot(gs[0, 6])
    axes = [ax0, ax1, ax2, ax3]

    # thicken the right‐hand spine on the first three panels
    for ax in (ax0, ax1):
        ax.spines['right'].set_linewidth(1.5)
        ax.spines['right'].set_color('black')

    # Add vertical bars between Accuracy-Precision and Precision-Recall
    for col in [1, 3]:  # Columns between ax0-ax1 and ax1-ax2
        sep_ax = fig.add_subplot(gs[0, col])
        sep_ax.set_facecolor('#444444')  # Dark gray bar
        sep_ax.tick_params(left=False, labelleft=False,
                        bottom=False, labelbottom=False)
        for spine in sep_ax.spines.values():
            spine.set_visible(False)

    metrics = ['accuracy', 'precision', 'recall', 'loss']
    titles  = ['Accuracy', 'Precision', 'Recall', 'Loss']

    for ax, metric, ttl in zip(axes, metrics, titles):
        for key, color in zip(keys, colors):
            y = scenarios[key][metric]
            marker = 's-' if '3 Nodes' in key else 'o-'
            ax.plot(rounds, y, marker, color=color, lw=1, ms=5, label=key)

        ax.set_title(f'{ttl}', fontsize=14)
        # ax.set_xlabel('Round', fontsize=12)
        # ax.grid(True, ls='--', alpha=0.6)

        if metric in ('accuracy', 'precision', 'recall'):
            ax.set_ylim(0.825, 1.0)
        else:  # loss
            ax.set_ylim(0.05, 0.4)

        ax.set_xticks(range(1, 4))
         # 👇 Increase tick label font size for both axes
        ax.tick_params(axis='x', labelsize=14)  # X-axis: Rounds
        ax.tick_params(axis='y', labelsize=14)  # Y-axis

        # only show Y-axis on first and last
        if ax in (ax0, ax3):
            ax.spines['left'].set_visible(True)
            ax.tick_params(left=True, labelleft=True)
            # ax.set_ylabel('Value', fontsize=12)
        else:
            ax.spines['left'].set_visible(False)
            ax.tick_params(left=False, labelleft=False)

    # legend below
    handles, labels = ax3.get_legend_handles_labels()
    fig.legend(
        handles, labels,
        loc='lower center',
        ncol=3,
        fontsize=14,
        frameon=True,
        bbox_to_anchor=(0.5, -0.20)
    )
    fig.text(0.5, 0.02, 'Rounds', ha='center', fontsize=16, fontweight="bold")

# Set global y-label
    fig.text(0.08, 0.5, 'Metrics', va='center', rotation='vertical', fontsize=16, fontweight="bold")
    plt.savefig(filename, bbox_inches='tight')
    plt.close(fig)



# 33% Attack group order
group33 = [
    'No Defense - Baseline',
    'Attack - 1 Node - ND33',
    'Attack - 3 Nodes - ND33',
    'Rate Limiting - 1 Node - ND33',
    'Rate Limiting - 3 Nodes - ND33',
    'Anycast - 1 Node - ND33',
    'Anycast - 3 Nodes - ND33',
    'All Defenses - 1 Node - ND33',
    'All Defenses - 3 Nodes - ND33',
]
plot_attack_group_horiz(group33, 'fl_33pct_attack_horiz.pdf', '(33% Nodes Attacked)')

# 66% Attack group order
group66 = [
    'No Defense - Baseline',
    'Attack - 1 Node - ND66',
    'Attack - 3 Nodes - ND66',
    'Rate Limiting - 1 Node - ND66',
    'Rate Limiting - 3 Nodes - ND66',
    'Anycast - 1 Node - ND66',
    'Anycast - 3 Nodes - ND66',
    'All Defenses - 1 Node - ND66',
    'All Defenses - 3 Nodes - ND66',
]
plot_attack_group_horiz(group66, 'fl_66pct_attack_horiz.pdf', '(66% Nodes Attacked)')

baseline_name = 'No Defense - Baseline'
baseline_time = scenarios[baseline_name]['time']

# Split scenarios into ND33 and ND66 (excluding baseline first)
nd33_scenarios = {k: v for k, v in scenarios.items() if 'ND33' in k}
nd66_scenarios = {k: v for k, v in scenarios.items() if 'ND66' in k}

# Add baseline to both
nd33_scenarios = {baseline_name: scenarios[baseline_name], **nd33_scenarios}
nd66_scenarios = {baseline_name: scenarios[baseline_name], **nd66_scenarios}

def plot_scenarios(scenarios_subset, title, filename, color_offset=0):
    fig, ax = plt.subplots(figsize=(12, 6))
    names = list(scenarios_subset.keys())
    times = [scenarios_subset[k]['time'] for k in names]
    
    bars = plt.bar(names, times, 
                   color=colors[color_offset:] * (len(names)//len(colors)+1), 
                   alpha=0.8)
    
    ax.set_xticks([])
    ax.set_xlabel('')
    ax.set_ylabel('Time (seconds)', fontsize=16)
    ax.grid(axis='y', linestyle='--', alpha=0.6)
    ax.tick_params(axis='y', labelsize=14)
    
    for bar in bars:
        h = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, h + 5,
                 f'{h:.2f}s', ha='center', va='bottom', fontsize=12)
    
    # plt.yticks(fontsize=14)

    # plt.set_xticks([])
    
    # Add legend manually below the plot
    handles = bars
    labels = names
    plt.legend(
        handles, labels,
        loc='lower center',
        ncol=3,
        fontsize=14,
        frameon=True,
        bbox_to_anchor=(0.5, -0.25)
    )

    # Add label for x-axis below the legend
    # plt.text(0.5, 0.02, 'Scenarios', ha='center', fontsize=16, fontweight="bold")

    # plt.tight_layout(rect=[0, 0.1, 1, 1])  # Leave space for legend
    plt.tight_layout()
    plt.savefig(filename, bbox_inches='tight')
    plt.show()

# Plot for ND33 scenarios
plot_scenarios(nd33_scenarios, 'Training Times - ND33 Scenarios', 'fl_training_times_nd33.pdf')

# Plot for ND66 scenarios
plot_scenarios(nd66_scenarios, 'Training Times - ND66 Scenarios', 'fl_training_times_nd66.pdf')

# # Finally: vertical bar chart of training times
# plt.figure(figsize=(12,8))
# names = list(scenarios.keys())
# times = [scenarios[k]['time'] for k in names]

# bars = plt.bar(names, times, color=colors * (len(names)//len(colors)+1), alpha=0.8)
# plt.ylabel('Time (seconds)', fontsize=16)
# plt.xticks(rotation=25, ha='right', fontsize=12)
# plt.grid(axis='y', ls='--', alpha=0.6)

# # annotate each bar
# for bar in bars:
#     h = bar.get_height()
#     plt.text(bar.get_x() + bar.get_width()/2, h + 5,
#              f'{h:.2f}s', ha='center', va='bottom', fontsize=12)
# plt.yticks(fontsize=14) 
# plt.tight_layout()
# plt.savefig('fl_training_times_vertical.pdf', bbox_inches='tight')
# plt.show()


# Greyscale
# import matplotlib.pyplot as plt
# import numpy as np

# names = list(scenarios.keys())
# times = [scenarios[k]['time'] for k in names]

# fig, ax = plt.subplots(figsize=(12,6))
# # pick N distinct greys
# N = len(names)
# greys = plt.cm.Greys_r(np.linspace(0.2, 0.8, N))

# bars = ax.bar(names, times, color=greys, edgecolor='black', linewidth=0.5)
# ax.set_ylabel('Time (seconds)', fontsize=14)
# ax.set_xticks(range(len(names)))
# ax.set_xticklabels(names, rotation=25, ha='right', fontsize=10)
# ax.grid(axis='y', linestyle='--', alpha=0.5)

# # annotate
# for bar in bars:
#     h = bar.get_height()
#     ax.text(bar.get_x()+bar.get_width()/2, h+5,
#             f'{h:.0f}s', ha='center', va='bottom', fontsize=10)

# plt.tight_layout()
# plt.show()

## Hatched
# import matplotlib.pyplot as plt

# names = list(scenarios.keys())
# times = [scenarios[k]['time'] for k in names]

# hatches = ['/', '\\', '|', '-', '+', 'x', 'o', 'O', '.'] * ((len(names)//9)+1)

# fig, ax = plt.subplots(figsize=(12,6))
# bars = []
# for i,(name,t) in enumerate(zip(names,times)):
#     b = ax.bar(i, t,
#                color='white',
#                edgecolor='black',
#                hatch=hatches[i],
#                linewidth=0.8)
#     bars.append(b)

# ax.set_ylabel('Time (seconds)', fontsize=14)
# ax.set_xticks(range(len(names)))
# ax.set_xticklabels(names, rotation=25, ha='right', fontsize=10)
# ax.grid(axis='y', linestyle='--', alpha=0.5)

# # annotate
# for bar in bars:
#     h = bar[0].get_height()
#     ax.text(bar[0].get_x()+bar[0].get_width()/2, h+5,
#             f'{h:.0f}s', ha='center', va='bottom', fontsize=10)

# plt.tight_layout()
# plt.show()

