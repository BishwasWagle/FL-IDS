# FL-IDS: Federated Learning Intrusion Detection System for Drone Swarms

This repository contains the code and experimental artifacts for **FL-IDS**, a hybrid deep learning-based Intrusion Detection System (IDS) integrated with a Federated Learning (FL) framework. The system is designed to detect and mitigate network-level attacks such as DDoS in drone swarms operating in adversarial edge environments like AERPAW.

---

## Overview

The project implements a **hybrid CNN–LSTM–GRU model** trained on a customized dataset combining:
- The [Edge-IIoT Dataset](https://www.kaggle.com/datasets/sibasispradhan/edge-iiotset-dataset)
- Real-world DDoS and SQL injection attack traffic collected on the **AERPAW testbed**

The IDS is trained both in **centralized** and **federated settings**, and evaluated under normal, mildly congested (33%), and severely congested (66%) network scenarios.


## Dataset Details

### Edge-IIoT Dataset
- Protocols: ARP, ICMP, HTTP, TCP, UDP, DNS, MQTT, Modbus
- Labels: Binary (Attack/Normal), Multi-class (15+ attack types)
- Feature engineering includes label encoding, one-hot encoding, chi-squared feature selection, and scaling.

### AERPAW Attack Dataset
- Captured attacks: `DDoS_TCP`, `DDoS_UDP`, `DDoS_ICMP`, `DDoS_HTTP`
- Preprocessing includes categorical encoding, duplicate removal, and merge with Edge-IIoT.

---

## Model Architecture

- **Conv1D + MaxPooling**: Feature extraction
- **LSTM + GRU**: Captures long- and short-term temporal patterns
- **Dense + Dropout**: Regularized classification layer

### Configuration:
| Parameter              | Value           |
|------------------------|-----------------|
| Epochs                 | 6               |
| Batch Size             | 32              |
| Optimizer              | Adam            |
| Loss (Binary)          | Binary CrossEntropy |
| Loss (Multiclass)      | Sparse Categorical CrossEntropy |
| Output Activation      | Sigmoid / Softmax |
| Sequence Shape         | (samples, time_steps, features) |

---

## Experiments

### Goals:
- Detect and Mitigate DDoS & GPS spoofing (network-level)
- Evaluate performance under 33% and 66% attack intensities

### Environment:
- **AERPAW Testbed**
- Simulated portable drones + aggregator node
- Network tools: `iperf3`, `tc`, `hping3`

---

## Evaluation Metrics

| Metric Type   | Metrics                        |
|---------------|--------------------------------|
| Model         | Accuracy, Precision, Recall, F1 |
| System        | CPU usage, Training Time, Memory |
| Network       | Bandwidth, RTT, Packet Loss, Attack Recovery Time |

---

## Defense Mechanisms

### Model-Level:
- Differential Privacy (DP)
- Adversarial Training (AT)
- Federated Learning

### Network-Level:
- Hierarchical Token Bucket (HTB) Rate Limiting
- Anycast + DNAT with `iptables`
- Geometric Trajectory Validation for GPS Spoofing

---

## Results Snapshot

- **Binary Classification Accuracy (FL):** ~0.99
- **Multiclass Precision/Recall (centralized):** 0.93–0.97
- **DDoS Traffic Detection:** >94% accuracy under realistic conditions
- **Federated Recovery:** Maintained accuracy even with 1–3 poisoned nodes

---

## How to Run

```bash
# Clone repository
git clone https://github.com/BishwasWagle/FL-IDS.git && cd FL-IDS

# Install dependencies
pip install -r requirements.txt

# Run centralized model
python model/train_centralized.py

# Launch federated server
python federated/server.py

# Launch federated clients (on different terminals or nodes)
python federated/client.py --client_id=1
