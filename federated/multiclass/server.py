import argparse
import ipaddress
import os
import sys
import errno
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import SelectKBest, chi2

import flwr as fl

# ----------------------------
# CLI
# ----------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Flower aggregator server implementation (multiclass)")
    parser.add_argument("-a", "--address", help="IP address", default="0.0.0.0")
    parser.add_argument("-p", "--port", help="Serving port", default=8000, type=int)
    parser.add_argument("-r", "--rounds", help="Number of training and aggregation rounds", default=1, type=int)
    parser.add_argument("-d", "--dataset", help="dataset directory", default="../federated_datasets/")
    return parser.parse_args()

def validate_args(args):
    try:
        ipaddress.ip_address(args.address)
    except ValueError:
        sys.exit(f"Wrong IP address: {args.address}")
    if args.port < 0 or args.port > 65535:
        sys.exit(f"Wrong serving port: {args.port}")
    if args.rounds < 0:
        sys.exit(f"Wrong number of rounds: {args.rounds}")
    if not os.path.isdir(args.dataset):
        sys.exit(f"Wrong path to directory with datasets: {args.dataset}")

# ----------------------------
# Data prep
# ----------------------------
ATTACKS = {
    "Normal": 0, "MITM": 1, "Uploading": 2, "Ransomware": 3, "SQL_injection": 4,
    "DDoS_HTTP": 5, "DDoS_TCP": 6, "Password": 7, "Port_Scanning": 8,
    "Vulnerability_scanner": 9, "Backdoor": 10, "XSS": 11, "Fingerprinting": 12,
    "DDoS_UDP": 13, "DDoS_ICMP": 14,
}
INV_ATTACKS = {v: k for k, v in ATTACKS.items()}

def load_and_preprocess_data(dataset_dir: str) -> Tuple[pd.DataFrame, pd.DataFrame]:
    df = pd.read_csv(os.path.join(dataset_dir, "Preprocessed_shuffled_train_data.csv"), low_memory=False)
    if "Unnamed: 0" in df.columns:
        df.drop(columns=["Unnamed: 0"], inplace=True)

    # Ensure Attack_type is numeric 0..14
    if df["Attack_type"].dtype == "O":
        df["Attack_type"] = df["Attack_type"].map(ATTACKS)
    df["Attack_type"] = pd.to_numeric(df["Attack_type"], errors="coerce").astype("Int64")
    df = df.dropna(subset=["Attack_type"]).copy()
    df["Attack_type"] = df["Attack_type"].astype(int)

    # Feature selection wrt multiclass target
    X_all = df.drop(columns=["Attack_label", "Attack_type"])
    y_all = df["Attack_type"]
    chi_selector = SelectKBest(chi2, k="all")
    chi_selector.fit_transform(X_all, y_all)
    chi_scores = pd.DataFrame({"feature": X_all.columns, "score": chi_selector.scores_}).sort_values(
        by="score", ascending=False
    )
    selected_features = chi_scores["feature"].tolist()

    # Persist train/test for clients
    train_set = df[selected_features + ["Attack_label", "Attack_type"]]
    test_set = df[selected_features + ["Attack_label", "Attack_type"]][49990:]  # keep your original slicing

    out_dir = os.path.join("../federated_datasets")
    try:
        os.makedirs(out_dir)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise
    train_set.to_csv(os.path.join(out_dir, "train_data.csv"), index=False)
    test_set.to_csv(os.path.join(out_dir, "test_data.csv"), index=False)

    return train_set, test_set

def distribute_data(train_set: pd.DataFrame, n_workers: int = 2) -> List[pd.DataFrame]:
    directory = "../federated_datasets"
    os.makedirs(directory, exist_ok=True)
    n_samples = int(train_set.shape[0] / n_workers)
    client_data = []
    train_copy = train_set.copy()

    fig, axes = plt.subplots(1, n_workers, figsize=(20, 6), sharey=True)
    for i in range(n_workers):
        sample = train_copy.sample(n=n_samples)
        sample.to_csv(os.path.join(directory, f"client_train_data_{i+1}.csv"), index=False)
        train_copy.drop(index=sample.index, inplace=True)
        client_data.append(sample)

        # Plot distribution
        sample_vis = sample.copy()
        sample_vis["Attack_type"] = sample_vis["Attack_type"].map(INV_ATTACKS)
        attack_counts_df = sample_vis["Attack_type"].value_counts().reset_index()
        attack_counts_df.columns = ["Attack Type", "Count"]
        ax = sns.barplot(x="Attack Type", y="Count", data=attack_counts_df, ax=axes[i])
        axes[i].set_title(f"Attack Counts for client {i+1}", fontsize=12)
        axes[i].tick_params(axis="x", rotation=75, labelsize=8)

        for p in ax.patches:
            ax.annotate(f"{int(p.get_height())}", (p.get_x() + p.get_width()/2., p.get_height()),
                        xytext=(0, 10), textcoords="offset points", ha="center", va="bottom", fontsize=8)

    plt.tight_layout()
    plt.savefig("attack_type_distribution.png", bbox_inches="tight")
    plt.close()
    return client_data

# ----------------------------
# FL strategy (keep defaults; weighted eval)
# ----------------------------
class CustomFedAvg(fl.server.strategy.FedAvg):
    def aggregate_evaluate(self, rnd, results, failures):
        if not results:
            return None
        total_samples = 0
        total_loss = 0.0
        metrics_accum = {"accuracy": 0.0, "f1_score": 0.0, "precision": 0.0, "recall": 0.0}

        for client, eval_res in results:
            num_examples = eval_res.num_examples
            total_samples += num_examples
            total_loss += (eval_res.loss or 0.0) * num_examples
            for k in metrics_accum:
                if k in eval_res.metrics:
                    metrics_accum[k] += float(eval_res.metrics[k]) * num_examples

        avg_loss = total_loss / max(total_samples, 1)
        avg_metrics = {k: (v / max(total_samples, 1)) for k, v in metrics_accum.items()}

        print(f"[Round {rnd}] Weighted aggregated metrics: {avg_metrics}")
        return avg_loss, avg_metrics

def fit_round(server_round: int) -> Dict:
    return {"server_round": server_round}

def start_federated_learning_server(args):
    strategy = CustomFedAvg(
        fraction_fit=1.0,
        min_fit_clients=2,
        min_evaluate_clients=2,
        min_available_clients=2,
        on_fit_config_fn=fit_round,
    )
    fl.server.start_server(
        server_address=f"{args.address}:{args.port}",
        strategy=strategy,
        config=fl.server.ServerConfig(num_rounds=args.rounds),
    )

def main():
    args = parse_args()
    validate_args(args)

    train_set, test_set = load_and_preprocess_data(args.dataset)
    _ = distribute_data(train_set, n_workers=2)

    # The server does not need the model here since we're relying on client-side eval.
    start_federated_learning_server(args)

if __name__ == "__main__":
    main()
