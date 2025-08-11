import argparse
import ipaddress
import os
import sys
import time
from typing import Dict

import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

from sklearn.metrics import f1_score, classification_report, confusion_matrix, recall_score, precision_score
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

import flwr as fl

from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, Conv1D, MaxPooling1D, Flatten, LSTM, GRU, Input

# ----------------------------
# Label maps
# ----------------------------
ATTACKS = {
    "Normal": 0, "MITM": 1, "Uploading": 2, "Ransomware": 3, "SQL_injection": 4,
    "DDoS_HTTP": 5, "DDoS_TCP": 6, "Password": 7, "Port_Scanning": 8,
    "Vulnerability_scanner": 9, "Backdoor": 10, "XSS": 11, "Fingerprinting": 12,
    "DDoS_UDP": 13, "DDoS_ICMP": 14,
}
INV_ATTACKS = {v: k for k, v in ATTACKS.items()}

# ----------------------------
# Model
# ----------------------------
def cnn_lstm_gru_model(input_shape, num_classes):
    model = Sequential([
        Input(shape=input_shape),
        Conv1D(filters=32, kernel_size=3, activation="relu"),
        MaxPooling1D(pool_size=2),

        Conv1D(filters=64, kernel_size=3, activation="relu"),
        MaxPooling1D(pool_size=2),

        LSTM(64, return_sequences=True),
        GRU(64, return_sequences=False),

        Flatten(),
        Dense(128, activation="relu"),
        Dropout(0.5),
        Dense(num_classes, activation="softmax"),
    ])
    model.compile(optimizer="adam", loss="sparse_categorical_crossentropy", metrics=["accuracy"])
    return model

def plot_metrics(history, state):
    os.makedirs("../../results/federated/multiclass", exist_ok=True)

    plt.figure()
    plt.plot(history.history["accuracy"])
    plt.plot(history.history["val_accuracy"])
    plt.title("Model Accuracy")
    plt.ylabel("Accuracy")
    plt.xlabel("Epoch")
    plt.legend(["Train", "Val"], loc="upper left")
    plt.savefig(f"../../results/federated/multiclass/accuracy_plot_{state}.jpg")
    plt.close()

    plt.figure()
    plt.plot(history.history["loss"])
    plt.plot(history.history["val_loss"])
    plt.title("Model Loss")
    plt.ylabel("Loss")
    plt.xlabel("Epoch")
    plt.legend(["Train", "Val"], loc="upper left")
    plt.savefig(f"../../results/federated/multiclass/loss_plot_{state}.jpg")
    plt.close()

# ----------------------------
# Main
# ----------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Flower client (multiclass)")
    parser.add_argument("-a", "--address", help="Aggregator server's IP address", default="127.0.0.1")
    parser.add_argument("-p", "--port", help="Aggregator server's serving port", default=8000, type=int)
    parser.add_argument("-i", "--id", help="client ID", default=1, type=int)
    parser.add_argument("-d", "--dataset", help="dataset directory", default="../federated_datasets/")
    args = parser.parse_args()

    # Basic validation
    try:
        ipaddress.ip_address(args.address)
    except ValueError:
        sys.exit(f"Wrong IP address: {args.address}")
    if args.port < 0 or args.port > 65535:
        sys.exit(f"Wrong serving port: {args.port}")
    if not os.path.isdir(args.dataset):
        sys.exit(f"Wrong path to directory with datasets: {args.dataset}")

    os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

    # Load train (client-specific) and global test
    df_train = pd.read_csv(os.path.join(args.dataset, f"client_train_data_{args.id}.csv"))
    df_test  = pd.read_csv(os.path.join(args.dataset, "test_data.csv"))

    # Ensure Attack_type numeric on both frames
    for df_ in (df_train, df_test):
        if "Unnamed: 0" in df_.columns:
            df_.drop(columns=["Unnamed: 0"], inplace=True)
        if df_["Attack_type"].dtype == "O":
            df_["Attack_type"] = df_["Attack_type"].map(ATTACKS)
        df_["Attack_type"] = pd.to_numeric(df_["Attack_type"], errors="coerce").astype("Int64")
        df_.dropna(subset=["Attack_type"], inplace=True)
        df_["Attack_type"] = df_["Attack_type"].astype(int)

    # Supervised split on multiclass label
    X_full = df_train.drop(columns=["Attack_label", "Attack_type"])
    y_full = df_train["Attack_type"].astype(int)

    X_train, X_hold, y_train, y_hold = train_test_split(X_full, y_full, test_size=0.2, random_state=42)
    X_train, X_val,  y_train, y_val  = train_test_split(X_train, y_train, test_size=0.125, random_state=42)

    # Scale + expand dims for Conv1D (N, F, 1)
    scaler = StandardScaler().fit(X_train)
    X_train = np.expand_dims(scaler.transform(X_train), axis=2)
    X_val   = np.expand_dims(scaler.transform(X_val),   axis=2)
    X_hold  = np.expand_dims(scaler.transform(X_hold),  axis=2)

    input_shape = (X_train.shape[1], 1)
    num_classes = 15
    model = cnn_lstm_gru_model(input_shape, num_classes)
    model.summary()

    class Client(fl.client.NumPyClient):
        def get_parameters(self, config):
            return model.get_weights()

        def fit(self, parameters, config):
            model.set_weights(parameters)
            train_start_time = time.time()
            history = model.fit(
                X_train,
                y_train,
                validation_data=(X_val, y_val),
                epochs=6,
                batch_size=32,
                verbose=1,
            )
            plot_metrics(history, args.id)
            print(f"Training time: {time.time() - train_start_time:.2f} seconds")
            return model.get_weights(), len(X_train), {}

        def evaluate(self, parameters: fl.common.NDArrays, config: Dict[str, fl.common.Scalar]):
            model.set_weights(parameters)
            test_start_time = time.time()

            # Align test columns to training columns and scale
            X_test_df = df_test.drop(columns=["Attack_label", "Attack_type"]).copy()
            train_cols = df_train.drop(columns=["Attack_label", "Attack_type"]).columns
            X_test_df = X_test_df[train_cols]

            X_test = np.expand_dims(scaler.transform(X_test_df), axis=2)
            y_test = df_test["Attack_type"].astype(int)

            loss, accuracy = model.evaluate(X_test, y_test, batch_size=32, verbose=1)

            y_pred = model.predict(X_test, verbose=0)
            y_pred_classes = np.argmax(y_pred, axis=1)

            f1        = f1_score(y_test, y_pred_classes, average="weighted")
            precision = precision_score(y_test, y_pred_classes, average="weighted")
            recall    = recall_score(y_test, y_pred_classes, average="weighted")

            # Confusion matrices
            os.makedirs("../../results/federated/multiclass", exist_ok=True)
            class_names_ordered = [INV_ATTACKS[i] for i in range(num_classes)]

            conf_mat = confusion_matrix(y_test, y_pred_classes, labels=list(range(num_classes)))
            plt.figure(figsize=(10, 8))
            sns.heatmap(conf_mat, annot=True, fmt="d", cmap="Blues",
                        xticklabels=class_names_ordered, yticklabels=class_names_ordered)
            plt.xlabel("Predicted")
            plt.ylabel("True")
            plt.title("Confusion Matrix")
            plt.tight_layout()
            plt.savefig(f"../../results/federated/multiclass/con_max_client{args.id}.jpg")
            plt.close()

            cm_norm = conf_mat.astype("float") / np.maximum(conf_mat.sum(axis=1)[:, np.newaxis], 1)
            plt.figure(figsize=(10, 8))
            sns.heatmap(cm_norm, annot=True, cmap="Blues",
                        xticklabels=class_names_ordered, yticklabels=class_names_ordered, fmt=".2f")
            plt.xlabel("Predicted")
            plt.ylabel("True")
            plt.title("Normalized Confusion Matrix")
            plt.tight_layout()
            plt.savefig(f"../../results/federated/multiclass/con_percent_client{args.id}.jpg")
            plt.close()

            print(f"Testing time: {time.time() - test_start_time:.2f} seconds")
            return loss, len(X_test), {
                "accuracy": float(accuracy),
                "f1_score": float(f1),
                "recall": float(recall),
                "precision": float(precision),
            }

    # Start client (note: API is deprecated in newer Flower—OK for now)
    fl.client.start_client(
        server_address=f"{args.address}:{args.port}",
        client=Client().to_client(),
    )
