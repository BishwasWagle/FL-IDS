import argparse
import ipaddress
import os
import sys
import time

import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

from typing import Dict
from sklearn.metrics import f1_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, Conv1D, MaxPooling1D, Flatten, LSTM, GRU
import flwr as fl

def cnn_lstm_gru_model(input_shape, num_classes):
    model = Sequential([
        Conv1D(filters=32, kernel_size=3, activation='relu', input_shape=input_shape),        
        MaxPooling1D(pool_size=2),
        
        Conv1D(filters=64, kernel_size=3, activation='relu'),
        MaxPooling1D(pool_size=2),
        
        LSTM(64, return_sequences=True),
        GRU(64, return_sequences=False),
        
        Flatten(),
        
        Dense(128, activation='relu'),
        Dropout(0.5),
        Dense(num_classes, activation='softmax')
    ])
    model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
    return model

def plot_metrics(history, state):
    """Plot training and validation accuracy and loss."""
    plt.figure()
    plt.plot(history.history['accuracy'])
    plt.plot(history.history['val_accuracy'])
    plt.title('Model Accuracy')
    plt.ylabel('Accuracy')
    plt.xlabel('Epoch')
    plt.legend(['Train', 'Test'], loc='upper left')
    plt.savefig(f'../../results/federated/multiclass/accuracy_plot_{state}.jpg')
    plt.close()
    
    plt.figure()
    plt.plot(history.history['loss'])
    plt.plot(history.history['val_loss'])
    plt.title('Model Loss')
    plt.ylabel('Loss')
    plt.xlabel('Epoch')
    plt.legend(['Train', 'Test'], loc='upper left')
    plt.savefig(f'../../results/federated/multiclass/loss_plot_{state}.jpg')
    plt.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Flower straggler / client implementation')
    parser.add_argument("-a", "--address", help="Aggregator server's IP address", default="127.0.0.1")
    parser.add_argument("-p", "--port", help="Aggregator server's serving port", default=8000, type=int)
    parser.add_argument("-i", "--id", help="client ID", default=1, type=int)
    parser.add_argument("-d", "--dataset", help="dataset directory", default="../federated_datasets/")
    args = parser.parse_args()

    try:
        ipaddress.ip_address(args.address)
    except ValueError:
        sys.exit(f"Wrong IP address: {args.address}")
    if args.port < 0 or args.port > 65535:
        sys.exit(f"Wrong serving port: {args.port}")
    if not os.path.isdir(args.dataset):
        sys.exit(f"Wrong path to directory with datasets: {args.dataset}")

    os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

    # Load train and test data
    df_train = pd.read_csv(os.path.join(args.dataset, f'client_train_data_{args.id}.csv'))
    df_test = pd.read_csv(os.path.join(args.dataset, 'test_data.csv'))

    X = df_train.drop(columns=['Attack_label', 'Attack_type'])
    y = df_train['Attack_type']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    X_train, X_val, y_train, y_val = train_test_split(X_train, y_train, test_size=0.125, random_state=42)

    scaler = StandardScaler().fit(X_train)
    X_train = scaler.transform(X_train)
    X_val = scaler.transform(X_val)
    X_test = scaler.transform(X_test)

    input_shape = (X_test.shape[1], 1)
    num_classes = 15
    model = cnn_lstm_gru_model(input_shape, num_classes)
    model.summary()
    attacks = {'Normal': 0, 'MITM': 1, 'Uploading': 2, 'Ransomware': 3, 'SQL_injection': 4,
               'DDoS_HTTP': 5, 'DDoS_TCP': 6, 'Password': 7, 'Port_Scanning': 8,
               'Vulnerability_scanner': 9, 'Backdoor': 10, 'XSS': 11, 'Fingerprinting': 12,
               'DDoS_UDP': 13, 'DDoS_ICMP': 14}

    class Client(fl.client.NumPyClient):
        def get_parameters(self, config):
            return model.get_weights()

        def fit(self, parameters, config):
            model.set_weights(parameters)
            train_start_time = time.time()
            history = model.fit(X_train, y_train, validation_data=(X_val, y_val), epochs=6, batch_size=32)
            train_end_time = time.time()
            print(f"Training time: {train_end_time - train_start_time:.2f} seconds")
            return model.get_weights(), len(X_train), {}

        def evaluate(self, parameters: fl.common.NDArrays, config: Dict[str, fl.common.Scalar]):
            model.set_weights(parameters)
            test_start_time = time.time()
            loss, accuracy = model.evaluate(X_test, y_test, batch_size=32)

            y_pred = model.predict(np.expand_dims(X_test, axis=2))
            y_pred_classes = np.argmax(y_pred, axis=1)
        
            f1 = f1_score(y_test, y_pred_classes, average='weighted')
            test_end_time = time.time()
            print(f"Testing time: {test_end_time - test_start_time:.2f} seconds")
            # print(classification_report(y_test, np.round(y_pred), target_names=['No Intrusion', 'Intrusion']))
            # conf_mat = confusion_matrix(y_test, np.round(y_pred))
            
            inverse_attacks = {v: k for k, v in attacks.items()}

            # if state == 'test':
            unique_classes = np.unique(y_pred_classes)
            class_names_ordered = [inverse_attacks[i] for i in unique_classes]
            print(unique_classes,"^^^^^^^^^^^^^^^")
            print(class_names_ordered, "&&&&&&&&&&&&&")
            print(y_pred_classes)
            class_names_ordered = [attack for attack, number in sorted(attacks.items(), key=lambda item: item[1])]
            print(class_names_ordered)

            cm = confusion_matrix(y_test, y_pred_classes)

            plt.figure(figsize=(15, 10))
            sns.heatmap(
                cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=class_names_ordered,
                yticklabels=class_names_ordered
                )
            plt.xlabel('Predicted Label')
            plt.ylabel('True Label')
            plt.title('Confusion Matrix')
            plt.savefig(f'../../results/federated/multiclass/confusion_matrix_{args.id}.jpg')
            plt.close()

            cm_norm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
            plt.figure(figsize=(15, 10))
            sns.heatmap(cm_norm, annot=True, cmap='Blues', xticklabels=class_names_ordered, yticklabels=class_names_ordered, fmt='.2%')
            plt.xlabel('Predicted labels')
            plt.ylabel('True labels')
            plt.title('Normalized Confusion Matrix as Percentages')
            plt.savefig(f'../../results/federated/multiclass/con_percent_client{args.id}.jpg')
            plt.close()
            
            return loss, len(X_test), {"accuracy": accuracy, "f1_score": f1}
    
    fl.client.start_numpy_client(server_address=f"{args.address}:{args.port}", client=Client())
