import argparse
import ipaddress
from multiprocessing import parent_process
import os
import sys
import errno
import pandas as pd
import numpy as np
import flwr as fl
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.metrics import f1_score
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, Conv1D, MaxPooling1D, LSTM, GRU, Flatten
from typing import Dict


# Function to parse command line arguments
def parse_args():
    parser = argparse.ArgumentParser(description='Flower aggregator server implementation')
    parser.add_argument("-a", "--address", help="IP address", default="0.0.0.0")
    parser.add_argument("-p", "--port", help="Serving port", default=8000, type=int)
    parser.add_argument("-r", "--rounds", help="Number of training and aggregation rounds", default=1, type=int)
    parser.add_argument("-d", "--dataset", help="dataset directory", default="../federated_datasets/")
    return parser.parse_args()


# Function to check IP address and port validity
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


# Load and preprocess the dataset
def load_and_preprocess_data(dataset_dir):
    # df = pd.read_csv(os.path.join(dataset_dir, 'combined_edgeIIot_500k_custom_DDos.csv'), low_memory=False)
    df = pd.read_csv(os.path.join(dataset_dir, 'Preprocessed_shuffled_train_data.csv'), low_memory=False)
    df.drop(columns=['Unnamed: 0'], inplace=True)

    
    # Map attack types to numeric labels
    attacks = {'Normal': 0, 'MITM': 1, 'Uploading': 2, 'Ransomware': 3, 'SQL_injection': 4,
               'DDoS_HTTP': 5, 'DDoS_TCP': 6, 'Password': 7, 'Port_Scanning': 8,
               'Vulnerability_scanner': 9, 'Backdoor': 10, 'XSS': 11, 'Fingerprinting': 12,
               'DDoS_UDP': 13, 'DDoS_ICMP': 14}
    
    df['Attack_type'] = df['Attack_type'].map(attacks)
    
    X = df.drop(columns=['Attack_label', 'Attack_type'])
    y = df['Attack_label']
    
    # Feature selection using Chi-squared test
    chi_selector = SelectKBest(chi2, k='all')
    X_kbest = chi_selector.fit_transform(X, y)
    chi_scores = chi_selector.scores_
    
    # Combine scores with feature names and sort
    chi_scores = pd.DataFrame({'feature': X.columns, 'score': chi_scores}).sort_values(by='score', ascending=False)
    
    selected_features = chi_scores['feature'].tolist()
    
    # Split data into training and testing sets
    train_set = df[selected_features + ['Attack_label', 'Attack_type']]
    test_set = df[selected_features + ['Attack_label', 'Attack_type']][49990:]
    directory = os.path.join('../federated_datasets')
    try:
        os.makedirs(directory)
        train_set.to_csv(os.path.join(directory, 'train_data.csv'), index=False)
        test_set.to_csv(os.path.join(directory, 'test_data.csv'), index=False)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise
        else:   
            train_set.to_csv(os.path.join(directory, 'train_data.csv'), index=False)
            test_set.to_csv(os.path.join(directory, 'test_data.csv'), index=False)
    
    return train_set, test_set


# Function to distribute data across clients
def distribute_data(train_set, n_workers=3):
    directory = '../federated_datasets'
    os.makedirs(directory, exist_ok=True)
    
    n_samples = int(train_set.shape[0] / n_workers)
    client_data = []
    train_copy = train_set.copy()
    
    fig, axes = plt.subplots(1, n_workers, figsize=(20, 6), sharey=True)
    for i in range(n_workers):
        sample = train_copy.sample(n=n_samples)
        sample.to_csv(os.path.join(directory, f'client_train_data_{i+1}.csv'), index=False)
        train_copy.drop(index=sample.index, inplace=True)
        client_data.append(sample)
        attacks = {'Normal': 0,'MITM': 1, 'Uploading': 2, 'Ransomware': 3, 'SQL_injection': 4,
       'DDoS_HTTP': 5, 'DDoS_TCP': 6, 'Password': 7, 'Port_Scanning': 8,
       'Vulnerability_scanner': 9, 'Backdoor': 10, 'XSS': 11, 'Fingerprinting': 12,
       'DDoS_UDP': 13, 'DDoS_ICMP': 14}
        # Reverse attack mapping for visualization
        reverse_attacks = {v: k for k, v in attacks.items()}
        sample['Attack_type'] = sample['Attack_type'].map(reverse_attacks)
        
        # Plot distribution of attack types
        attack_counts_df = sample['Attack_type'].value_counts().reset_index()
        attack_counts_df.columns = ['Attack Type', 'Count']
        
        ax = sns.barplot(x='Attack Type', y='Count', data=attack_counts_df, ax=axes[i], palette='viridis')
        axes[i].set_title(f'Attack Counts for client{i+1}', fontsize=14)
        axes[i].set_xlabel('Attack Type', fontsize=12)
        axes[i].set_ylabel('Count', fontsize=12)
        axes[i].tick_params(axis='x', rotation=75, labelsize=8)
        
        # Show exact values on bars
        for p in ax.patches:
            ax.annotate(f'{int(p.get_height())}', (p.get_x() + p.get_width() / 2., p.get_height()),
                        xytext=(0, 10), textcoords='offset points', ha='center', va='bottom', fontsize=8)
    
    plt.tight_layout()
    plt.savefig('attack_type_distribution.png', bbox_inches='tight')
    plt.close()
    
    return client_data


# Function to create CNN-LSTM-GRU model
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
        Dense(num_classes, activation='sigmoid')
    ])
    
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model


def fit_round(server_round: int) -> Dict:
	"""Send round number to client."""
	return {"server_round": server_round}

# Evaluation function for federated learning
def get_evaluate_fn(model, X_test, y_test):
    def evaluate(server_round, parameters, config):
        model.set_weights(parameters)
        loss, accuracy = model.evaluate(X_test, y_test, batch_size=32)
        f1 = f1_score(y_test, np.argmax(model.predict(X_test), axis=1), average='weighted')
        return loss, {"accuracy": accuracy, "f1-score": f1}
    
    return evaluate

from flwr.common import FitIns, Parameters

class CustomFedAvg(fl.server.strategy.FedAvg):
    new_results = []
    bad_clients = []
    def aggregate_evaluate(self, rnd, results, failures):
        """Filter out clients where intrusion detection rate > 70%"""
        print(rnd, results, failures)
        for client, eval_res in results:  # Unpack properly
            metrics = eval_res.metrics  # Extract metrics from EvaluateRes

            if metrics.get("high_intrusion", False):  # Safely get the boolean value
                # self.new_results.append((eval_res.parameters, eval_res.num_examples, metrics))
                self.bad_clients.append(client.cid)
                print(f"⚠️ Client {client.cid} exceeds 70% intrusion detection. Removing from next rounds.")
            else:
                self.new_results.append((client, eval_res))  

        return super().aggregate_evaluate(rnd, self.new_results, failures)

    def configure_fit(self, server_round, parameters, client_manager):
        """Modify client selection to exclude flagged clients"""
        clients = client_manager.sample(num_clients=3)  # Sample 5 clients
        available_clients = [c for c in clients if c.cid not in self.bad_clients]
        fit_ins = FitIns(Parameters(tensors=parameters.tensors, tensor_type="numpy"), {})
        
        return [(client, fit_ins) for client in available_clients]  # Correct format

# Apply CustomFedAvg Strategy


# Function to set up and start the federated learning server
def start_federated_learning_server(args, model, X_test, y_test):
    # strategy = fl.server.strategy.FedAvg(
    #     min_available_clients=3,
    #     evaluate_fn=get_evaluate_fn(model, X_test, y_test),
    #     on_fit_config_fn=fit_round,
    # )
    strategy = CustomFedAvg(
    fraction_fit=0.5,  # Select 50% of clients per round
    min_fit_clients=2,
    min_evaluate_clients=2,
    min_available_clients=2,
    evaluate_fn=get_evaluate_fn(model, X_test, y_test),
    on_fit_config_fn=fit_round,
)
    fl.server.start_server(
        server_address=f"{args.address}:{args.port}",
        strategy=strategy,
        config=fl.server.ServerConfig(num_rounds=args.rounds),
    )


# Main function to orchestrate the entire process
def main():
    args = parse_args()
    validate_args(args)
    
    # Load and preprocess data
    train_set, test_set = load_and_preprocess_data(args.dataset)
    
    # Distribute data across clients
    client_data = distribute_data(train_set)
    
    # Prepare data for model training
    X = train_set.drop(columns=['Attack_label', 'Attack_type'])
    y = train_set['Attack_label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    X_train, X_val, y_train, y_val = train_test_split(X_train, y_train, test_size=0.125, random_state=42)
    
    # Scale the data
    scaler = StandardScaler().fit(X_train)
    X_train = scaler.transform(X_train)
    X_val = scaler.transform(X_val)
    X_test = scaler.transform(X_test)
    
    # Create model
    input_shape = (X_test.shape[1], 1)
    model = cnn_lstm_gru_model(input_shape, num_classes=1)
    model.summary()
    
    # Start federated learning server
    start_federated_learning_server(args, model, X_test, y_test)


if __name__ == "__main__":
    main()


# /Applications/Wireshark.app/Contents/MacOS/tshark -r ddos_http_attack.pcap -c 5000 -T fields \
#   -e frame.time \
#   -e ip.src_host \
#   -e ip.dst_host \
#   -e arp.dst.proto_ipv4 \
#   -e arp.opcode \
#   -e arp.hw.size \
#   -e arp.src.proto_ipv4 \
#   -e icmp.checksum \
#   -e icmp.seq_le \
#   -e icmp.transmit_timestamp \
#   -e icmp.unused \
#   -e http.file_data \
#   -e http.content_length \
#   -e http.request.uri.query \
#   -e http.request.method \
#   -e http.referer \
#   -e http.request.full_uri \
#   -e http.request.version \
#   -e http.response \
#   -e http.tls_port \
#   -e tcp.ack \
#   -e tcp.ack_raw \
#   -e tcp.checksum \
#   -e tcp.connection.fin \
#   -e tcp.connection.rst \
#   -e tcp.connection.syn \
#   -e tcp.connection.synack \
#   -e tcp.dstport \
#   -e tcp.flags \
#   -e tcp.flags.ack \
#   -e tcp.len \
#   -e tcp.options \
#   -e tcp.payload \
#   -e tcp.seq \
#   -e tcp.srcport \
#   -e udp.port \
#   -e udp.stream \
#   -e udp.time_delta \
#   -e dns.qry.name \
#   -e dns.qry.name.len \
#   -e dns.qry.qu \
#   -e dns.qry.type \
#   -e dns.retransmission \
#   -e dns.retransmit_request \
#   -e dns.retransmit_request_in \
#   -e mqtt.conack.flags \
#   -e mqtt.conflag.cleansess \
#   -e mqtt.conflags \
#   -e mqtt.hdrflags \
#   -e mqtt.len \
#   -e mqtt.msg_decoded_as \
#   -e mqtt.msg \
#   -e mqtt.msgtype \
#   -e mqtt.proto_len \
#   -e mqtt.protoname \
#   -e mqtt.topic \
#   -e mqtt.topic_len \
#   -e mqtt.ver \
#   -e mbtcp.len \
#   -e mbtcp.trans_id \
#   -e mbtcp.unit_id \
#   -E header=y -E separator=, -E quote=d > ddos_icmp_attack.csv
