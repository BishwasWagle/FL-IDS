import pandas as pd
import numpy as np
import time
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.feature_selection import SelectKBest, chi2
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from keras.models import Sequential
from keras.layers import Dense, Dropout, Conv1D, MaxPooling1D, Flatten, LSTM, GRU
from tensorflow.keras.optimizers import Adam
from sklearn.metrics import classification_report, confusion_matrix
from tensorflow.keras.utils import plot_model
from tensorflow.keras.models import load_model

def load_and_preprocess_data(file_path):
    """Load dataset and preprocess it by mapping attack types and selecting features."""
    df = pd.read_csv(file_path, low_memory=False)
    # df.drop(columns=['Unnamed: 0'], inplace=True)
    
    # Mapping attack types to numerical labels
    attacks = {'Normal': 0, 'MITM': 1, 'Uploading': 2, 'Ransomware': 3, 'SQL_injection': 4,
               'DDoS_HTTP': 5, 'DDoS_TCP': 6, 'Password': 7, 'Port_Scanning': 8,
               'Vulnerability_scanner': 9, 'Backdoor': 10, 'XSS': 11, 'Fingerprinting': 12,
               'DDoS_UDP': 13, 'DDoS_ICMP': 14}
    df['Attack_type'] = df['Attack_type'].map(attacks)
    
    X = df.drop(columns=['Attack_label', 'Attack_type'])
    y = df['Attack_type']
    
    return X, y, attacks

def feature_selection(X, y):
    """Select best features using Chi-Squared test."""
    chi_selector = SelectKBest(chi2, k='all')
    chi_selector.fit_transform(X, y)
    
    chi_scores = pd.DataFrame({'feature': X.columns, 'score': chi_selector.scores_}).dropna()
    chi_scores = chi_scores.sort_values(by='score', ascending=False)
    selected_features = chi_scores['feature'].tolist()
    print(selected_features)
    
    return selected_features

def prepare_data(X, y, selected_features):
    """Scale and split data into training, validation, and test sets."""
    scaler = StandardScaler().fit(X[selected_features])
    X_train, X_test, y_train, y_test = train_test_split(X[selected_features], y, test_size=0.2, random_state=42)
    X_train, X_val, y_train, y_val = train_test_split(X_train, y_train, test_size=0.125, random_state=42)
    
    X_train = scaler.transform(X_train)
    X_val = scaler.transform(X_val)
    X_test = scaler.transform(X_test)
    
    return X_train, X_val, X_test, y_train, y_val, y_test, scaler

def cnn_lstm_gru_model(input_shape):
    """Define and compile CNN-LSTM-GRU model."""
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
        Dense(15, activation='softmax')
    ])
    
    model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
    return model

def train_and_evaluate(model, X_train, y_train, X_val, y_val, X_test, y_test):
    """Train the model and evaluate its performance."""
    start_time = time.time()
    history = model.fit(X_train, y_train, validation_data=(X_val, y_val), epochs=6, batch_size=32)
    train_time = time.time() - start_time
    
    start_time = time.time()
    loss, accuracy = model.evaluate(X_test, y_test, batch_size=32)
    test_time = time.time() - start_time
    
    print(f'Test Loss: {loss:.4f}')
    print(f'Test Accuracy: {accuracy:.4f}')
    print(f'Training time: {train_time:.2f} seconds')
    print(f'Testing time: {test_time:.2f} seconds')
    
    return history, model

def plot_metrics(history, state):
    """Plot training and validation accuracy and loss."""
    plt.figure()
    plt.plot(history.history['accuracy'])
    plt.plot(history.history['val_accuracy'])
    plt.title('Model Accuracy')
    plt.ylabel('Accuracy')
    plt.xlabel('Epoch')
    plt.legend(['Train', 'Test'], loc='upper left')
    plt.savefig(f'../results/centralized/multiclass/{state}/accuracy_plot.jpg')
    plt.close()
    
    plt.figure()
    plt.plot(history.history['loss'])
    plt.plot(history.history['val_loss'])
    plt.title('Model Loss')
    plt.ylabel('Loss')
    plt.xlabel('Epoch')
    plt.legend(['Train', 'Test'], loc='upper left')
    plt.savefig(f'../results/centralized/multiclass/{state}/loss_plot.jpg')
    plt.close()

def evaluate_model(model, X_test, y_test, attacks, state):
    """Evaluate the model and generate a confusion matrix."""
    y_pred = model.predict(np.expand_dims(X_test, axis=2))
    y_pred_classes = np.argmax(y_pred, axis=1)
    inverse_attacks = {v: k for k, v in attacks.items()}
    if state == 'test':
        unique_classes = np.unique(y_pred_classes)
        class_names_ordered = [inverse_attacks[i] for i in unique_classes]
        # print(classification_report(y_test, y_pred_classes, target_names=class_names_ordered))
        print(y_pred_classes)
        print(class_names_ordered)        
        conf_mat = confusion_matrix(y_test, y_pred_classes)
    else:
        class_names_ordered = [attack for attack, number in sorted(attacks.items(), key=lambda item: item[1])]
        print(classification_report(y_test, y_pred_classes, target_names=class_names_ordered))
        conf_mat = confusion_matrix(y_test, y_pred_classes)
    plt.figure(figsize=(15, 10))
    sns.heatmap(
        conf_mat, annot=True, fmt='d', cmap='Blues',
        xticklabels=class_names_ordered,
        yticklabels=class_names_ordered
        )
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    plt.title('Confusion Matrix')
    plt.savefig(f'../results/centralized/multiclass/{state}/confusion_matrix.jpg')
    plt.close()

    cm_norm = conf_mat.astype('float') / conf_mat.sum(axis=1)[:, np.newaxis]

    plt.figure(figsize=(15, 10))
    sns.heatmap(
        cm_norm, annot=True, cmap='Blues',
        xticklabels=class_names_ordered,
        yticklabels=class_names_ordered,
        fmt='.2%'
    )

    # Set the plot labels and title for the normalized confusion matrix
    plt.xlabel('Predicted Labels')
    plt.ylabel('True Labels')
    plt.title('Normalized Confusion Matrix (Percentages)')
    # Optional: Save the normalized confusion matrix plot
    plt.savefig(f'../results/centralized/multiclass/{state}/normalized_confusion_matrix.jpg')
    plt.close()

def load_and_preprocess_test_data(file_path, intended_columns, selected_features):
    df = pd.read_csv(file_path)
    for column in intended_columns:
        if column not in df.columns:
            df[column] = 0  # Default value for missing columns
    
    list_a = df.columns.to_list()
    list_b = intended_columns
    result = [item for item in list_a if item not in list_b]
    df.drop(columns=result, inplace=True)
    df = df[selected_features]
    return df

def main():
    """Main execution function."""
    # file_path = 'datasets/combined_edgeIIot_500k_custom_DDos.csv'
    file_path = 'datasets/Preprocessed_shuffled_train_data.csv'
    X, y, attacks = load_and_preprocess_data(file_path)
    selected_features = feature_selection(X, y)
    X_train, X_val, X_test, y_train, y_val, y_test, scaler = prepare_data(X, y, selected_features)
    
    input_shape = (X_train.shape[1], 1)
    model = cnn_lstm_gru_model(input_shape)
    model.summary()
    plot_model(model, to_file='model_structure.png', show_shapes=True)
    
    history, model = train_and_evaluate(model, X_train, y_train, X_val, y_val, X_test, y_test)
    plot_metrics(history, 'train')
    evaluate_model(model, X_test, y_test, attacks, 'train')
    
    model.save('cnn_lstm_gru_model_binary_working.h5')

    # Test with attack datasets 
    # test_file_path = 'datasets/Preprocessed_validation_all_fields.csv'
    test_file_path = 'datasets/Preprocessed_prediction_sql_injection.csv'
    df_before = pd.read_csv(test_file_path)
    test_df = load_and_preprocess_test_data(test_file_path, selected_features, selected_features)
    X_test_scaled = scaler.transform(test_df)
    attacks = {'Normal': 0, 'MITM': 1, 'Uploading': 2, 'Ransomware': 3, 'SQL_injection': 4,
               'DDoS_HTTP': 5, 'DDoS_TCP': 6, 'Password': 7, 'Port_Scanning': 8,
               'Vulnerability_scanner': 9, 'Backdoor': 10, 'XSS': 11, 'Fingerprinting': 12,
               'DDoS_UDP': 13, 'DDoS_ICMP': 14}
    df_before['Attack_type'] = df_before['Attack_type'].map(attacks)
    # test_df['Attack_type'] = 4
    y_test = df_before['Attack_type']
    evaluate_model(model, X_test_scaled, y_test, attacks, 'test')

if __name__ == "__main__":
    main()
