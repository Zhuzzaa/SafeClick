import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.preprocessing import StandardScaler
import joblib
import os
import time
from tqdm import tqdm
import logging
from extract_features import extract_url_features
from sklearn.tree import DecisionTreeClassifier

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def process_dataset_in_batches(input_path, batch_size=100000):
    """Process the dataset in batches to handle large files efficiently."""
    logger.info(f"Processing dataset from {input_path}")
    
    # Read the dataset in chunks
    chunks = pd.read_csv(input_path, chunksize=batch_size)
    all_features = []
    
    for chunk in tqdm(chunks, desc="Processing batches"):
        # Drop rows with NaN values in 'class' column
        chunk = chunk.dropna(subset=['class'])
        
        # Convert class column to numeric, replacing any non-numeric values with NaN
        chunk['class'] = pd.to_numeric(chunk['class'], errors='coerce')
        
        # Drop rows where class conversion resulted in NaN
        chunk = chunk.dropna(subset=['class'])
        
        # Convert class to integer
        chunk['class'] = chunk['class'].astype(int)
        
        features_list = []
        for url in chunk['url']:
            features = extract_url_features(url)
            if features:
                features_list.append(features)
            else:
                # If feature extraction fails, use zeros
                features_list.append({k: 0 for k in extract_url_features("http://example.com").keys()})
        
        features_df = pd.DataFrame(features_list)
        features_df['class'] = chunk['class']
        all_features.append(features_df)
    
    # Combine all batches
    final_df = pd.concat(all_features, ignore_index=True)
    
    # Final check for NaN values
    if final_df['class'].isna().any():
        logger.warning("Found NaN values in class column after processing. Dropping these rows.")
        final_df = final_df.dropna(subset=['class'])
    
    # Check class balance
    class_distribution = final_df['class'].value_counts().to_dict()
    logger.info(f"Processed {len(final_df)} samples")
    logger.info(f"Class distribution: {class_distribution}")
    
    # Check if we have both classes
    if len(class_distribution) < 2:
        logger.error("Dataset contains only one class. Cannot train binary classification model.")
        raise ValueError("Dataset must contain both classes (0 and 1) for binary classification.")
    
    return final_df

def train_and_evaluate_models(X_train, X_test, y_train, y_test):
    """Train and evaluate multiple models."""
    models = {
        'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
        'Logistic Regression': LogisticRegression(max_iter=1000, n_jobs=-1),
        'Decision Tree': DecisionTreeClassifier(random_state=42)
    }
    
    results = []
    
    for name, model in models.items():
        logger.info(f"Training {name}...")
        start_time = time.time()
        
        # Train model
        model.fit(X_train, y_train)
        
        # Make predictions
        y_pred = model.predict(X_test)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        
        # Calculate ROC-AUC only if model supports predict_proba
        if hasattr(model, 'predict_proba'):
            try:
                y_pred_proba = model.predict_proba(X_test)[:, 1]
                roc_auc = roc_auc_score(y_test, y_pred_proba)
            except Exception as e:
                logger.warning(f"Could not calculate ROC-AUC for {name}: {str(e)}")
                roc_auc = None
        else:
            roc_auc = None
        
        # Save model
        model_path = os.path.join('models', f'{name.lower().replace(" ", "_")}.joblib')
        joblib.dump(model, model_path)
        
        # Record results
        results.append({
            'Model': name,
            'Accuracy': accuracy,
            'Precision': precision,
            'Recall': recall,
            'F1-score': f1,
            'ROC-AUC': roc_auc,
            'Train Time (s)': time.time() - start_time
        })
        
        logger.info(f"{name} training completed in {time.time() - start_time:.2f} seconds")
    
    return pd.DataFrame(results)

def main():
    # Create models directory if it doesn't exist
    os.makedirs('models', exist_ok=True)
    
    # Process dataset
    input_path = os.path.join('data', 'malicious_phish.csv')
    df = pd.read_csv(input_path)
    
    # Извлечение признаков из URL
    features_list = []
    for url in df['url']:
        features = extract_url_features(url)
        if features is not None:
            features_list.append(features)
        else:
            # Если не удалось извлечь признаки, добавляем строку с нулями
            features_list.append({k: 0 for k in extract_url_features('http://example.com').keys()})
    features_df = pd.DataFrame(features_list)
    features_df['class'] = df['class']
    
    X = features_df.drop(['class'], axis=1)
    y = features_df['class']
    
    # Final validation of data
    logger.info("Validating data before training...")
    logger.info(f"X shape: {X.shape}")
    logger.info(f"y shape: {y.shape}")
    logger.info(f"Number of NaN values in X: {X.isna().sum().sum()}")
    logger.info(f"Number of NaN values in y: {y.isna().sum()}")
    logger.info(f"Class distribution: {y.value_counts().to_dict()}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train and evaluate models
    results = train_and_evaluate_models(X_train_scaled, X_test_scaled, y_train, y_test)
    
    # Save results
    results.to_csv('model_comparison_results.csv', index=False)
    logger.info("Results saved to model_comparison_results.csv")
    
    # Print results
    print("\nModel Comparison Results:")
    print(results.to_string(index=False))

if __name__ == "__main__":
    main() 