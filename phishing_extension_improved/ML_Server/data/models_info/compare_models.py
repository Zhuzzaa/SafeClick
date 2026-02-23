import pandas as pd
import numpy as np
import time
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import os
from main import load_kaggle_dataset, extract_url_features

def compare_models(dataset_path):
    # Загрузка и подготовка данных
    print("Loading dataset...")
    data = load_kaggle_dataset(dataset_path)
    X = data.drop('type', axis=1)
    y = data['type']
    
    # Разделение данных
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Определение моделей для сравнения
    models = {
        'Random Forest': RandomForestClassifier(class_weight='balanced', random_state=42),
        'Logistic Regression': LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42),
        'Linear SVM': LinearSVC(max_iter=2000, class_weight='balanced', random_state=42),
        'KNN': KNeighborsClassifier()
    }
    
    results = []
    
    # Обучение и оценка каждой модели
    for name, model in models.items():
        start = time.time()
        try:
            model.fit(X_train_scaled, y_train)
            y_pred = model.predict(X_test_scaled)
            acc = accuracy_score(y_test, y_pred)
            prec = precision_score(y_test, y_pred)
            rec = recall_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred)
            try:
                roc = roc_auc_score(y_test, y_pred)
            except Exception:
                roc = 'N/A'
            elapsed = time.time() - start
            results.append({
                'Model': name,
                'Accuracy': acc,
                'Precision': prec,
                'Recall': rec,
                'F1': f1,
                'ROC-AUC': roc,
                'Train Time (s)': elapsed
            })
        except Exception as e:
            results.append({
                'Model': name,
                'Accuracy': 'ERROR',
                'Precision': 'ERROR',
                'Recall': 'ERROR',
                'F1': 'ERROR',
                'ROC-AUC': 'ERROR',
                'Train Time (s)': 'ERROR',
                'Error': str(e)
            })
    
    # Создание DataFrame с результатами
    results_df = pd.DataFrame(results)
    print("\nSummary of all models:")
    print(results_df)
    
    # Сохранение результатов в текстовый файл
    out_path = os.path.join(os.path.dirname(__file__), 'model_comparison_results.txt')
    with open(out_path, 'w', encoding='utf-8') as f:
        for res in results:
            f.write(f"Model: {res['Model']}\n")
            f.write(f"  Accuracy: {res['Accuracy']}\n")
            f.write(f"  Precision: {res['Precision']}\n")
            f.write(f"  Recall: {res['Recall']}\n")
            f.write(f"  F1: {res['F1']}\n")
            f.write(f"  ROC-AUC: {res['ROC-AUC']}\n")
            f.write(f"  Train Time (s): {res['Train Time (s)']}\n")
            if 'Error' in res:
                f.write(f"  Error: {res['Error']}\n")
            f.write("\n")
    print(f"Results saved to {out_path}")
    
    return results_df

if __name__ == "__main__":
    # Автоматически ищем датасет в папке data
    dataset_path = os.path.join(os.path.dirname(__file__), 'data', 'malicious_phish.csv')
    compare_models(dataset_path) 