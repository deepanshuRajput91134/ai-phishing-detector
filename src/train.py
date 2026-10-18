import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple
from scipy.sparse import hstack

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from features import (
    extract_url_features,
    extract_email_metadata_features
)
from dataset_generator import ensure_datasets


def train_url_model(data_path: str, model_save_path: str) -> Dict[str, Any]:
    """
    Extracts structural features from URLs, trains a Random Forest Classifier,
    evaluates performance, and serializes the model.
    """
    print(f"[*] Training URL Phishing Detector using {data_path}...")
    df = pd.read_csv(data_path)
    
    # Feature extraction
    feature_list = []
    for url in df["url"]:
        feature_list.append(extract_url_features(str(url)))
        
    X_df = pd.DataFrame(feature_list)
    feature_names = list(X_df.columns)
    X = X_df.values
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(n_estimators=120, max_depth=16, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred)),
        "recall": float(recall_score(y_test, y_pred)),
        "f1": float(f1_score(y_test, y_pred)),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "total_samples": len(df),
        "test_samples": len(y_test)
    }

    # Feature importance ranking
    importances = clf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    top_features = [
        {"feature": feature_names[i], "importance": float(importances[i])}
        for i in sorted_idx[:10]
    ]

    bundle = {
        "model": clf,
        "feature_names": feature_names,
        "metrics": metrics,
        "top_features": top_features
    }

    os.makedirs(os.path.dirname(model_save_path), exist_ok=True)
    joblib.dump(bundle, model_save_path)
    print(f"[+] URL Model successfully trained and saved to {model_save_path}")
    print(f"    - Accuracy:  {metrics['accuracy']*100:.2f}%")
    print(f"    - Precision: {metrics['precision']*100:.2f}%")
    print(f"    - Recall:    {metrics['recall']*100:.2f}%")
    print(f"    - F1-Score:  {metrics['f1']*100:.2f}%")
    return metrics


def train_email_model(data_path: str, model_save_path: str) -> Dict[str, Any]:
    """
    Trains a hybrid NLP + behavioral metadata classifier for email phishing detection.
    Combines TF-IDF n-grams with structural signals (urgency scores, credentials, IP links).
    """
    print(f"[*] Training Email Phishing Detector using {data_path}...")
    df = pd.read_csv(data_path)
    
    # Text corpus preparation
    subjects = df["subject"].fillna("").astype(str)
    bodies = df["body"].fillna("").astype(str)
    combined_texts = [f"{s} {b}" for s, b in zip(subjects, bodies)]

    # Heuristic metadata extraction
    meta_list = []
    for s, b in zip(subjects, bodies):
        meta_list.append(extract_email_metadata_features(s, b))
        
    meta_df = pd.DataFrame(meta_list)
    meta_cols = list(meta_df.columns)
    
    y = df["label"].values

    # Train / Test split
    indices = np.arange(len(df))
    train_idx, test_idx = train_test_split(indices, test_size=0.2, random_state=42, stratify=y)

    train_texts = [combined_texts[i] for i in train_idx]
    test_texts = [combined_texts[i] for i in test_idx]

    train_meta = meta_df.iloc[train_idx].values
    test_meta = meta_df.iloc[test_idx].values

    y_train = y[train_idx]
    y_test = y[test_idx]

    # 1. TF-IDF vectorization
    vectorizer = TfidfVectorizer(max_features=2500, ngram_range=(1, 2), stop_words="english")
    X_train_tfidf = vectorizer.fit_transform(train_texts)
    X_test_tfidf = vectorizer.transform(test_texts)

    # 2. Metadata scaling
    scaler = StandardScaler()
    X_train_meta = scaler.fit_transform(train_meta)
    X_test_meta = scaler.transform(test_meta)

    # 3. Feature stacking (Text + Behavioral Metadata)
    X_train_combined = hstack([X_train_tfidf, X_train_meta])
    X_test_combined = hstack([X_test_tfidf, X_test_meta])

    # 4. Model Training
    clf = LogisticRegression(C=2.0, max_iter=1000, random_state=42)
    clf.fit(X_train_combined, y_train)

    y_pred = clf.predict(X_test_combined)

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred)),
        "recall": float(recall_score(y_test, y_pred)),
        "f1": float(f1_score(y_test, y_pred)),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "total_samples": len(df),
        "test_samples": len(y_test)
    }

    bundle = {
        "model": clf,
        "vectorizer": vectorizer,
        "scaler": scaler,
        "meta_cols": meta_cols,
        "metrics": metrics
    }

    os.makedirs(os.path.dirname(model_save_path), exist_ok=True)
    joblib.dump(bundle, model_save_path)
    print(f"[+] Email Model successfully trained and saved to {model_save_path}")
    print(f"    - Accuracy:  {metrics['accuracy']*100:.2f}%")
    print(f"    - Precision: {metrics['precision']*100:.2f}%")
    print(f"    - Recall:    {metrics['recall']*100:.2f}%")
    print(f"    - F1-Score:  {metrics['f1']*100:.2f}%")
    return metrics


def train_all(base_dir: str = None):
    """Orchestrates full dataset generation and dual model training."""
    if base_dir is None:
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    
    data_dir = os.path.join(base_dir, "data")
    models_dir = os.path.join(base_dir, "models")

    url_csv, email_csv = ensure_datasets(data_dir)

    url_model_path = os.path.join(models_dir, "url_classifier.joblib")
    email_model_path = os.path.join(models_dir, "email_classifier.joblib")

    url_metrics = train_url_model(url_csv, url_model_path)
    email_metrics = train_email_model(email_csv, email_model_path)

    print("\n" + "="*50)
    print("      TRAINING PIPELINE COMPLETE")
    print("="*50)
    print(f"URL Detector Accuracy:   {url_metrics['accuracy']*100:.2f}%")
    print(f"Email Detector Accuracy: {email_metrics['accuracy']*100:.2f}%")
    print("="*50)


if __name__ == "__main__":
    train_all()
