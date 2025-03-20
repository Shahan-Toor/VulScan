"""
Train and evaluate machine learning models for vulnerability analysis.
"""

import os
import sys
import json
import logging
import pickle
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, LSTM, Embedding, Bidirectional
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add src to Python path if running as script
if __name__ == "__main__" and os.path.exists(os.path.join(os.path.dirname(os.path.dirname(__file__)), "__init__.py")):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

# Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(SCRIPT_DIR, "models")
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(SCRIPT_DIR)), "data")

# Create directories if they don't exist
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

def load_training_data() -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Load training data for vulnerability models.
    
    Returns:
        Tuple of DataFrames (vulnerabilities, pages)
    """
    # Check for existing training data
    vuln_data_path = os.path.join(DATA_DIR, "training_vulnerabilities.csv")
    pages_data_path = os.path.join(DATA_DIR, "training_pages.csv")
    
    if os.path.exists(vuln_data_path) and os.path.exists(pages_data_path):
        logger.info(f"Loading existing training data from {vuln_data_path} and {pages_data_path}")
        vulnerabilities_df = pd.read_csv(vuln_data_path)
        pages_df = pd.read_csv(pages_data_path)
        return vulnerabilities_df, pages_df
    
    # If no existing data, generate synthetic training data
    logger.info("No training data found, generating synthetic data")
    
    # Generate synthetic vulnerability data
    vuln_types = ["sql_injection", "xss", "csrf", "idor", "file_inclusion", "command_injection"]
    severities = ["critical", "high", "medium", "low", "info"]
    
    # Generate 1000 synthetic vulnerability records
    num_records = 1000
    
    # Generate base URLs
    base_urls = [
        "https://example.com",
        "https://testsite.org",
        "https://vulnerableapp.net",
        "https://securitytesting.io",
        "https://webapp.com"
    ]
    
    # Generate random vulnerability data
    import random
    
    vuln_data = []
    for i in range(num_records):
        base_url = random.choice(base_urls)
        path = random.choice([
            "/login", "/register", "/profile", "/admin", "/cart", "/checkout",
            "/search", "/product", "/user", "/settings", "/api/users", "/api/products"
        ])
        
        url = f"{base_url}{path}"
        vuln_type = random.choice(vuln_types)
        
        # Appropriate parameters based on vulnerability type
        if vuln_type == "sql_injection":
            param = random.choice(["id", "user_id", "product_id", "order_id", "category_id"])
            payload = random.choice(["' OR 1=1 --", "' UNION SELECT 1,2,3 --", "1' OR '1'='1", "admin'--"])
            evidence = f"SQL error in response: You have an error in your SQL syntax near '{payload}'"
        elif vuln_type == "xss":
            param = random.choice(["q", "search", "name", "message", "comment"])
            payload = random.choice(["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "\"><script>alert(1)</script>"])
            evidence = f"Payload {payload} reflected in response"
        elif vuln_type == "csrf":
            param = ""
            payload = ""
            evidence = "No CSRF token found in form submission"
        elif vuln_type == "idor":
            param = random.choice(["user_id", "account_id", "doc_id", "file_id"])
            payload = str(random.randint(1, 1000))
            evidence = f"Unauthorized access to resource {param}={payload}"
        else:
            param = random.choice(["file", "path", "url", "cmd", "exec"])
            payload = random.choice(["../../../etc/passwd", "| cat /etc/passwd", "?cmd=whoami"])
            evidence = f"Successful exploitation with payload: {payload}"
        
        # Random but weighted severity
        weights = [0.1, 0.25, 0.4, 0.15, 0.1]  # Probability distribution
        severity = random.choices(severities, weights=weights)[0]
        
        # Is this a false positive? (20% chance)
        is_false_positive = random.random() < 0.2
        
        # Generate risk score (influenced by severity but with some randomness)
        if severity == "critical":
            base_score = random.uniform(8.0, 10.0)
        elif severity == "high":
            base_score = random.uniform(6.0, 8.0)
        elif severity == "medium":
            base_score = random.uniform(4.0, 6.0)
        elif severity == "low":
            base_score = random.uniform(2.0, 4.0)
        else:  # info
            base_score = random.uniform(0.1, 2.0)
        
        # Add some noise
        risk_score = round(min(10.0, max(0.1, base_score + random.uniform(-1.0, 1.0))), 1)
        
        # Risk level based on risk score
        if risk_score >= 8.0:
            risk_level = "critical"
        elif risk_score >= 6.0:
            risk_level = "high"
        elif risk_score >= 4.0:
            risk_level = "medium"
        elif risk_score >= 2.0:
            risk_level = "low"
        else:
            risk_level = "info"
            
        vuln_data.append({
            "id": i + 1,
            "type": vuln_type,
            "url": url,
            "method": random.choice(["GET", "POST", "PUT", "DELETE"]),
            "param": param,
            "payload": payload,
            "evidence": evidence,
            "severity": severity,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "is_false_positive": is_false_positive
        })
    
    # Create DataFrame for vulnerabilities
    vulnerabilities_df = pd.DataFrame(vuln_data)
    
    # Generate page data
    page_data = []
    urls = set(vulnerabilities_df["url"].unique())
    
    for url in urls:
        base_url = url.split("/")[2]
        title = f"{base_url.split('.')[0].title()} - {url.split('/')[-1].replace('_', ' ').title()}"
        depth = len(url.split("/")) - 3  # Remove protocol and domain parts
        
        page_data.append({
            "url": url,
            "title": title,
            "depth": depth,
            "status_code": 200,
            "content_type": "text/html",
            "size": random.randint(5000, 50000)
        })
    
    # Add some additional pages not associated with vulnerabilities
    for i in range(100):
        base_url = random.choice(base_urls)
        path = random.choice([
            "/about", "/contact", "/faq", "/terms", "/privacy", "/help",
            "/blog", "/news", "/support", "/docs", "/api/docs", "/status"
        ])
        
        url = f"{base_url}{path}"
        if url not in urls:
            title = f"{base_url.split('.')[0].title()} - {path.split('/')[-1].replace('_', ' ').title()}"
            depth = len(url.split("/")) - 3
            
            page_data.append({
                "url": url,
                "title": title,
                "depth": depth,
                "status_code": 200,
                "content_type": "text/html",
                "size": random.randint(5000, 50000)
            })
    
    # Create DataFrame for pages
    pages_df = pd.DataFrame(page_data)
    
    # Save the synthetic data to CSV
    vulnerabilities_df.to_csv(vuln_data_path, index=False)
    pages_df.to_csv(pages_data_path, index=False)
    
    logger.info(f"Generated and saved synthetic training data to {DATA_DIR}")
    return vulnerabilities_df, pages_df

def preprocess_data(vulnerabilities_df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, TfidfVectorizer]:
    """
    Preprocess vulnerability data for ML models.
    
    Args:
        vulnerabilities_df: DataFrame of vulnerabilities
        
    Returns:
        Tuple of (features array, labels array, vectorizer)
    """
    logger.info("Preprocessing vulnerability data for model training")
    
    # Extract text features for TF-IDF
    text_features = []
    for _, row in vulnerabilities_df.iterrows():
        # Combine relevant text fields
        text = f"{row['type']} {row['url']} {row['param']} {row['payload']} {row['evidence']}"
        text_features.append(text)
    
    # Transform text to TF-IDF features
    vectorizer = TfidfVectorizer(max_features=1000)
    X_text = vectorizer.fit_transform(text_features)
    
    # Get labels (false positive classification)
    y = vulnerabilities_df["is_false_positive"].values
    
    return X_text, y, vectorizer

def train_false_positive_classifier(X: np.ndarray, y: np.ndarray) -> RandomForestClassifier:
    """
    Train a false positive classifier model.
    
    Args:
        X: Feature matrix
        y: Target labels
        
    Returns:
        Trained classifier model
    """
    logger.info("Training false positive classifier")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train Random Forest model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    logger.info(f"False positive classifier metrics:")
    logger.info(f"  Accuracy: {accuracy:.4f}")
    logger.info(f"  Precision: {precision:.4f}")
    logger.info(f"  Recall: {recall:.4f}")
    logger.info(f"  F1 Score: {f1:.4f}")
    
    return model

def prepare_risk_score_data(vulnerabilities_df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
    """
    Prepare data for risk score prediction model.
    
    Args:
        vulnerabilities_df: DataFrame of vulnerabilities
        
    Returns:
        Tuple of (feature matrix, target values)
    """
    # Extract features for risk scoring
    logger.info("Preparing data for risk score prediction model")
    
    # One-hot encode categorical features
    vuln_type_dummies = pd.get_dummies(vulnerabilities_df["type"], prefix="type")
    severity_dummies = pd.get_dummies(vulnerabilities_df["severity"], prefix="severity")
    method_dummies = pd.get_dummies(vulnerabilities_df["method"], prefix="method")
    
    # Extract URL depth as a feature
    vulnerabilities_df["url_depth"] = vulnerabilities_df["url"].apply(lambda x: len(x.split("/")) - 3)
    
    # Create feature matrix
    features = pd.concat([
        vuln_type_dummies,
        severity_dummies,
        method_dummies,
        vulnerabilities_df[["url_depth"]]
    ], axis=1)
    
    # Target is risk score
    y = vulnerabilities_df["risk_score"].values
    
    return features.values, y

def train_risk_score_model(X: np.ndarray, y: np.ndarray) -> tf.keras.Model:
    """
    Train a neural network model for risk score prediction.
    
    Args:
        X: Feature matrix
        y: Target values (risk scores)
        
    Returns:
        Trained neural network model
    """
    logger.info("Training risk score prediction model")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Build neural network model
    model = Sequential([
        Dense(64, activation="relu", input_shape=(X_train.shape[1],)),
        Dropout(0.2),
        Dense(32, activation="relu"),
        Dropout(0.2),
        Dense(16, activation="relu"),
        Dense(1)  # Single output for regression
    ])
    
    # Compile model
    model.compile(
        optimizer="adam",
        loss="mean_squared_error",
        metrics=["mean_absolute_error"]
    )
    
    X_train = np.array(X_train, dtype=np.float32)
    y_train = np.array(y_train, dtype=np.float32)

    # Train model
    history = model.fit(
        X_train, 
        y_train,
        epochs=50,
        batch_size=32,
        validation_split=0.2,
        verbose=1
    )
    
    # Evaluate model
    loss, mae = model.evaluate(X_test, y_test)
    logger.info(f"Risk score model evaluation:")
    logger.info(f"  Mean Squared Error: {loss:.4f}")
    logger.info(f"  Mean Absolute Error: {mae:.4f}")
    
    return model

def save_models(vectorizer: TfidfVectorizer, fp_classifier: RandomForestClassifier, risk_model: tf.keras.Model) -> None:
    """
    Save trained models to disk.
    
    Args:
        vectorizer: Trained TF-IDF vectorizer
        fp_classifier: Trained false positive classifier
        risk_model: Trained risk score model
    """
    logger.info(f"Saving models to {MODEL_DIR}")
    
    # Save TF-IDF vectorizer
    with open(os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl"), "wb") as f:
        pickle.dump(vectorizer, f)
    
    # Save false positive classifier
    with open(os.path.join(MODEL_DIR, "vulnerability_classifier.pkl"), "wb") as f:
        pickle.dump(fp_classifier, f)
    
    # Save risk score model
    risk_model_path = os.path.join(MODEL_DIR, "risk_scorer.keras")
    risk_model.save(risk_model_path)
    
    logger.info("All models saved successfully")

def main():
    """Main function to train all models."""
    logger.info("Starting model training process")
    
    # Load training data
    vulnerabilities_df, pages_df = load_training_data()
    logger.info(f"Loaded training data: {len(vulnerabilities_df)} vulnerabilities, {len(pages_df)} pages")
    
    # Train false positive classifier
    X_text, y_fp, vectorizer = preprocess_data(vulnerabilities_df)
    fp_classifier = train_false_positive_classifier(X_text, y_fp)
    
    # Train risk score model
    X_risk, y_risk = prepare_risk_score_data(vulnerabilities_df)

    X_risk = np.array(X_risk, dtype=np.float32)
    y_risk = np.array(y_risk, dtype=np.float32)
    risk_model = train_risk_score_model(X_risk, y_risk)
    
    # Save models
    save_models(vectorizer, fp_classifier, risk_model)
    
    logger.info("Model training completed successfully")

if __name__ == "__main__":
    main() 