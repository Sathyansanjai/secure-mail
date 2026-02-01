import os
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# Configuration
ML_DIR = "ml"
MODEL_FILE = "phishing_model.pkl"
DATASET_PATH = None  # User should set this to their CSV path

def train_model(dataset_path=None):
    if not os.path.exists(ML_DIR):
        os.makedirs(ML_DIR)
        print(f"Created directory: {ML_DIR}")

    texts = []
    labels = []

    if dataset_path and os.path.exists(dataset_path):
        print(f"Loading dataset from: {dataset_path}")
        df = pd.read_csv(dataset_path)
        # Assuming CSV has 'text' and 'label' columns
        if 'text' in df.columns and 'label' in df.columns:
            texts = df['text'].astype(str).tolist()
            labels = df['label'].tolist()
        else:
            print("Error: CSV must contain 'text' and 'label' columns.")
            return
    else:
        print("No external dataset found. Using enhanced internal synthetic dataset...")
        # High-fidelity synthetic dataset for demonstration
        texts = [
            # Phishing (Synthesized professional patterns)
            "Urgent: Your account privacy has been compromised. Verify your identity now.",
            "Suspension Notice: Unusual login attempt from unrecognized device. Reset password.",
            "Immediate Action Required: Confirm your payment details to avoid service interruption.",
            "Security Alert: A security breach was detected. Please secure your account immediately.",
            "Account Lockout: Your subscription has expired. Update billing information to reactivate.",
            "Win a $500 Gift Card! Click here to claim your exclusive reward.",
            "Official Notice: Please confirm your shipping address for the pending package.",
            "Technical Support: Your system needs an update. View instructions here.",
            
            # Safe (Professional correspondence)
            "The quarterly report is attached for your review. Let me know if you have questions.",
            "Meeting invitation: Project sync scheduled for tomorrow at 10 AM.",
            "Thank you for your inquiry. Our team will get back to you shortly.",
            "Your order #12345 has been shipped. Track your package on our website.",
            "Happy birthday from all of us! Have a wonderful day.",
            "Please find the notes from today's sync meeting in the shared drive.",
            "I've updated the documentation for the new API endpoint. Please check.",
            "Regarding our discussion earlier, I've confirmed the deadline for next Friday."
        ]
        labels = [1] * 8 + [0] * 8

    # ML Pipeline
    print("Vectorizing data...")
    # Using bi-grams and sub-linear scaling for better text analysis
    vectorizer = TfidfVectorizer(
        max_features=2000, 
        stop_words='english', 
        ngram_range=(1, 2),
        sublinear_tf=True
    )
    
    X = vectorizer.fit_transform(texts)
    
    # Split for validation if enough data
    if len(texts) > 20:
        X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.2, random_state=42)
        print("Training model on dataset...")
        model = LogisticRegression(C=1.0, max_iter=1000, class_weight='balanced')
        model.fit(X_train, y_train)
        
        y_pred = model.predict(X_test)
        print(f"\nModel Accuracy: {accuracy_score(y_test, y_pred)*100:.2f}%")
        print("Classification Report:\n", classification_report(y_test, y_pred))
    else:
        print("Small dataset detected. Training on full data...")
        model = LogisticRegression(C=1.0, max_iter=1000, class_weight='balanced')
        model.fit(X, labels)
        print(f"Training accuracy: {model.score(X, labels)*100:.2f}%")

    # Save
    model_path = os.path.join(ML_DIR, MODEL_FILE)
    joblib.dump((model, vectorizer), model_path)
    print(f"\n[OK] ML phishing model persisted at: {model_path}")

if __name__ == "__main__":
    # Check if a CSV was passed as an argument
    import sys
    csv_arg = sys.argv[1] if len(sys.argv) > 1 else DATASET_PATH
    train_model(csv_arg)
