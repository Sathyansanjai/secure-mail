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
DATASET_PATH = "enron_spam.csv"  # Default to Enron dataset if it exists

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
        print(f"Error: External dataset {DATASET_PATH} not found.")
        print("Please ensure enron_spam.csv is present or provided as an argument.")
        return

    # ML Pipeline
    print("Vectorizing data...")
    
    # Comprehensive stop words to ignore common linguistic noise
    custom_stop_words = [
        'just', 'start', 'we', 'now', 'pulled', 'pulled', 'jobs', 'alert', 'alerts',
        'matching', 'profile', 'fresher', 'software', 'engineer', 'developer',
        'weekly', 'report', 'stats', 'meeting', 'availability', 'purchase',
        'device', 'reminder', 'renew', 'opportunities', 'unread', 'dashboard',
        'comment', 'conversation', 'view', 'check', 'explore', 'exploring',
        'com', 'iii', 'notification', 'notifications', 'update', 'updates',
        'job', 'apply', 'application', 'status', 'candidate', 'resume', 'cv',
        'interview', 'hiring', 'position', 'role', 'team', 'join', 'network',
        'connection', 'connect', 'invitation', 'invite', 'linkedin', 'naukri',
        'indeed', 'glassdoor', 'recruiter', 'talent', 'acquisition', 'hr'
    ]
    from sklearn.feature_extraction import text
    stop_words = list(text.ENGLISH_STOP_WORDS.union(custom_stop_words))

    # Improved vectorization:
    # - min_df=3: Ignore words that appear in fewer than 3 documents
    # - max_df=0.7: Ignore words that appear in more than 70% of documents
    # - n-gram range (1,3): Still look at common phrases
    vectorizer = TfidfVectorizer(
        max_features=5000, 
        stop_words=stop_words, 
        ngram_range=(1, 3), 
        sublinear_tf=True,
        min_df=3,
        max_df=0.7,
        strip_accents='unicode'
    )
    
    X = vectorizer.fit_transform(texts)
    
    # Split for validation to show user metrics
    if len(texts) > 20:
        X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.2, random_state=42)
        print("Validating model on 80/20 split...")
        val_model = LogisticRegression(C=2.0, max_iter=2000, class_weight='balanced', solver='lbfgs')
        val_model.fit(X_train, y_train)
        y_pred = val_model.predict(X_test)
        print(f"\nValidation Accuracy: {accuracy_score(y_test, y_pred)*100:.2f}%")
        print("Validation Report:\n", classification_report(y_test, y_pred))
        
        # Now retrain on 100% of data for the final saved model
        print("Retraining final model on 100% of data for maximum accuracy...")
        model = LogisticRegression(C=2.0, max_iter=2000, class_weight='balanced', solver='lbfgs')
        model.fit(X, labels)
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
