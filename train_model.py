import os
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

# Make sure 'ml' folder exists
if not os.path.exists("ml"):
    os.makedirs("ml")

# Enhanced training data
texts = [
    # Phishing emails
    "verify your account immediately",
    "click here to reset your password",
    "urgent action required",
    "free gift card claim now",
    "bank account suspended",
    "you have won a prize click to claim",
    "confirm your identity now",
    "your package could not be delivered",
    "unusual activity detected on your account",
    "congratulations you are a winner",
    "update your payment information",
    "your account will be closed",
    "claim your refund now",
    "limited time offer act now",
    "click to get bumper price",
    "verify payment details urgently",
    "your subscription is expiring",
    "security alert click here",
    "confirm shipping address immediately",
    "refund pending click to process",
    
    # Safe emails
    "meeting scheduled tomorrow",
    "project update attached",
    "family dinner tonight",
    "invoice for last month",
    "hello how are you",
    "quarterly report is ready",
    "thanks for your help",
    "see you at the conference",
    "team lunch on friday",
    "please review the document",
    "happy birthday to you",
    "reminder about appointment",
    "weekly newsletter",
    "status update on project",
    "travel itinerary attached",
    "notes from meeting",
    "thank you for your order",
    "welcome to our service",
    "password reset requested",
    "your order has shipped"
]

labels = [
    # Phishing (1)
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    # Safe (0)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
]

# Vectorization
vectorizer = TfidfVectorizer(max_features=100)
X = vectorizer.fit_transform(texts)

# Train model
model = LogisticRegression(max_iter=1000)
model.fit(X, labels)

# Save model and vectorizer
joblib.dump((model, vectorizer), "ml/phishing_model.pkl")

print("✅ ML phishing model trained and saved in ml/phishing_model.pkl")
print(f"✅ Training accuracy: {model.score(X, labels) * 100:.2f}%")
