import joblib
import os

MODEL_PATH = "ml/phishing_model.pkl"

def test_inference():
    if not os.path.exists(MODEL_PATH):
        print("Model not found!")
        return

    model, vectorizer = joblib.load(MODEL_PATH)
    
    test_emails = [
        "Hey, can you verify if you received the files? Also, let me know if you need anything else.", # Safe
        "Urgent: Verify your account immediately to avoid suspension. Click here to login.",       # Phishing
        "The project update is attached. You should check it out and also verify the numbers.",     # Safe
        "Win a gift card now! Verify your details to claim the prize.",                             # Phishing
        "Software Engineer: BOT Campus AI - Software Engineer Fresher and more. We've pulled these jobs just for you. Start exploring now." # LinkedIn-style (Previously failing)
    ]
    
    for email in test_emails:
        X = vectorizer.transform([email])
        prediction = model.predict(X)[0]
        probs = model.predict_proba(X)[0]
        conf = probs[1] if prediction == 1 else probs[0]
        
        status = "PHISHING" if prediction == 1 else "SAFE"
        print(f"[{status}] (Conf: {conf*100:.2f}%) Text: {email[:100]}...")

if __name__ == "__main__":
    test_inference()
