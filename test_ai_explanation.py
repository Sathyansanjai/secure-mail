"""
Test script to demonstrate AI-powered phishing explanations
"""

from security.ml_detector import generate_ai_phishing_explanation

# Sample phishing email
sender = "security@paypa1-verify.com"
subject = "URGENT: Verify Your Account Now"
body = """
Dear Customer,

Your PayPal account has been temporarily suspended due to suspicious activity.
You must verify your identity immediately by clicking the link below:

http://paypa1-verify.com/login

Failure to verify within 24 hours will result in permanent account closure.

Best regards,
PayPal Security Team
"""

phishing_words = [
    {'word': 'urgent', 'weight': 0.45},
    {'word': 'verify', 'weight': 0.38},
    {'word': 'suspended', 'weight': 0.35},
    {'word': 'immediately', 'weight': 0.32}
]

confidence = 0.89

print("=" * 60)
print("AI-POWERED PHISHING EXPLANATION TEST")
print("=" * 60)
print(f"\nFrom: {sender}")
print(f"Subject: {subject}")
print(f"Confidence: {int(confidence * 100)}%")
print("\n" + "-" * 60)
print("AI EXPLANATION:")
print("-" * 60)

explanation = generate_ai_phishing_explanation(
    sender, subject, body, phishing_words, confidence
)

print(explanation)
print("\n" + "=" * 60)
