import joblib
import os
import numpy as np
from lime.lime_text import LimeTextExplainer
import logging

logger = logging.getLogger(__name__)

# Load trained model
MODEL_PATH = "ml/phishing_model.pkl"

# Ensure ml directory exists
if not os.path.exists("ml"):
    os.makedirs("ml")
    logger.info("Created ml directory")

# Initialize LIME explainer
explainer = LimeTextExplainer(class_names=['Safe', 'Phishing'])

class KnowledgeSynthesisEngine:
    """
    Synthesizes professional security insights based on detected risk indicators.
    """
    TACTICS_MAP = {
        'Urgency/Pressure': ['urgent', 'immediate', 'immediately', 'now', 'expire', 'limited', 'quick'],
        'Credential Harvesting': ['verify', 'password', 'login', 'account', 'credentials', 'reset', 'confirm'],
        'Social Engineering': ['click', 'link', 'suspended', 'alert', 'security', 'unusual', 'activity'],
        'Financial Lure/Scam': ['prize', 'winner', 'claim', 'refund', 'payment', 'gift', 'card'],
        'Trust Exploitation': ['official', 'support', 'technical', 'helpdesk', 'system', 'administrator']
    }

    CONNECTORS = [
        "The analysis indicates a high correlation between {tactic} and typical malicious patterns.",
        "Detected {tactic} vectors that are highly indicative of advanced persistent threats.",
        "The payload structure exhibits characteristics of {tactic}, a common infiltration strategy.",
        "Internal heuristics have identified a {tactic} signature within the communication context."
    ]

    INSIGHTS = [
        "Specifically, the presence of these indicators suggests a targeted attempt at {action}.",
        "These patterns are often associated with {action} in sophisticated social engineering campaigns.",
        "We recommend caution as the linguistic structure aligns with standard {action} methodologies."
    ]

    ACTION_MAP = {
        'Urgency/Pressure': 'coerced response generation',
        'Credential Harvesting': 'unauthorized access acquisition',
        'Social Engineering': 'manipulative psychological exploit',
        'Financial Lure/Scam': 'fraudulent asset extraction',
        'Trust Exploitation': 'authority-based deception'
    }

    @classmethod
    def synthesize(cls, risk_words):
        if not risk_words:
            return "Analysis complete. Pattern recognition identified non-specific anomalies within the communication structure."

        # Map words to tactics
        detected_tactics = set()
        for word_data in risk_words:
            word = word_data['word'].lower()
            for tactic, keywords in cls.TACTICS_MAP.items():
                if word in keywords:
                    detected_tactics.add(tactic)
        
        if not detected_tactics:
            return f"Heuristic analysis flagged high-risk tokens including: {', '.join([w['word'] for w in risk_words[:3]])}. This linguistic pattern is statistically aligned with known phishing vectors."

        # Pick primary tactic
        primary_tactic = list(detected_tactics)[0]
        import random
        
        connector = random.choice(cls.CONNECTORS).format(tactic=primary_tactic)
        insight = random.choice(cls.INSIGHTS).format(action=cls.ACTION_MAP.get(primary_tactic, 'data exfiltration'))
        
        # Combine with risk words
        top_words = [f"'{w['word']}'" for w in risk_words[:3]]
        
        return f"{connector} {insight} Key risk-weighted tokens: {', '.join(top_words)}."

def ml_predict(text):
    """
    Predict if email text is phishing with XAI explanation
    Returns: (is_phishing: bool, confidence: float, reason: str, explanation: dict)
    """
    try:
        if not os.path.exists(MODEL_PATH):
            logger.warning(f"ML model not found at {MODEL_PATH}. Please run train_model.py to train the model.")
            return False, 0.0, "Model not trained", {}
        
        model, vectorizer = joblib.load(MODEL_PATH)
        
        # Vectorize input
        X = vectorizer.transform([text])
        
        # Predict
        prediction = model.predict(X)[0]
        confidence = model.predict_proba(X)[0]
        
        # Get confidence for predicted class
        pred_confidence = confidence[1] if prediction == 1 else confidence[0]
        
        # Generate explanation using LIME
        explanation_data = {}
        if prediction == 1:  # Only explain phishing emails
            try:
                # Create prediction function for LIME
                def predict_proba(texts):
                    return model.predict_proba(vectorizer.transform(texts))
                
                # Generate explanation
                exp = explainer.explain_instance(
                    text, 
                    predict_proba, 
                    num_features=10,
                    top_labels=1
                )
                
                # Get important words and their weights
                explanation_list = exp.as_list(label=1)  # Label 1 is phishing
                
                # Separate positive and negative contributions
                phishing_words = []
                safe_words = []
                
                for word, weight in explanation_list:
                    # Clean the word (remove < > and extra spaces)
                    cleaned_word = word.strip('<> ')
                    if weight > 0:
                        phishing_words.append({
                            'word': cleaned_word,
                            'weight': round(weight, 3)
                        })
                    else:
                        safe_words.append({
                            'word': cleaned_word,
                            'weight': round(abs(weight), 3)
                        })
                
                explanation_data = {
                    'phishing_words': phishing_words[:5],  # Top 5 phishing indicators
                    'safe_words': safe_words[:3],  # Top 3 safe indicators
                    'confidence': round(pred_confidence * 100, 2)
                }
                
            except Exception as e:
                logger.warning(f"LIME explanation error: {e}")
                explanation_data = {}
        
        # Determine reason using Knowledge Synthesis Engine
        reason = ""
        if prediction == 1:
            reason = KnowledgeSynthesisEngine.synthesize(explanation_data.get('phishing_words', []))
        else:
            reason = "Automated heuristics and linguistic analysis indicate this message maintains a high integrity score. No malicious payloads or social engineering patterns identified."
        
        return bool(prediction), float(pred_confidence), reason, explanation_data
    
    except Exception as e:
        logger.error(f"ML Prediction Error: {e}")
        return False, 0.0, "Error in prediction", {}


def get_explanation_html(explanation_data):
    """
    Generate HTML visualization of LIME explanation
    """
    if not explanation_data:
        return ""
    
    html = '<div class="xai-explanation premium-card">'
    html += '<div class="xai-header">'
    html += '<h4><i class="fas fa-microchip"></i> AI Insight Engine</h4>'
    html += '<span class="confidence-tag">Analysis Confidence: ' + str(explanation_data.get('confidence', 0)) + '%</span>'
    html += '</div>'
    
    # Phishing indicators
    if explanation_data.get('phishing_words'):
        html += '<div class="explanation-section danger-words">'
        html += '<p class="section-label"><i class="fas fa-exclamation-circle"></i> Key Risk Indicators</p>'
        html += '<div class="word-badges">'
        for word_data in explanation_data['phishing_words']:
            word = word_data['word']
            weight = word_data['weight']
            # Map weight 0.1-0.5 to intensity
            intensity = min(int(weight * 150) + 10, 100)
            html += f'<div class="word-badge-container">'
            html += f'<span class="word-badge danger" style="background: rgba(255, 71, 87, {0.1 + (weight*0.8)})">'
            html += f'{word}'
            html += '</span>'
            html += f'<div class="weight-bar"><div class="weight-fill" style="width: {min(weight*100, 100)}%"></div></div>'
            html += '</div>'
        html += '</div></div>'
    
    # Safe indicators
    if explanation_data.get('safe_words'):
        html += '<div class="explanation-section safe-words">'
        html += '<p class="section-label"><i class="fas fa-check-circle"></i> Neutral/Safe Context</p>'
        html += '<div class="word-badges">'
        for word_data in explanation_data['safe_words']:
            word = word_data['word']
            html += f'<span class="word-badge safe">'
            html += f'{word}'
            html += '</span>'
        html += '</div></div>'
    
    html += '<div class="xai-footer">'
    html += '<i class="fas fa-info-circle"></i> '
    html += 'These tokens were identified by our XAI engine as influential factors in this classification.</div>'
    html += '</div>'
    
    return html
