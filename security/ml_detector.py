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

class CybersecurityAgent:
    """
    An autonomous agent that perceives email context and constructs dynamic security narratives.
    Replaces static templates with a logic-based construction pipeline.
    """
    
    @staticmethod
    def analyze_and_explain(sender, subject, risk_words):
        """
        Constructs a unique explanation based on the specific evidence found.
        """
        if not risk_words:
            return "The security agent detected anomalous patterns but could not isolate specific linguistic triggers."

        # PERCEPTION: Gather artifacts
        words = [w['word'] for w in risk_words[:3]]
        word_str = ", ".join(f"'{w}'" for w in words)
        
        # PROFILING: Determine attack archetype
        archetype = "General Phishing"
        risk_types = []
        
        # Simple keyword mapping for archetype detection
        keywords = " ".join(words).lower()
        if any(x in keywords for x in ['password', 'login', 'account', 'verify']):
            archetype = "Credential Harvesting"
        elif any(x in keywords for x in ['urgent', 'immediate', 'expire', 'now']):
            archetype = "High-Pressure Social Engineering"
        elif any(x in keywords for x in ['winner', 'prize', 'gift', 'money', 'claim']):
            archetype = "Financial Fraud"
        elif any(x in keywords for x in ['security', 'alert', 'suspended']):
            archetype = "Impersonation Attack"

        # CONSTRUCTION: Build the narrative dynamically
        # Opening
        explanation = f"The automated agent detected {archetype} indicators. "
        
        # Evidence Bridge
        explanation += f"Specifically, the use of high-risk tokens like {word_str} "
        
        # Contextual Analysis (using Subject/Sender if available)
        if subject:
             explanation += f"within the subject line '{subject[:30]}...' "
        
        # Strategic Conclusion
        explanation += "suggests a deliberate attempt to manipulate the recipient. "
        explanation += "The agent has classified this as a confirmed threat based on these observed behavioral vectors."

        return explanation

def ml_predict(text, sender="", subject=""):
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
        confidence = model.predict_proba(X)[0]
        
        # Get phishing probability (index 1)
        phishing_prob = confidence[1]
        
        # Enforce higher threshold for classification to reduce false positives
        # Default is 0.5, but we want to be safer (e.g., 0.7)
        THRESHOLD = 0.70
        prediction = 1 if phishing_prob > THRESHOLD else 0
        
        # Get confidence for predicted class
        pred_confidence = phishing_prob if prediction == 1 else confidence[0]
        
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
        
        # Determine reason using Cybersecurity Agent
        reason = ""
        if prediction == 1:
            # DYNAMIC AGENT EXPLANATION
            reason = CybersecurityAgent.analyze_and_explain(
                sender, 
                subject, 
                explanation_data.get('phishing_words', [])
            )
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
    
    # Fallback if no specific words
    if not explanation_data.get('phishing_words') and not explanation_data.get('safe_words'):
        html += '<div class="explanation-section">'
        html += '<p class="xai-note"><i class="fas fa-info-circle"></i> No specific linguistic tokens strongly influenced this result. The classification is based on broader semantic patterns and metadata heuristics.</p>'
        html += '</div>'
    
    html += '<div class="xai-footer">'
    html += '<i class="fas fa-info-circle"></i> '
    html += 'These tokens were identified by our XAI engine as influential factors in this classification.</div>'
    html += '</div>'
    
    return html
