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
        
        # Determine reason with keyword detection
        reason = ""
        if prediction == 1:
            keywords = ["verify", "urgent", "click", "suspended", "reset", "claim", 
                       "prize", "winner", "confirm", "account", "password", "immediate",
                       "expire", "unusual", "security", "alert"]
            found = [kw for kw in keywords if kw.lower() in text.lower()]
            
            if explanation_data and explanation_data.get('phishing_words'):
                # Use LIME explanation for reason
                top_words = [w['word'] for w in explanation_data['phishing_words'][:3]]
                reason = f"Suspicious words detected so it can declared into pishing it can declared by this words this  words can also used in most of deepfake mail: {', '.join(top_words)}"
            elif found:
                reason = f"Suspicious keywords its not accurate but it most of phishing mails have this keywords: {', '.join(found[:5])}"
            else:
                reason = "ML model flagged as phishing"
        else:
            reason = "Safe email"
        
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
    
    html = '<div class="xai-explanation">'
    html += '<h4><i class="fas fa-brain"></i> AI Explanation</h4>'
    
    # Phishing indicators
    if explanation_data.get('phishing_words'):
        html += '<div class="explanation-section danger-words">'
        html += '<p class="section-label">🔴 Phishing Indicators:</p>'
        html += '<div class="word-badges">'
        for word_data in explanation_data['phishing_words']:
            word = word_data['word']
            weight = word_data['weight']
            intensity = min(int(weight * 100), 100)
            html += f'<span class="word-badge danger" style="opacity: {0.5 + (intensity/200)}">'
            html += f'{word} <small>({weight:.2f})</small>'
            html += '</span>'
        html += '</div></div>'
    
    # Safe indicators
    if explanation_data.get('safe_words'):
        html += '<div class="explanation-section safe-words">'
        html += '<p class="section-label">🟢 Safe Indicators:</p>'
        html += '<div class="word-badges">'
        for word_data in explanation_data['safe_words']:
            word = word_data['word']
            weight = word_data['weight']
            html += f'<span class="word-badge safe">'
            html += f'{word} <small>({weight:.2f})</small>'
            html += '</span>'
        html += '</div></div>'
    
    html += '<p class="xai-note"><i class="fas fa-info-circle"></i> '
    html += 'Weights show how much each word influenced the phishing detection.</p>'
    html += '</div>'
    
    return html
