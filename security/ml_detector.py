import joblib
import os
import numpy as np
from lime.lime_text import LimeTextExplainer
import logging
import random

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
        Constructs a unique, professional security briefing.
        """
        if not risk_words:
            return "Analysis inconclusive: Standard pattern matching yielded no specific signatures, yet the anomaly score exceeded safety thresholds."

        try:
            # 1. PERCEPTION: Extract Core Artifacts
            words = [w['word'] for w in risk_words[:4]]
            word_str = ", ".join(f"'{w}'" for w in words)
            sender_display = sender if sender else "Unknown Source"
            subject_display = f"'{subject}'" if subject else "the message header"
            
            # 2. PROFILING: Identify Behavioral Archetype
            keywords = " ".join(words).lower()
            if any(x in keywords for x in ['password', 'login', 'account', 'verify', 'update']):
                archetype = "Credential Harvesting"
                impact = "unauthorized access and identity theft"
            elif any(x in keywords for x in ['urgent', 'immediate', 'expire', 'now', 'action']):
                archetype = "Coercive Social Engineering"
                impact = "forced decision-making under artificial pressure"
            elif any(x in keywords for x in ['winner', 'prize', 'gift', 'money', 'claim', 'fund']):
                archetype = "Advance-Fee / Financial Fraud"
                impact = "financial loss via deceptive solicitation"
            elif any(x in keywords for x in ['security', 'alert', 'suspended', 'unusual']):
                archetype = "Impersonation / Security Spoofing"
                impact = "stealing trust by mimicking authority figures"
            else:
                archetype = "Anomalous Communication Pattern"
                impact = "delivery of potentially malicious payloads"

            # 3. CONSTRUCTION: Select a Professional Narrative Template
            templates = [
                # Template A: The Executive Brief
                f"**Threat Assessment**: The email {subject_display} from {sender_display} has been flagged as {archetype}. analysis detected a cluster of high-risk terminology ({word_str}) typically deployed to facilitate {impact}.",
                
                # Template B: The Technical Breakdown
                f"**Security Analysis**: Heuristic scanning identified {archetype} vectors within the subject {subject_display}. The linguistic density of terms such as {word_str} deviates significantly from standard business communication protocols.",
                
                # Template C: The Tactical Observation
                f"**Behavioral Report**: The sender ({sender_display}) is employing {archetype} tactics. By utilizing triggers like {word_str} in context of {subject_display}, the message attempts to bypass critical thinking to achieve {impact}.",
                
                # Template D: The Forensics Summary
                f"**Forensic Insight**: This message fits the profile of {archetype}. Key signatures isolated include {word_str}, which correlate with known campaigns aiming for {impact}."
            ]
            
            # Select a template
            explanation = random.choice(templates)
            return explanation

        except Exception as e:
            return f"Automated analysis interrupted. Error code: {str(e)}. Default action: Block and Quarantine."

def generate_ai_phishing_explanation(sender, subject, body, phishing_words, confidence):
    """
    Uses Gemini AI to generate professional, educational phishing explanations.
    Falls back to CybersecurityAgent if API fails.
    """
    try:
        from google import genai
        from config import config
        
        # Configure Gemini
        client = genai.Client(api_key=config.GEMINI_API_KEY)
        
        # Extract key risk words for context
        risk_words_str = ", ".join([f"'{w['word']}'" for w in phishing_words[:5]]) if phishing_words else "various suspicious patterns"
        
        # Craft expert prompt
        prompt = f"""You are a cybersecurity expert explaining why an email is phishing to a non-technical user.

**Email Details:**
From: {sender}
Subject: {subject}
Body snippet: {body[:300]}...
Detected risk indicators: {risk_words_str}
Confidence: {int(confidence * 100)}%

**Instructions:**
Write a clear, professional 2-3 sentence explanation that:
1. Identifies the specific phishing tactic being used (e.g., urgency, fake links, impersonation)
2. Points out 1-2 concrete red flags in this email
3. Ends with brief, actionable safety advice

Use a professional but friendly tone. Do NOT use bullet points or formatting - just natural paragraphs.
Keep it under 80 words total.

Generate the explanation now:"""

        # Call Gemini API
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt
        )
        
        explanation = response.text.strip()
        
        # Validate response
        if explanation and len(explanation) > 30:
            return explanation
        else:
            raise ValueError("AI response too short")
            
    except Exception as e:
        # Fallback to CybersecurityAgent
        logger.warning(f"AI explanation failed: {e}. Using fallback.")
        return CybersecurityAgent.analyze_and_explain(sender, subject, phishing_words)


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
        
        # Determine reason using AI-powered explanation
        reason = ""
        if prediction == 1:
            # AI-POWERED EXPLANATION (with fallback to CybersecurityAgent)
            reason = generate_ai_phishing_explanation(
                sender, 
                subject,
                text,  # Full email body for context
                explanation_data.get('phishing_words', []),
                pred_confidence
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

class ReplyAgent:
    """
    LLM-powered email reply agent using Google Gemini API.
    Generates intelligent, context-aware, professional responses.
    """
    
    @classmethod
    def generate_draft(cls, sender, subject, body):
        """
        Generates a professional email reply using Gemini API.
        Falls back to heuristic templates on error.
        """
        try:
            from google import genai
            from config import config
            
            # Configure Gemini with new SDK
            client = genai.Client(api_key=config.GEMINI_API_KEY)
            
            # Extract sender name
            sender_name = sender.split("<")[0].strip().replace('"', '') or "Colleague"
            
            # Craft intelligent prompt
            prompt = f"""You are a professional email assistant helping draft a reply.

**Incoming Email:**
From: {sender}
Subject: {subject}
Body: {body}

**Instructions:**
1. Write a professional, concise reply (under 150 words)
2. Acknowledge the key points from their email
3. Use a warm but professional tone
4. If they asked a question, provide a thoughtful response or indicate you'll follow up
5. If it's a meeting request, express interest and ask for timing
6. If it's urgent, acknowledge the urgency
7. Sign off as "[Your Name]" (the user will replace this)
8. Do NOT include a subject line, only the email body

Generate the reply now:"""

            # Call Gemini API with new SDK
            response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=prompt
            )
            
            draft = response.text.strip()
            
            # Validate response
            if not draft or len(draft) < 20:
                raise ValueError("Generated response too short")
            
            return draft
            
        except Exception as e:
            # Fallback to heuristic templates
            import logging
            logging.error(f"Gemini API error: {e}. Falling back to templates.")
            return cls._fallback_template(sender, subject, body)
    
    @classmethod
    def _fallback_template(cls, sender, subject, body):
        """Fallback heuristic templates when API fails."""
        sender_name = sender.split("<")[0].strip().replace('"', '') or "there"
        text = (subject + " " + body).lower()
        
        # Simple intent detection
        if any(x in text for x in ['meeting', 'schedule', 'call', 'zoom']):
            return f"Hi {sender_name},\n\nThank you for reaching out. I'd be happy to connect. Please let me know what times work best for you this week.\n\nBest regards,\n[Your Name]"
        
        elif any(x in text for x in ['urgent', 'asap', 'immediate']):
            return f"Hello {sender_name},\n\nI have received your urgent message and am looking into this immediately. I will get back to you as soon as possible.\n\nBest,\n[Your Name]"
        
        elif any(x in text for x in ['offer', 'position', 'role', 'hiring']):
            return f"Dear {sender_name},\n\nThank you for considering me for this opportunity. I am very interested and would love to discuss the role further. Please let me know the next steps.\n\nSincerely,\n[Your Name]"
        
        else:
            return f"Hi {sender_name},\n\nThank you for your email. I have reviewed your message and will get back to you shortly with a detailed response.\n\nBest regards,\n[Your Name]"
