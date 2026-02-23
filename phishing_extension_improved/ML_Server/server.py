from flask import Flask, request, jsonify
import joblib
import numpy as np
from utils import extract_features_from_url, normalize_features
import logging
import requests
import os
from server.whitelist import check_virustotal

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Load the model
try:
    model = joblib.load('model/phishing_model.pkl')
    logger.info("Model loaded successfully")
except Exception as e:
    logger.error(f"Error loading model: {str(e)}")
    raise

def google_safe_browsing(url, api_key):
    """Check URL against Google Safe Browsing API"""
    try:
        endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        headers = {'Content-Type': 'application/json'}
        params = {'key': api_key}
        body = {
            "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        response = requests.post(endpoint, params=params, json=body, headers=headers, timeout=5)
        if response.status_code == 200:
            result = response.json()
            if 'matches' in result and result['matches']:
                logger.info(f"Google Safe Browsing found threats: {result['matches']}")
                return 1
            return 0
        elif response.status_code == 204:
            return 0
        else:
            logger.warning(f"Google Safe Browsing API error: {response.status_code} - {response.text}")
            return 0
    except Exception as e:
        logger.error(f"Error in Google Safe Browsing check: {e}")
        return 0

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'No URL provided'}), 400

        url = data['url']
        logger.info(f"Received prediction request for URL: {url}")

        # Extract features
        features = extract_features_from_url(url)
        logger.info(f"Extracted features: {features}")

        # Make prediction
        prediction = model.predict([features])[0]
        probability = model.predict_proba([features])[0]
        probability_percent = float(probability[1]) * 100
        
        logger.info(f"Prediction: {prediction}, Probability: {probability_percent}")

        # Check Google Safe Browsing
        # Use user-provided API key if available, otherwise use environment variable or default
        api_keys = data.get('apiKeys', {})
        gsb_api_key = (
            api_keys.get('googleSafeBrowsing') or 
            os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or 
            "AIzaSyBX4GIjERaI6Cl7yMwKo1fKIef9uIEaFsE"
        )
        gsb_flag = google_safe_browsing(url, gsb_api_key)
        gsb_status = 'dangerous' if gsb_flag == 1 else 'safe'

        # Build response with security_checks structure
        response_data = {
            'result': probability_percent,
            'prediction': int(prediction),
            'status': 'success',
            'features': features,
            'security_checks': {
                'model': {
                    'status': 'dangerous' if probability_percent >= 50 else 'safe',
                    'confidence': probability_percent,
                    'checked': True
                },
                'google_safe_browsing': {
                    'status': gsb_status,
                    'flagged': bool(gsb_flag),
                    'checked': True
                }
            }
        }

        # VirusTotal check (best-effort; may be rate-limited)
        # Use user-provided API key if available
        vt_api_key = api_keys.get('virusTotal') if api_keys else None
        try:
            if vt_api_key:
                # Pass custom API key to check_virustotal if function supports it
                # For now, we'll need to update whitelist.py to accept API key parameter
                vt_safe, vt_score, vt_status = check_virustotal(url, vt_api_key)
            else:
                vt_safe, vt_score, vt_status = check_virustotal(url)
        except Exception:
            vt_safe, vt_score, vt_status = None, None, 'error'
        response_data['security_checks']['virustotal'] = {
            'status': 'unavailable' if vt_status != 'success' else ('safe' if vt_safe else 'dangerous'),
            'score': float(vt_score * 100) if vt_score is not None else None,
            'checked': vt_status == 'success',
            'status_detail': vt_status
        }

        return jsonify(response_data)

    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000) 