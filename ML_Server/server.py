from flask import Flask, request, jsonify
import joblib
import numpy as np
from utils import extract_features_from_url, normalize_features
import logging

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
        
        logger.info(f"Prediction: {prediction}, Probability: {probability}")

        return jsonify({
            'result': float(probability[1]) * 100,  # Convert to percentage
            'prediction': int(prediction),
            'status': 'success',
            'features': features
        })

    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000) 