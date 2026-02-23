from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import numpy as np
import os
import sys
import logging
import traceback
from logging.config import dictConfig
from functools import lru_cache
import time
import requests
from whitelist import is_whitelisted, check_virustotal

# Add path to utils.py in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils import extract_features_from_url, normalize_features, is_valid_url
from config import SERVER_CONFIG, MODEL_CONFIG, CORS_CONFIG, LOGGING_CONFIG

# Configure logging
dictConfig({
    'version': 1,
    'formatters': {
        'default': {
            'format': LOGGING_CONFIG['format']
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'default',
            'stream': 'ext://sys.stdout'
        }
    },
    'root': {
        'level': LOGGING_CONFIG['level'],
        'handlers': ['console']
    }
})

app = Flask(__name__)
CORS(app, resources={
    r"/*": {
        "origins": CORS_CONFIG['origins'],
        "methods": CORS_CONFIG['methods'],
        "allow_headers": CORS_CONFIG['allow_headers']
    }
})

# Cache for predictions to prevent duplicate requests
prediction_cache = {}
CACHE_TIMEOUT = 5  # seconds

def get_cached_prediction(url):
    current_time = time.time()
    if url in prediction_cache:
        timestamp, result = prediction_cache[url]
        if current_time - timestamp < CACHE_TIMEOUT:
            return result
    return None

def set_cached_prediction(url, result):
    prediction_cache[url] = (time.time(), result)

# Load model
try:
    if not os.path.exists(MODEL_CONFIG['model_path']):
        raise FileNotFoundError(f"Model not found at: {MODEL_CONFIG['model_path']}")

    model_data = joblib.load(MODEL_CONFIG['model_path'])
    logging.info(f"Loaded model data type: {type(model_data)}")
    
    if isinstance(model_data, dict):
        model = model_data['model']
        feature_names = model_data['feature_names']
        logging.info(f"Loaded model from dictionary with {len(feature_names)} features")
    else:
        model = model_data
        if hasattr(model, 'feature_names_in_'):
            feature_names = model.feature_names_in_.tolist()
            logging.info(f"Model expects features: {feature_names}")
        else:
            feature_names = [
                'url_length', 'domain_length', 'num_dots', 'num_slashes',
                'num_hyphens', 'num_underscores', 'num_question_marks',
                'num_equals', 'num_at', 'num_and', 'num_exclamation',
                'num_spaces', 'num_tildes', 'num_commas', 'num_plus',
                'num_asterisks', 'num_hashes', 'num_dollars', 'num_percent',
                'num_special_chars', 'has_https', 'has_ip', 'has_port',
                'has_query', 'has_anchor', 'has_digits_in_domain',
                'suspicious_tld', 'num_subdomains', 'is_shortening_service',
                'suspicious_words_count', 'path_length', 'query_length',
                'domain_entropy', 'path_entropy', 'query_entropy'
            ]
            logging.info(f"Using default feature names: {feature_names}")

    MODEL_CONFIG['feature_count'] = len(feature_names)
    logging.info(f"Model expects {len(feature_names)} features")
    logging.info("Model loaded successfully")
except Exception as e:
    logging.error(f"Error loading model: {e}")
    logging.error(traceback.format_exc())
    raise

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None,
        'feature_count': len(feature_names),
        'model_type': MODEL_CONFIG['model_type'],
        'feature_names': feature_names
    })

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        logging.info(f"Received prediction request with data: {data}")

        if not data:
            logging.error("Empty request body received")
            return jsonify({
                'error': 'Invalid input, request body is required',
                'status': 'error'
            }), 400

        # --- Критично: если есть features, работаем только с ними! ---
        if 'features' in data:
            features = data['features']
            logging.info(f"Features received: {features}")
            for idx, val in enumerate(features):
                name = feature_names[idx] if idx < len(feature_names) else f"EXTRA_{idx}"
                logging.info(f"{idx}: {name} = {val}")

            # Проверяем только features, не трогаем url!
            if len(features) != len(feature_names):
                logging.error(f"Invalid feature count: got {len(features)}, expected {len(feature_names)}")
                return jsonify({
                    'error': f'Invalid number of features. Expected {len(feature_names)}, got {len(features)}',
                    'status': 'error'
                }), 400

            # Предсказание только по features
            try:
                input_data = pd.DataFrame([features], columns=feature_names)
                logging.info(f"Input data shape: {input_data.shape}")
                logging.info(f"Input data columns: {input_data.columns.tolist()}")
                
                prediction = model.predict(input_data)
                logging.info(f"Raw prediction: {prediction}")
                
                probability = model.predict_proba(input_data)[0][1] * 100
                logging.info(f"Probability: {probability}")

                result = {
                    'result': float(probability),
                    'prediction': int(prediction[0]),
                    'status': 'success',
                    'threshold': MODEL_CONFIG['prediction_threshold'],
                    'features': dict(zip(feature_names, features))
                }

                logging.info(f"Prediction completed: {result}")
                return jsonify(result)

            except Exception as e:
                logging.error(f"Error during model prediction: {e}")
                logging.error(traceback.format_exc())
                return jsonify({
                    'error': f'Error during model prediction: {str(e)}',
                    'status': 'error'
                }), 500

        # --- Если features нет, работаем по url ---
        elif 'url' in data:
            url = data['url'].strip()
            logging.info(f"Processing URL: {url}")

            # Check cache first
            cached_result = get_cached_prediction(url)
            if cached_result:
                logging.info(f"Returning cached prediction for {url}")
                return jsonify(cached_result)

            # Validate URL
            if not is_valid_url(url):
                logging.error(f"Invalid URL received: {url}")
                return jsonify({
                    'error': 'Invalid URL format. URL must start with http:// or https:// and contain a valid domain.',
                    'status': 'error'
                }), 400

            # Этап 1: Проверка whitelist
            is_white, white_score = is_whitelisted(url)
            whitelist_status = {
                'status': 'safe' if is_white else 'not_whitelisted',
                'score': float(white_score * 100) if is_white else None,
                'checked': True
            }

            try:
                # Этап 2: Проверка моделью
                features = extract_features_from_url(url)
                logging.info(f"Raw features: {features}")

                if len(features) != len(feature_names):
                    logging.error(f"Invalid feature count: got {len(features)}, expected {len(feature_names)}")
                    return jsonify({
                        'error': f'Invalid number of features. Expected {len(feature_names)}, got {len(features)}',
                        'status': 'error'
                    }), 400

                input_data = pd.DataFrame([features], columns=feature_names)
                prediction = model.predict(input_data)
                probability = model.predict_proba(input_data)[0][1] * 100
                
                # Определяем результаты от разных источников
                model_analysis = {
                    'thinks': 'dangerous' if probability >= MODEL_CONFIG['prediction_threshold'] else 'safe',
                    'confidence': float(probability)
                }

                # Проверка Google Safe Browsing
                api_key = "AIzaSyBVRfUYnn9e2V-8ZLBG0cFsXlafr615kHY"  # TODO: вынести в конфиг
                gsb_flag = google_safe_browsing(url, api_key)
                gsb_analysis = {
                    'thinks': 'dangerous' if gsb_flag == 1 else 'safe',
                    'flagged': bool(gsb_flag)
                }

                # Проверка VirusTotal
                vt_safe, vt_score, vt_status = check_virustotal(url)
                vt_analysis = {
                    'thinks': 'unavailable' if vt_status != "success" else ('safe' if vt_safe else 'dangerous'),
                    'score': float(vt_score * 100) if vt_score is not None else None,
                    'status': vt_status
                }

                # Рассчитываем общий риск скор
                # База - результат модели
                combined_risk = probability

                # Если URL в whitelist, снижаем риск на 20%
                if is_white:
                    combined_risk = max(0, combined_risk - 20)

                # Если GSB определил как опасный, увеличиваем риск на 20%
                if gsb_flag == 1:
                    combined_risk = min(100, combined_risk + 20)

                # Если VT определил как опасный и проверка успешна, увеличиваем риск на 10%
                if vt_safe is not None and not vt_safe and vt_status == "success":
                    combined_risk = min(100, combined_risk + 10)

                # Если оба сервиса определили как опасный, дополнительно увеличиваем риск
                if gsb_flag == 1 and vt_safe is not None and not vt_safe and vt_status == "success":
                    combined_risk = min(100, combined_risk + 10)

                # Формируем сообщения для каждого источника
                model_message = f"Our model thinks: {'Dangerous' if model_analysis['thinks'] == 'dangerous' else 'Safe'}"
                gsb_message = f"Google Safe Browsing thinks: {'Dangerous' if gsb_analysis['thinks'] == 'dangerous' else 'Safe'}"
                vt_message = f"VirusTotal: {'Unavailable (rate limit)' if vt_status == 'rate_limit' else 'Unavailable' if vt_status != 'success' else 'Dangerous' if vt_analysis['thinks'] == 'dangerous' else 'Safe'}"
                whitelist_message = f"Whitelist status: {'In whitelist' if is_white else 'Not in whitelist'}"

                result = {
                    'status': 'success',
                    'prediction': 1 if probability >= MODEL_CONFIG['prediction_threshold'] else 0,
                    'result': float(probability),
                    'note': f"{model_message}\n{gsb_message}\n{vt_message}\n{whitelist_message}",
                    'threshold': MODEL_CONFIG['prediction_threshold'],
                    'detailed_analysis': {
                        'model_analysis': model_analysis,
                        'google_safe_browsing': gsb_analysis,
                        'virustotal': vt_analysis,
                        'whitelist': whitelist_status,
                        'risk_scores': {
                            'model': float(probability),
                            'combined': float(combined_risk)
                        }
                    },
                    'security_checks': {
                        'whitelist': whitelist_status,
                        'model': {
                            'status': model_analysis['thinks'],
                            'confidence': float(probability),
                            'checked': True
                        },
                        'google_safe_browsing': {
                            'status': 'dangerous' if gsb_flag == 1 else 'safe',
                            'flagged': bool(gsb_flag),
                            'checked': True
                        },
                        'virustotal': {
                            'status': 'unavailable' if vt_status != 'success' else ('safe' if vt_safe else 'dangerous'),
                            'score': float(vt_score * 100) if vt_score is not None else None,
                            'checked': vt_status == 'success',
                            'status_detail': vt_status
                        }
                    },
                    'features': dict(zip(feature_names, features))
                }

                set_cached_prediction(url, result)
                logging.info(f"Prediction completed: {result}")
                return jsonify(result)

            except Exception as e:
                logging.error(f"Error during prediction: {e}")
                logging.error(traceback.format_exc())
                return jsonify({
                    'error': f'Error during prediction: {str(e)}',
                    'status': 'error'
                }), 500

        else:
            logging.error("No url or features in request")
            return jsonify({
                'error': 'Invalid input, either \"url\" or \"features\" key is required',
                'status': 'error'
            }), 400

    except Exception as e:
        logging.error(f"Error during prediction: {e}")
        logging.error(traceback.format_exc())
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

# --- Google Safe Browsing ---
def google_safe_browsing(url, api_key):
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
        response = requests.post(endpoint, params=params, json=body, headers=headers)
        if response.status_code == 200:
            result = response.json()
            if 'matches' in result:
                threats = result['matches']
                logging.info(f"Google Safe Browsing found threats: {threats}")
                return 1
            return 0
        elif response.status_code == 204:
            return 0
        else:
            logging.error(f"Google Safe Browsing API error: {response.status_code} - {response.text}")
            return 0
    except Exception as e:
        logging.error(f"Error in Google Safe Browsing check: {e}")
        return 0

if __name__ == '__main__':
    logging.info(f"Starting server on {SERVER_CONFIG['host']}:{SERVER_CONFIG['port']}")
    app.run(
        host=SERVER_CONFIG['host'],
        port=SERVER_CONFIG['port'],
        debug=SERVER_CONFIG['debug'],
        threaded=SERVER_CONFIG['threaded']
    )