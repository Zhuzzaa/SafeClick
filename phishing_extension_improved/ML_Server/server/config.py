import os

# Server configuration
SERVER_CONFIG = {
    'host': 'localhost',
    'port': 5000,
    'debug': False,  # Disable debug mode in production
    'threaded': True,
    'timeout': 30  # Request timeout in seconds
}

# Model configuration
MODEL_CONFIG = {
    'model_path': os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'model', 'phishing_model.pkl')),
    'prediction_threshold': 50,
    'model_type': 'random_forest',
    'cache_timeout': 5,  # Cache predictions for 5 seconds
    'max_url_length': 2048,  # Maximum URL length to process
    'min_url_length': 10  # Minimum URL length to process
}

# CORS configuration
CORS_CONFIG = {
    'origins': ['chrome-extension://*'],  # Only allow Chrome extension
    'methods': ['GET', 'POST', 'OPTIONS'],
    'allow_headers': ['Content-Type'],
    'max_age': 3600  # Cache preflight requests for 1 hour
}

# Logging configuration
LOGGING_CONFIG = {
    'level': 'INFO',  # Set to INFO for production
    'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    'max_bytes': 10485760,  # 10MB
    'backup_count': 5
}

# Security configuration
SECURITY_CONFIG = {
    'rate_limit': {
        'requests_per_minute': 60,
        'burst': 10
    },
    'allowed_protocols': ['http', 'https'],
    'blocked_domains': [
        'localhost',
        '127.0.0.1',
        '0.0.0.0'
    ]
} 