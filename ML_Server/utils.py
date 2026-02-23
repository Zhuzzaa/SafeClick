from urllib.parse import urlparse
import re
import pandas as pd
import numpy as np
from collections import Counter
import tldextract


def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return all([parsed.scheme in ('http', 'https'), parsed.netloc])
    except Exception:
        return False


def extract_features_from_url(url):
    """
    Extract features from a URL using the enhanced feature extraction system.
    Returns a list of features compatible with the new model.
    """
    try:
        # Базовый парсинг URL
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
        
        # Извлечение домена и TLD
        ext = tldextract.extract(url)
        domain_name = ext.domain
        tld = ext.suffix
        
        # Список подозрительных TLD
        suspicious_tlds = {'xyz', 'tk', 'info', 'top', 'work', 'click', 'loan', 'bid', 'win', 'review'}
        
        # Список подозрительных слов
        suspicious_words = {
            'secure', 'login', 'verify', 'account', 'banking', 'paypal', 'signin', 'signup',
            'password', 'confirm', 'update', 'security', 'validate', 'authenticate', 'support',
            'customer', 'service', 'help', 'verify', 'validation', 'secure', 'security',
            'login', 'signin', 'signup', 'account', 'banking', 'paypal', 'password',
            'confirm', 'update', 'validate', 'authenticate', 'support', 'customer',
            'service', 'help', 'verify', 'validation'
        }
        
        # Список сервисов сокращения ссылок
        shortening_services = {
            'bit.ly', 'goo.gl', 't.co', 'tinyurl', 'is.gd', 'cli.gs', 'ow.ly', 'yfrog',
            'migre.me', 'ff.im', 'tiny.cc', 'url4.eu', 'tr.im', 'twit.ac', 'su.pr',
            'twurl.nl', 'snipurl', 'short.to', 'BudURL', 'ping.fm', 'post.ly', 'Just.as',
            'bkite', 'snipr', 'fic.kr', 'loopt.us', 'htxt.it', 'alturl', 'redir.ec',
            'tiny.pl', 'urlx.ie', 'twitthis', 'htxt.it', 'alturl', 'redir.ec', 'tiny.pl',
            'urlx.ie', 'twitthis', 'htxt.it', 'alturl', 'redir.ec', 'tiny.pl', 'urlx.ie'
        }

        features = {
            'url_length': len(url),
            'domain_length': len(domain),
            'num_dots': url.count('.'),
            'num_slashes': url.count('/'),
            'num_hyphens': url.count('-'),
            'num_underscores': url.count('_'),
            'num_question_marks': url.count('?'),
            'num_equals': url.count('='),
            'num_at': url.count('@'),
            'num_and': url.count('&'),
            'num_exclamation': url.count('!'),
            'num_spaces': url.count(' '),
            'num_tildes': url.count('~'),
            'num_commas': url.count(','),
            'num_plus': url.count('+'),
            'num_asterisks': url.count('*'),
            'num_hashes': url.count('#'),
            'num_dollars': url.count('$'),
            'num_percent': url.count('%'),
            'num_special_chars': sum(url.count(c) for c in '!@#$%^&*()_+-=[]{}|;:,.<>?/~'),
            'has_https': int(parsed.scheme == 'https'),
            'has_ip': int(bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', url))),
            'has_port': int(':' in domain),
            'has_query': int(bool(query)),
            'has_anchor': int('#' in url),
            'has_digits_in_domain': int(bool(re.search(r'\d', domain_name))),
            'suspicious_tld': int(tld in suspicious_tlds),
            'num_subdomains': len(ext.subdomain.split('.')) if ext.subdomain else 0,
            'is_shortening_service': int(any(service in domain for service in shortening_services)),
            'suspicious_words_count': sum(1 for word in suspicious_words if word in url.lower()),
            'path_length': len(path),
            'query_length': len(query),
            'domain_entropy': -sum((count/len(domain)) * np.log2(count/len(domain)) 
                                 for count in Counter(domain).values()) if domain else 0,
            'path_entropy': -sum((count/len(path)) * np.log2(count/len(path)) 
                               for count in Counter(path).values()) if path else 0,
            'query_entropy': -sum((count/len(query)) * np.log2(count/len(query)) 
                                for count in Counter(query).values()) if query else 0
        }
        
        # Define feature order to match model's expectations
        feature_order = [
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

        # Return features in the correct order
        return [features[feature] for feature in feature_order]
    
    except Exception as e:
        print(f"Error extracting features from URL {url}: {str(e)}")
        return None

def normalize_features(features):
    """
    Normalize features to ensure compatibility with the model.
    """
    features = np.array(features)
    features = np.clip(features, 0, 1)
    return features.tolist()
