import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse, parse_qs
import os
import tldextract
from collections import Counter

def extract_url_features(url):
    """Извлекает признаки из URL."""
    try:
        # Нормализация URL - добавляем протокол если его нет
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        # Базовый парсинг URL
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
        
        # Извлечение домена и TLD
        ext = tldextract.extract(url)
        domain_name = ext.domain
        tld = ext.suffix
        
        # Удаляем протокол из URL для подсчета символов
        url_without_protocol = url.replace('http://', '').replace('https://', '')
        
        # Список подозрительных TLD
        suspicious_tlds = {'xyz', 'tk', 'info', 'top', 'work', 'click', 'loan', 'bid', 'win', 'review'}
        
        # Список подозрительных слов
        suspicious_words = {
            'secure', 'login', 'verify', 'account', 'banking', 'paypal', 'signin', 'signup',
            'password', 'confirm', 'update', 'security', 'validate', 'authenticate', 'support',
            'customer', 'service', 'help', 'verify', 'validation', 'secure', 'security',
            'login', 'signin', 'signup', 'account', 'banking', 'paypal', 'password',
            'confirm', 'update', 'validate', 'authenticate', 'support', 'customer',
            'service', 'help', 'verify', 'validation', 'secure', 'security', 'login',
            'signin', 'signup', 'account', 'banking', 'paypal', 'password', 'confirm',
            'update', 'validate', 'authenticate', 'support', 'customer', 'service',
            'help', 'verify', 'validation'
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
            'url_length': len(url_without_protocol),
            'domain_length': len(domain),
            'num_dots': url_without_protocol.count('.'),
            'num_slashes': url_without_protocol.count('/'),
            'num_hyphens': url_without_protocol.count('-'),
            'num_underscores': url_without_protocol.count('_'),
            'num_question_marks': url_without_protocol.count('?'),
            'num_equals': url_without_protocol.count('='),
            'num_at': url_without_protocol.count('@'),
            'num_and': url_without_protocol.count('&'),
            'num_exclamation': url_without_protocol.count('!'),
            'num_spaces': url_without_protocol.count(' '),
            'num_tildes': url_without_protocol.count('~'),
            'num_commas': url_without_protocol.count(','),
            'num_plus': url_without_protocol.count('+'),
            'num_asterisks': url_without_protocol.count('*'),
            'num_hashes': url_without_protocol.count('#'),
            'num_dollars': url_without_protocol.count('$'),
            'num_percent': url_without_protocol.count('%'),
            'num_special_chars': sum(url_without_protocol.count(c) for c in '!@#$%^&*()_+-=[]{}|;:,.<>?/~'),
            'has_https': int(parsed.scheme == 'https'),
            'has_ip': int(bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', url_without_protocol))),
            'has_port': int(':' in domain),
            'has_query': int(bool(query)),
            'has_anchor': int('#' in url_without_protocol),
            'has_digits_in_domain': int(bool(re.search(r'\d', domain_name))),
            'suspicious_tld': int(tld in suspicious_tlds),
            'num_subdomains': len(ext.subdomain.split('.')) if ext.subdomain else 0,
            'is_shortening_service': int(any(service in domain for service in shortening_services)),
            'suspicious_words_count': sum(1 for word in suspicious_words if word in url_without_protocol.lower()),
            'path_length': len(path),
            'query_length': len(query),
            'domain_entropy': -sum((count/len(domain)) * np.log2(count/len(domain)) 
                                 for count in Counter(domain).values()) if domain else 0,
            'path_entropy': -sum((count/len(path)) * np.log2(count/len(path)) 
                               for count in Counter(path).values()) if path else 0,
            'query_entropy': -sum((count/len(query)) * np.log2(count/len(query)) 
                                for count in Counter(query).values()) if query else 0
        }
        
        return features
    
    except Exception as e:
        print(f"Ошибка при обработке URL {url}: {str(e)}")
        return None

def process_dataset(input_path, output_path):
    """Обрабатывает датасет и извлекает признаки."""
    print("Загрузка датасета...")
    df = pd.read_csv(input_path)
    
    print(f"\nОбработка {len(df)} URL...")
    features_list = []
    for i, url in enumerate(df['url']):
        if i % 100000 == 0:
            print(f"Обработано {i} URL...")
        
        features = extract_url_features(url)
        if features:
            features_list.append(features)
        else:
            # Если не удалось извлечь признаки, добавляем строку с нулевыми значениями
            features_list.append({k: 0 for k in extract_url_features("http://example.com").keys()})
    
    print("\nСоздание DataFrame с признаками...")
    features_df = pd.DataFrame(features_list)
    
    # Добавляем исходные колонки
    features_df['url'] = df['url']
    features_df['class'] = df['class']
    
    # Сохраняем результат
    print(f"\nСохранение результата в {output_path}...")
    features_df.to_csv(output_path, index=False)
    
    # Вывод информации о признаках
    print("\nИнформация о признаках:")
    print(f"Количество признаков: {len(features_df.columns) - 2}")  # -2 для url и class
    print("\nСтатистика по признакам:")
    print(features_df.describe())
    
    return features_df

if __name__ == "__main__":
    input_path = os.path.join('data', 'malicious_phish_cleaned.csv')
    output_path = os.path.join('data', 'malicious_phish_features.csv')
    
    df = process_dataset(input_path, output_path) 