# Whitelist configuration
WHITELIST = {
    # Major tech companies
    'google.com': 0.1,
    'microsoft.com': 0.1,
    'apple.com': 0.1,
    'amazon.com': 0.1,
    'facebook.com': 0.1,
    'twitter.com': 0.1,
    'linkedin.com': 0.1,
    'github.com': 0.1,
    
    # Major banks
    'chase.com': 0.1,
    'bankofamerica.com': 0.1,
    'wellsfargo.com': 0.1,
    'citibank.com': 0.1,
    
    # Government sites
    'gov': 0.1,
    'edu': 0.1,
    
    # Popular services
    'netflix.com': 0.1,
    'spotify.com': 0.1,
    'youtube.com': 0.1,
    'instagram.com': 0.1,
    'reddit.com': 0.1,
    
    # Security companies
    'microsoft.com/security': 0.1,
    'google.com/safety': 0.1,
    'mozilla.org/security': 0.1,
}

# API Keys (should be moved to environment variables in production)
import os
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "83d060e81e061cca8a72e727fb5bb2048e76d0d42ab14cc0eaab4da96d4b56fa")  # VirusTotal API key (fallback)

def is_whitelisted(url):
    """
    Check if URL is in whitelist
    Returns (is_whitelisted, risk_score)
    """
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check exact matches
        if domain in WHITELIST:
            return True, WHITELIST[domain]
            
        # Check for subdomains of whitelisted domains
        for whitelisted_domain, score in WHITELIST.items():
            if domain.endswith('.' + whitelisted_domain):
                return True, score
                
        # Check for TLD matches (gov, edu)
        tld = domain.split('.')[-1]
        if tld in WHITELIST:
            return True, WHITELIST[tld]
            
        return False, None
    except:
        return False, None

def check_virustotal(url, api_key=None):
    """
    Check URL against VirusTotal API
    Returns (is_safe, confidence_score, status)
    Args:
        url: URL to check
        api_key: Optional custom API key (if None, uses default from VIRUSTOTAL_API_KEY)
    """
    try:
        import requests
        import time
        
        # Use custom API key if provided, otherwise use default
        vt_api_key = api_key or VIRUSTOTAL_API_KEY
        
        # First, submit URL for scanning
        scan_url = "https://www.virustotal.com/vtapi/v2/url/scan"
        params = {'apikey': vt_api_key, 'url': url}
        response = requests.post(scan_url, data=params)
        
        if response.status_code == 204:  # Rate limit exceeded
            return None, None, "rate_limit"
        elif response.status_code != 200:
            return None, None, "error"
            
        # Wait a bit for scan to complete
        time.sleep(2)
        
        # Get report
        report_url = "https://www.virustotal.com/vtapi/v2/url/report"
        params = {'apikey': vt_api_key, 'resource': url}
        response = requests.get(report_url, params=params)
        
        if response.status_code == 204:  # Rate limit exceeded
            return None, None, "rate_limit"
        elif response.status_code != 200:
            return None, None, "error"
            
        result = response.json()
        
        # Calculate safety score based on positive/negative detections
        positives = result.get('positives', 0)
        total = result.get('total', 0)
        
        if total == 0:
            return None, None, "no_data"
            
        safety_score = 1 - (positives / total)
        
        # Consider safe if less than 5% of engines detect it as malicious
        is_safe = safety_score > 0.95
        
        return is_safe, safety_score, "success"
        
    except Exception as e:
        print(f"Error checking VirusTotal: {e}")
        return None, None, "error" 