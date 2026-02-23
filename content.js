// content.js
// This script runs in the context of web pages

// Configuration
const CONFIG = {
  SENSITIVE_KEYWORDS: [
    'verify your account',
    'confirm your identity',
    'update your information',
    'your account has been limited',
    'unusual activity',
    'security alert',
    'password expired',
    'enter your credentials',
    'verify your payment',
    'confirm your details',
    'account suspended',
    'security verification',
    'login required',
    'account access',
    'verify your email'
  ],
  SUSPICIOUS_DOMAINS: [
    'login-',
    'account-',
    'verify-',
    'secure-',
    'update-',
    'confirm-'
  ],
  WARNING_STYLES: {
    high: {
      backgroundColor: '#ff0000',
      color: 'white',
      borderColor: '#cc0000'
    },
    medium: {
      backgroundColor: '#ffcc00',
      color: 'black',
      borderColor: '#cc9900'
    },
    error: {
      backgroundColor: '#666666',
      color: 'white',
      borderColor: '#444444'
    }
  }
};

// Track last checked URL to prevent duplicate checks
let lastCheckedUrl = null;
let lastCheckTime = 0;
const MIN_CHECK_INTERVAL = 5000; // 5 seconds

// Function to analyze the page content for phishing indicators
function analyzePageContent() {
  const pageContent = document.body.innerText.toLowerCase();
  const url = window.location.href;
  const domain = window.location.hostname;

  const analysis = {
    url: url,
    domain: domain,
    title: document.title,
    hasLoginForm: checkForLoginForm(),
    hasSensitiveKeywords: checkForSensitiveKeywords(pageContent),
    hasSuspiciousDomain: checkSuspiciousDomain(domain),
    hasSuspiciousForms: checkSuspiciousForms(),
    hasExternalLinks: checkExternalLinks()
  };

  // Send data to background script for further analysis
  chrome.runtime.sendMessage({
    action: 'analyzeContent',
    data: analysis
  });
}

// Check if the page has a login form
function checkForLoginForm() {
  // 1. Есть ли поле password?
  const passwordFields = Array.from(document.querySelectorAll('input[type="password"]'));
  if (passwordFields.length === 0) return false;

  for (const passwordField of passwordFields) {
    const form = passwordField.closest('form');
    if (form) {
      // Если в форме есть хотя бы 2 input'а (например, username/email + password)
      const inputs = form.querySelectorAll('input');
      if (inputs.length >= 2) return true;

      // Есть ли кнопка submit в форме?
      const submitBtn = form.querySelector('button[type="submit"],input[type="submit"]');
      if (submitBtn) return true;
    }
  }
  // Если есть хотя бы один password field вне формы — тоже считаем как login form
  if (passwordFields.length > 0) return true;

  return false;
}

// Check for sensitive keywords that might indicate phishing
function checkForSensitiveKeywords(content) {
  return CONFIG.SENSITIVE_KEYWORDS.some(keyword => 
    content.includes(keyword.toLowerCase())
  );
}

// Check for suspicious domain patterns
function checkSuspiciousDomain(domain) {
  return CONFIG.SUSPICIOUS_DOMAINS.some(pattern => 
    domain.includes(pattern)
  );
}

// Check for suspicious form patterns
function checkSuspiciousForms() {
  const forms = document.querySelectorAll('form');
  const suspiciousPatterns = [
    'action="http://"',
    'action="https://"',
    'method="get"',
    'autocomplete="off"'
  ];

  for (const form of forms) {
    const formHtml = form.outerHTML.toLowerCase();
    if (suspiciousPatterns.some(pattern => formHtml.includes(pattern))) {
      return true;
    }
  }
  return false;
}

// Check for external links in forms
function checkExternalLinks() {
  const forms = document.querySelectorAll('form');
  const currentDomain = window.location.hostname;

  for (const form of forms) {
    if (form.action && !form.action.includes(currentDomain)) {
      return true;
    }
  }
  return false;
}

// Create and inject warning banner
function createWarningBanner(message, type) {
    // Remove existing banner if any
    removeWarningBanner();
  
  const banner = document.createElement('div');
  banner.id = 'phishing-warning-banner';
    banner.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        padding: 10px;
        text-align: center;
        font-family: Arial, sans-serif;
        font-size: 14px;
        z-index: 999999;
        display: flex;
        justify-content: center;
        align-items: center;
        gap: 10px;
    `;

    // Set banner style based on type
    switch (type) {
        case 'phishing':
            banner.style.backgroundColor = '#ff4444';
            banner.style.color = 'white';
            break;
        case 'suspicious':
            banner.style.backgroundColor = '#ffbb33';
            banner.style.color = 'black';
            break;
        case 'error':
            banner.style.backgroundColor = '#ff4444';
            banner.style.color = 'white';
            break;
        default:
            banner.style.backgroundColor = '#ffbb33';
            banner.style.color = 'black';
    }

    // Add message
    const messageSpan = document.createElement('span');
    messageSpan.textContent = message;
    banner.appendChild(messageSpan);

    // Add close button
  const closeButton = document.createElement('button');
    closeButton.textContent = '×';
    closeButton.style.cssText = `
        background: none;
        border: none;
        color: inherit;
        font-size: 20px;
        cursor: pointer;
        padding: 0 5px;
    `;
    closeButton.onclick = removeWarningBanner;
  banner.appendChild(closeButton);

    // Insert banner at the top of the page
    document.body.insertBefore(banner, document.body.firstChild);
}

// Remove warning banner
function removeWarningBanner() {
    const existingBanner = document.getElementById('phishing-warning-banner');
    if (existingBanner) {
        existingBanner.remove();
      }
}

// Check if URL should be checked
function shouldCheckUrl(url) {
    const now = Date.now();
    if (url === lastCheckedUrl && (now - lastCheckTime) < MIN_CHECK_INTERVAL) {
        return false;
    }
    lastCheckedUrl = url;
    lastCheckTime = now;
    return true;
  }

// Check current URL
async function checkCurrentUrl() {
    const url = window.location.href;
    if (!shouldCheckUrl(url)) {
        console.log('Skipping URL check - too soon since last check');
        return;
    }
    try {
        await chrome.runtime.sendMessage({
            action: 'checkUrl',
            url: url
        });
        // Не вызываем processUrlCheck, баннеры строятся только по phishing-alert
    } catch (error) {
        console.error('Error checking URL:', error);
        createWarningBanner('Error checking URL. Please try again later.', 'error');
    }
}

function getDomAnalysisWithLogging() {
    try {
        const pageContent = document.body ? document.body.innerText.toLowerCase() : '';
        const domain = window.location.hostname;
        const domAnalysis = {
            hasLoginForm: checkForLoginForm(),
            hasSensitiveKeywords: checkForSensitiveKeywords(pageContent),
            hasSuspiciousDomain: checkSuspiciousDomain(domain),
            hasSuspiciousForms: checkSuspiciousForms(),
            hasExternalLinks: checkExternalLinks()
        };
        console.log('[content.js] DOM Analysis result:', domAnalysis);
        return domAnalysis;
    } catch (error) {
        console.error('[content.js] Error in DOM analysis:', error);
        return null;
    }
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'checkCurrentUrl') {
        checkCurrentUrl();
    } else if (request.action === 'getDomFeatures') {
        const features = extractDomFeatures();
        sendResponse({ features: features });
    } else if (request.action === 'getDomAnalysis') {
        // Ensure we have a valid document
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
                const domAnalysis = getDomAnalysisWithLogging();
                sendResponse({ domAnalysis });
            }, { once: true });
        } else {
            const domAnalysis = getDomAnalysisWithLogging();
            sendResponse({ domAnalysis });
        }
        return true; // Keep the message channel open for async response
    } else if (request.type === 'phishing-alert') {
        // Строгая проверка: показываем баннер только если есть валидный score и riskLevel
        if (
            typeof request.score !== 'number' ||
            isNaN(request.score) ||
            request.score < 0 ||
            request.score > 100 ||
            !['high', 'medium', 'low', 'error'].includes(request.riskLevel)
        ) {
            console.warn('Phishing banner: invalid data', request);
            removeWarningBanner(); // Убираем баннер, если данные невалидны
            return;
        }
        // Для whitelist всегда зелёный баннер
        if (request.score === 10 && request.riskLevel === 'low') {
            chrome.storage.local.get(['settings'], (result) => {
                const settings = result.settings || {};
                if (settings.showWarnings !== false) {
                    createWarningBanner('This site is in the whitelist and considered safe.', 'safe');
                }
            });
            return;
        }
        // Для model
        let bannerType = 'suspicious';
        if (request.riskLevel === 'high') bannerType = 'phishing';
        if (request.riskLevel === 'medium') bannerType = 'suspicious';
        if (request.riskLevel === 'low') bannerType = 'safe';
        if (request.riskLevel === 'error') bannerType = 'error';

        let bannerText = '';
        if (request.riskLevel === 'high') {
            bannerText = `Warning: This site has a ${request.score?.toFixed(1) ?? '?'}% chance of being a phishing site!`;
        } else if (request.riskLevel === 'medium') {
            bannerText = `Caution: This site has a ${request.score?.toFixed(1) ?? '?'}% chance of being suspicious.`;
        } else if (request.riskLevel === 'low') {
            bannerText = `This site appears to be safe.`;
        } else if (request.riskLevel === 'error') {
            bannerText = 'Error checking URL. Please try again later.';
        } else {
            removeWarningBanner(); // Не показываем баннер вообще
            return;
        }

        chrome.storage.local.get(['settings'], (result) => {
            const settings = result.settings || {};
            if (settings.showWarnings !== false) {
                createWarningBanner(bannerText, bannerType);
            }
        });
    }
    return true;
});

function extractDomFeatures() {
    try {
        const html = document.documentElement.innerHTML;
        return [
            /<a\s+href/i.test(html) ? 1 : 0, // AnchorURL
            /<script\s+src/i.test(html) ? 1 : 0, // LinksInScriptTags
            /<form\s+action/i.test(html) ? 1 : 0, // ServerFormHandler
            /window\.location/i.test(html) ? 1 : 0, // WebsiteForwarding
            /oncontextmenu/i.test(html) ? 1 : 0, // StatusBarCust
            /oncontextmenu/i.test(html) ? 1 : 0, // DisableRightClick
            /window\.open/i.test(html) ? 1 : 0, // UsingPopupWindow
            /<iframe/i.test(html) ? 1 : 0 // IframeRedirection
        ];
    } catch (error) {
        console.error("Error extracting DOM features:", error);
        return Array(8).fill(0);
    }
}

// Check URL when page loads
document.addEventListener('DOMContentLoaded', () => {
    // Wait a bit to let the page fully load
    setTimeout(checkCurrentUrl, 1000);
});

// Check URL when navigation occurs (for SPAs)
let lastUrl = location.href;
new MutationObserver(() => {
    const currentUrl = location.href;
    if (currentUrl !== lastUrl) {
        lastUrl = currentUrl;
        checkCurrentUrl();
    }
}).observe(document, { subtree: true, childList: true });

// Дополнительная обработка pushState/popstate для SPA
window.addEventListener('popstate', checkCurrentUrl);
(function(history){
    var pushState = history.pushState;
    history.pushState = function(state) {
        if (typeof history.onpushstate == "function") {
            history.onpushstate({state: state});
        }
        setTimeout(checkCurrentUrl, 100);
        return pushState.apply(history, arguments);
    };
})(window.history);