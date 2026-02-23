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

// Dynamic features tracking
const dynamicFeatures = {
  redirectsCount: 0,
  popupAttempts: 0,
  externalFormSubmissions: 0,
  dynamicallyCreatedForms: 0,
  hiddenForms: 0,
  evalUsage: false,
  externalRequests: 0,
  formDataToExternalDomains: false,
  suspiciousJavaScript: false,
  iframeRedirections: 0
};

// Track initial URL for redirect detection
let initialUrl = window.location.href;
let currentDomain = window.location.hostname;

// Initialize dynamic monitoring
function initializeDynamicMonitoring() {
  // Track redirects
  let lastUrl = window.location.href;
  const urlObserver = setInterval(() => {
    if (window.location.href !== lastUrl) {
      dynamicFeatures.redirectsCount++;
      lastUrl = window.location.href;
    }
  }, 500);

  // Track popup attempts
  const originalWindowOpen = window.open;
  window.open = function(...args) {
    dynamicFeatures.popupAttempts++;
    console.log('[Safe Click] Popup attempt detected:', args[0]);
    return originalWindowOpen.apply(this, args);
  };

  // Track eval usage
  const originalEval = window.eval;
  window.eval = function(...args) {
    dynamicFeatures.evalUsage = true;
    console.log('[Safe Click] eval() usage detected');
    return originalEval.apply(this, args);
  };

  // Track external requests (fetch)
  const originalFetch = window.fetch;
  window.fetch = function(...args) {
    try {
      const url = typeof args[0] === 'string' ? args[0] : args[0].url;
      if (url && !url.startsWith('/') && !url.startsWith(window.location.origin)) {
        dynamicFeatures.externalRequests++;
      }
    } catch (e) {}
    return originalFetch.apply(this, args);
  };

  // Track external requests (XMLHttpRequest)
  const originalXHROpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    try {
      if (url && !url.startsWith('/') && !url.startsWith(window.location.origin)) {
        dynamicFeatures.externalRequests++;
      }
    } catch (e) {}
    return originalXHROpen.call(this, method, url, ...rest);
  };

  // Track form submissions to external domains
  document.addEventListener('submit', (e) => {
    const form = e.target;
    if (form.tagName === 'FORM') {
      const action = form.action || form.getAttribute('action');
      if (action) {
        try {
          const actionUrl = new URL(action, window.location.origin);
          if (actionUrl.hostname !== currentDomain && actionUrl.hostname !== '') {
            dynamicFeatures.externalFormSubmissions++;
            dynamicFeatures.formDataToExternalDomains = true;
            console.log('[Safe Click] Form submission to external domain:', actionUrl.hostname);
          }
        } catch (err) {
          // Invalid URL, might be suspicious
          if (action && !action.startsWith('/') && !action.startsWith('#')) {
            dynamicFeatures.externalFormSubmissions++;
          }
        }
      }
    }
  }, true);

  // Track dynamically created forms
  const formObserver = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      mutation.addedNodes.forEach((node) => {
        if (node.nodeType === 1) { // Element node
          if (node.tagName === 'FORM') {
            dynamicFeatures.dynamicallyCreatedForms++;
            console.log('[Safe Click] Dynamically created form detected');
          }
          // Check for forms in added nodes
          const forms = node.querySelectorAll && node.querySelectorAll('form');
          if (forms && forms.length > 0) {
            dynamicFeatures.dynamicallyCreatedForms += forms.length;
          }
        }
      });
    });
  });

  formObserver.observe(document.body, {
    childList: true,
    subtree: true
  });

  // Track hidden forms
  function checkHiddenForms() {
    const forms = document.querySelectorAll('form');
    forms.forEach((form) => {
      const style = window.getComputedStyle(form);
      if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
        dynamicFeatures.hiddenForms++;
      }
      // Check if form is positioned off-screen
      const rect = form.getBoundingClientRect();
      if (rect.top < -1000 || rect.left < -1000) {
        dynamicFeatures.hiddenForms++;
      }
    });
  }

  // Check for suspicious JavaScript patterns
  function checkSuspiciousJavaScript() {
    const scripts = document.querySelectorAll('script');
    let suspiciousPatterns = 0;
    scripts.forEach((script) => {
      if (script.textContent) {
        const content = script.textContent.toLowerCase();
        // Check for obfuscation patterns
        if (content.includes('fromcharcode') || 
            content.includes('unescape') ||
            content.match(/\\x[0-9a-f]{2}/g) ||
            content.match(/\\u[0-9a-f]{4}/g)) {
          suspiciousPatterns++;
        }
        // Check for suspicious function calls
        if (content.includes('document.write') && content.length > 1000) {
          suspiciousPatterns++;
        }
      }
    });
    if (suspiciousPatterns > 2) {
      dynamicFeatures.suspiciousJavaScript = true;
    }
  }

  // Check for iframe redirections
  function checkIframeRedirections() {
    const iframes = document.querySelectorAll('iframe');
    iframes.forEach((iframe) => {
      try {
        const src = iframe.src || iframe.getAttribute('src');
        if (src) {
          const iframeUrl = new URL(src, window.location.origin);
          if (iframeUrl.hostname !== currentDomain) {
            dynamicFeatures.iframeRedirections++;
          }
        }
      } catch (e) {}
    });
  }

  // Periodic checks
  setTimeout(() => {
    checkHiddenForms();
    checkSuspiciousJavaScript();
    checkIframeRedirections();
  }, 2000);

  // Re-check periodically
  setInterval(() => {
    checkHiddenForms();
    checkIframeRedirections();
  }, 5000);
}

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

function getScoreDescriptor(score) {
  if (score >= 70) {
    return {
      label: 'High suspicion',
      color: '#ff6b6b',
      description: 'High likelihood of phishing. Proceed with extreme caution.'
    };
  }
  if (score >= 40) {
    return {
      label: 'Medium suspicion',
      color: '#fbbc04',
      description: 'Potentially risky. Double-check the URL and sender details.'
    };
  }
  return {
    label: 'Low suspicion',
    color: '#34a853',
    description: 'Few phishing indicators detected. Stay vigilant.'
  };
}

function getExternalStatusDescriptor(sourceName, check) {
  if (!check) {
    return {
      title: sourceName,
      value: 'Not checked',
      color: '#9e9e9e',
      description: 'No data available from this service.'
    };
  }
  const status = (check.status || 'unknown').toLowerCase();
  if (status === 'dangerous' || status === 'phishing' || status === 'malware' || check.flagged) {
    return {
      title: sourceName,
      value: 'Dangerous',
      color: '#ff6b6b',
      description: 'Service flagged this URL as potentially malicious.'
    };
  }
  if (status === 'safe') {
    return {
      title: sourceName,
      value: 'Safe',
      color: '#34a853',
      description: 'Service did not find known threats for this URL.'
    };
  }
  return {
    title: sourceName,
    value: 'Unknown',
    color: '#fbbc04',
    description: `Service returned status: ${check.status_detail || 'unavailable'}.`
  };
}

function createStatusRow(descriptor, extraText = '') {
  const row = document.createElement('div');
  row.style.cssText = `
    display:flex;
    flex-direction:column;
    gap:2px;
  `;
  const title = document.createElement('div');
  title.textContent = descriptor.title;
  title.style.cssText = 'font-size:11px;text-transform:uppercase;color:#9fa5ad;letter-spacing:0.06em;';
  const value = document.createElement('div');
  value.textContent = descriptor.value + (extraText ? ` ${extraText}` : '');
  value.style.cssText = `font-size:15px;font-weight:600;color:${descriptor.color};`;
  const description = document.createElement('div');
  description.textContent = descriptor.description;
  description.style.cssText = 'font-size:11px;color:#cfd3da;';
  row.appendChild(title);
  row.appendChild(value);
  row.appendChild(description);
  return row;
}

function formatDisplayUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.hostname + (parsed.pathname.length > 1 ? parsed.pathname : '');
  } catch (e) {
    return url;
  }
}

function renderSecurityBanner({ url, score, securityChecks }) {
  removeWarningBanner();
  const banner = document.createElement('div');
  banner.id = 'phishing-warning-banner';
  banner.style.cssText = `
    position:fixed;
    top:16px;
    right:16px;
    max-width:360px;
    padding:14px 16px;
    font-family:'Segoe UI', Arial, sans-serif;
    font-size:13px;
    z-index:999999;
    display:flex;
    flex-direction:column;
    gap:12px;
    background:#111214ef;
    color:#f5f5f5;
    border-radius:14px;
    border:1px solid rgba(255,255,255,0.08);
    box-shadow:0 15px 35px rgba(0,0,0,0.45);
  `;

  const header = document.createElement('div');
  header.style.cssText = 'display:flex;justify-content:space-between;align-items:flex-start;gap:12px;';

  const headerText = document.createElement('div');
  const title = document.createElement('div');
  title.textContent = 'Safe Click Threat Snapshot';
  title.style.cssText = 'font-size:11px;font-weight:600;color:#9ba0a6;text-transform:uppercase;letter-spacing:0.08em;';
  const urlLine = document.createElement('div');
  urlLine.textContent = formatDisplayUrl(url);
  urlLine.style.cssText = 'font-size:15px;font-weight:600;color:#ffffff;margin-top:2px;';
  headerText.appendChild(title);
  headerText.appendChild(urlLine);

  const closeButton = document.createElement('button');
  closeButton.textContent = '×';
  closeButton.style.cssText = `
    background:rgba(255,255,255,0.08);
    border:none;
    color:#ffffff;
    font-size:18px;
    width:28px;
    height:28px;
    border-radius:6px;
    cursor:pointer;
  `;
  closeButton.onclick = removeWarningBanner;

  header.appendChild(headerText);
  header.appendChild(closeButton);

  const sectionsWrapper = document.createElement('div');
  sectionsWrapper.style.cssText = 'display:flex;flex-direction:column;gap:10px;';

  const modelDescriptor = getScoreDescriptor(score);
  const modelRow = createStatusRow({
    title: 'Model Suspiciousness',
    value: `${score.toFixed(1)}% (${modelDescriptor.label})`,
    color: modelDescriptor.color,
    description: modelDescriptor.description
  });

  const gsbDescriptor = getExternalStatusDescriptor(
    'Google Safe Browsing',
    securityChecks && securityChecks.google_safe_browsing ? securityChecks.google_safe_browsing : null
  );

  const vtDescriptor = getExternalStatusDescriptor(
    'VirusTotal',
    securityChecks && securityChecks.virustotal ? securityChecks.virustotal : null
  );

  const vtExtraText =
    securityChecks &&
    securityChecks.virustotal &&
    typeof securityChecks.virustotal.score === 'number'
      ? `(${securityChecks.virustotal.score.toFixed(1)}% safe)`
      : '';

  sectionsWrapper.appendChild(modelRow);
  sectionsWrapper.appendChild(createStatusRow(gsbDescriptor));
  sectionsWrapper.appendChild(createStatusRow(vtDescriptor, vtExtraText));

  banner.appendChild(header);
  banner.appendChild(sectionsWrapper);
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
            // Static features
            hasLoginForm: checkForLoginForm(),
            hasSensitiveKeywords: checkForSensitiveKeywords(pageContent),
            hasSuspiciousDomain: checkSuspiciousDomain(domain),
            hasSuspiciousForms: checkSuspiciousForms(),
            hasExternalLinks: checkExternalLinks(),
            // Dynamic features
            redirectsCount: dynamicFeatures.redirectsCount,
            popupAttempts: dynamicFeatures.popupAttempts,
            externalFormSubmissions: dynamicFeatures.externalFormSubmissions,
            dynamicallyCreatedForms: dynamicFeatures.dynamicallyCreatedForms,
            hiddenForms: dynamicFeatures.hiddenForms,
            evalUsage: dynamicFeatures.evalUsage,
            externalRequests: dynamicFeatures.externalRequests,
            formDataToExternalDomains: dynamicFeatures.formDataToExternalDomains,
            suspiciousJavaScript: dynamicFeatures.suspiciousJavaScript,
            iframeRedirections: dynamicFeatures.iframeRedirections
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
        if (
            typeof request.score !== 'number' ||
            isNaN(request.score) ||
            request.score < 0 ||
            request.score > 100
        ) {
            console.warn('Phishing banner: invalid data', request);
            removeWarningBanner();
            return;
        }

        chrome.storage.local.get(['settings'], (result) => {
            const settings = result.settings || {};
            if (settings.showWarnings === false) {
                return;
            }
            renderSecurityBanner({
                url: request.url,
                score: request.score,
                securityChecks: request.securityChecks || null
            });
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
    // Initialize dynamic monitoring
    initializeDynamicMonitoring();
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