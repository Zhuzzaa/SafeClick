document.addEventListener('DOMContentLoaded', function () {
  console.log("Popup loaded");
  document.getElementById('check-button').addEventListener('click', checkUrl);

  // Tab navigation
  const tabs = document.querySelectorAll('.tab');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

      tab.classList.add('active');
      const tabName = tab.getAttribute('data-tab');
      document.getElementById(`${tabName}-tab`).classList.add('active');

      chrome.storage.local.set({ activeTab: tabName });

      if (tabName === 'history') {
        loadHistory();
      } else if (tabName === 'current') {
        getCurrentTabInfo();
      } else if (tabName === 'activation') {
        loadApiKeys();
      }
    });
  });

  chrome.storage.local.get(['activeTab'], (result) => {
    const activeTab = result.activeTab || 'current';
    document.querySelector(`.tab[data-tab="${activeTab}"]`).click();
  });

  document.getElementById('check-button').addEventListener('click', checkUrl);
  document.getElementById('save-settings').addEventListener('click', saveSettings);
  document.getElementById('clear-history').addEventListener('click', clearHistory);
  document.getElementById('save-api-keys').addEventListener('click', saveApiKeys);
  document.getElementById('reset-api-keys').addEventListener('click', resetApiKeys);
  
  // Toggle visibility for API keys
  document.querySelectorAll('.toggle-visibility').forEach(btn => {
    btn.addEventListener('click', function() {
      const targetId = this.getAttribute('data-target');
      const input = document.getElementById(targetId);
      if (input.type === 'password') {
        input.type = 'text';
        this.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>';
      } else {
        input.type = 'password';
        this.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
      }
    });
  });
  
  // Validate API keys
  document.querySelectorAll('.validate-key-btn').forEach(btn => {
    btn.addEventListener('click', function() {
      const service = this.getAttribute('data-service');
      const keyInputId = this.getAttribute('data-key-input');
      const key = document.getElementById(keyInputId).value.trim();
      validateApiKey(service, key, this);
    });
  });

  loadSettings();

  var btn = document.getElementById('open-options');
  if (btn) {
    btn.addEventListener('click', function(e) {
      e.preventDefault();
      console.log('Gear button clicked!');
      // Пробуем открыть в новой вкладке
      var win = window.open('options.html', '_blank');
      if (!win) {
        // Если popup заблокирован, открываем в этом же окне
        window.location.href = 'options.html';
      }
    });
  }
});

function clearHistory() {
  chrome.storage.local.set({ analysisHistory: [] }, () => {
    loadHistory();
  });
}

function getCurrentTabInfo() {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    if (tabs.length === 0) {
      console.error("No active tabs found.");
      return;
    }

    const currentTab = tabs[0];
    const url = currentTab.url;

    if (!url || url.startsWith('chrome://') || url === 'about:blank') {
      console.log("Skipping analysis for system or blank tab.");
      const statusElement = document.getElementById('current-status');
      statusElement.innerHTML = `<p>This is a system or blank tab. No analysis performed.</p>`;
      return;
    }

    const statusElement = document.getElementById('current-status');
    const formattedUrl = formatUrlForDisplay(url);
    statusElement.innerHTML = `<p class="url-display">Analyzing: <strong>${formattedUrl}</strong></p>`;

    chrome.runtime.sendMessage(
      { action: 'checkUrl', url: url },
      function (response) {
        if (chrome.runtime.lastError) {
          console.error('Error sending message to background:', chrome.runtime.lastError);
          return;
        }

        if (response && response.success) {
          console.log("Response from background script:", response);
          if (typeof response.score === 'undefined' || response.score === null) {
            console.error("Invalid score in response:", response);
            showResult('Error: Invalid response format from server', 'warning');
            return;
          }
          // После получения анализа URL, запрашиваем DOM-анализ отдельно
          chrome.runtime.sendMessage({ action: 'getDomAnalysisForCurrentTab' }, function(domResponse) {
            let domAnalysis = domResponse && domResponse.domAnalysis ? domResponse.domAnalysis : null;
            let domError = domResponse && domResponse.error ? domResponse.error : null;
            displayAnalysisResult(response.score, url, 'current-status', 'current-details', response.prediction, domAnalysis, domError);
          });
        } else {
          console.error("Error in background response:", response.error);
          showResult(response.error || 'Error analyzing URL. Please try again.', 'warning');
        }
      }
    );
  });
}

function checkUrl() {
  const urlInput = document.getElementById('url-input');
  const url = urlInput.value.trim();

  if (!url) {
    showResult('Please enter a URL to check', 'warning');
    return;
  }

  // Validate URL format
  try {
    new URL(url);
  } catch (e) {
    showResult('Invalid URL format. Please enter a valid URL.', 'warning');
    return;
  }

  const resultElement = document.getElementById('check-result');
  resultElement.style.display = 'block';
  resultElement.className = 'result';
  document.getElementById('result-text').textContent = 'Analyzing URL...';

  chrome.runtime.sendMessage(
    { action: 'checkUrl', url: url },
    function (response) {
      if (chrome.runtime.lastError) {
        console.error('Error sending message to background:', chrome.runtime.lastError);
        showResult('Error checking URL. Please try again.', 'warning');
        return;
      }

      if (response && response.success) {
        console.log("Response from background script:", response);
        if (typeof response.score === 'undefined' || response.score === null) {
          console.error("Invalid score in response:", response);
          showResult('Error: Invalid response format from server', 'warning');
          return;
        }
        displayAnalysisResult(response.score, url, 'check-result', 'check-details', response.prediction, response.domAnalysis);
        
        // Add to history
        chrome.storage.local.get(['analysisHistory'], function (result) {
          const history = result.analysisHistory || [];
          history.push({
            url: url,
            score: response.score,
            prediction: response.prediction,
            source: "popup",
            timestamp: Date.now()
          });
          if (history.length > 100) {
            history.shift();
          }
          chrome.storage.local.set({ analysisHistory: history });
        });
      } else {
        showResult(response.error || 'Error analyzing URL. Please try again.', 'warning');
      }
    }
  );
}

function displayAnalysisResult(score, url, resultElementId, detailsElementId, prediction = null, domAnalysis = null, domError = null) {
  let resultElement = document.getElementById(resultElementId);
  let resultTextElement = resultElement;
  let detailsElement = document.getElementById(detailsElementId);

  if (resultElementId === 'check-result') {
    resultElement = document.getElementById('check-result');
    resultTextElement = document.getElementById('result-text');
    detailsElement = document.getElementById('check-details');
  }

  if (!resultElement || !resultTextElement || !detailsElement) {
    console.error("Result or details element not found.");
    return;
  }

  resultElement.style.display = 'block';
  resultElement.className = 'result';

  // --- Model Analysis Section ---
  let modelHtml = '';
  let riskScore = 0;
  let verdict = 'Not phishing';
  let verdictColor = '#388e3c';
  let barColor = '#34a853';
  let showModel = false;
  if (prediction && prediction.security_checks) {
    const modelCheck = prediction.security_checks.model;
    const whitelistCheck = prediction.security_checks.whitelist;
    if (whitelistCheck && whitelistCheck.checked && whitelistCheck.status === 'safe') {
      riskScore = 10;
      verdict = 'Not phishing (Whitelisted)';
      verdictColor = '#388e3c';
      barColor = '#34a853';
      showModel = true;
    } else if (modelCheck && modelCheck.checked) {
      riskScore = modelCheck.confidence;
      if (modelCheck.status === 'dangerous') {
        verdict = 'Phishing';
        verdictColor = '#ea4335';
        barColor = '#ea4335';
      } else {
        verdict = 'Not phishing';
        verdictColor = '#388e3c';
        barColor = '#34a853';
      }
      showModel = true;
    }
  } else if (typeof score === 'number') {
    // Fallback rendering when server returns plain { result: <number> }
    riskScore = Math.max(0, Math.min(100, score));
    if (riskScore >= 50) {
      verdict = 'Phishing';
      verdictColor = '#ea4335';
      barColor = '#ea4335';
    } else {
      verdict = 'Not phishing';
      verdictColor = '#388e3c';
      barColor = '#34a853';
    }
    showModel = true;
  }
  if (showModel) {
    modelHtml = `
      <div class="analysis-section">
        <div class="section-title">Our Model Analysis</div>
        <div class="verdict" style="color:${verdictColor};font-weight:600;">${verdict}</div>
        <div class="risk-score-label">Risk Score: <span style="color:${barColor};font-weight:600;">${riskScore.toFixed(2)}/100</span></div>
        <div class="risk-score-bar" style="width:100%;background:#eee;border-radius:4px;height:8px;overflow:hidden;margin-top:4px;margin-bottom:8px;">
          <div style="width:${riskScore}%;background:${barColor};height:100%;transition:width 0.3s;"></div>
        </div>
      </div>
    `;
  }

  // --- Google Safe Browsing Section ---
  let gsbHtml = '';
  if (prediction && prediction.security_checks && prediction.security_checks.google_safe_browsing) {
    const gsbCheck = prediction.security_checks.google_safe_browsing;
    let gsbStatus = 'Unknown';
    let gsbColor = '#888';
    if (gsbCheck.status === 'safe') {
      gsbStatus = 'Safe';
      gsbColor = '#388e3c';
    } else if (gsbCheck.status === 'dangerous' || gsbCheck.status === 'phishing' || gsbCheck.status === 'malware') {
      gsbStatus = 'Phishing/Suspicious';
      gsbColor = '#ea4335';
    }
    gsbHtml = `
      <div class="analysis-section">
        <div class="section-title">Google Safe Browsing</div>
        <div class="verdict" style="color:${gsbColor};font-weight:600;">${gsbStatus}</div>
      </div>
    `;
  } else {
    // Always show Google Safe Browsing section, even if not checked
    gsbHtml = `
      <div class="analysis-section">
        <div class="section-title">Google Safe Browsing</div>
        <div class="verdict" style="color:#888;font-weight:600;">Not checked</div>
      </div>
    `;
  }

  // --- VirusTotal Section ---
  let vtHtml = '';
  if (prediction && prediction.security_checks && prediction.security_checks.virustotal) {
    const vtCheck = prediction.security_checks.virustotal;
    let vtStatus = 'Unknown';
    let vtColor = '#888';
    if (vtCheck.status === 'safe') {
      vtStatus = 'Safe';
      vtColor = '#388e3c';
    } else if (vtCheck.status === 'dangerous' || vtCheck.status === 'phishing' || vtCheck.status === 'malware') {
      vtStatus = 'Phishing/Suspicious';
      vtColor = '#ea4335';
    }
    vtHtml = `
      <div class="analysis-section">
        <div class="section-title">VirusTotal</div>
        <div class="verdict" style="color:${vtColor};font-weight:600;">${vtStatus}</div>
      </div>
    `;
  } else {
    // Если нет данных, всё равно показываем секцию
    vtHtml = `
      <div class="analysis-section">
        <div class="section-title">VirusTotal</div>
        <div class="verdict" style="color:#888;font-weight:600;">Not checked</div>
      </div>
    `;
  }

  // --- DOM Analysis Section ---
  let domText = '';
  // Показываем DOM анализ только для текущей вкладки
  if (resultElementId === 'current-status') {
    let dom = (prediction && prediction.domAnalysis) ? prediction.domAnalysis : null;
    if (!dom && domAnalysis) dom = domAnalysis;
    console.log('[popup.js] DOM Analysis received:', dom);
    const staticFeatures = [
      { key: 'hasLoginForm', label: 'Login form' },
      { key: 'hasSensitiveKeywords', label: 'Sensitive keywords' },
      { key: 'hasSuspiciousDomain', label: 'Suspicious domain' },
      { key: 'hasSuspiciousForms', label: 'Suspicious forms' },
      { key: 'hasExternalLinks', label: 'External links in forms' }
    ];
    
    const dynamicFeatures = [
      { key: 'redirectsCount', label: 'Automatic redirects', threshold: 1, isCount: true },
      { key: 'popupAttempts', label: 'Popup attempts', threshold: 1, isCount: true },
      { key: 'externalFormSubmissions', label: 'External form submissions', threshold: 1, isCount: true },
      { key: 'dynamicallyCreatedForms', label: 'Dynamically created forms', threshold: 1, isCount: true },
      { key: 'hiddenForms', label: 'Hidden forms', threshold: 1, isCount: true },
      { key: 'evalUsage', label: 'eval() usage', threshold: false, isCount: false },
      { key: 'externalRequests', label: 'External requests', threshold: 10, isCount: true },
      { key: 'formDataToExternalDomains', label: 'Form data to external domains', threshold: false, isCount: false },
      { key: 'suspiciousJavaScript', label: 'Suspicious JavaScript patterns', threshold: false, isCount: false },
      { key: 'iframeRedirections', label: 'Iframe redirections', threshold: 1, isCount: true }
    ];
    
    const features = [...staticFeatures, ...dynamicFeatures];
    domText = '<div class="analysis-section"><div class="section-title">DOM Analysis</div><ul style="margin:6px 0 0 12px;padding:0;">';
    
    if (domError) {
      domText += `<li style="color:#ea4335;">Error: ${domError}</li>`;
    } else if (!dom) {
      domText += '<li style="color:#ea4335;">Failed to retrieve DOM analysis. The page might be protected or not fully loaded.</li>';
    } else {
      let hasIssues = false;
      
      // Static features
      staticFeatures.forEach(f => {
        let found = typeof dom[f.key] !== 'undefined' ? dom[f.key] : false;
        if (found) hasIssues = true;
        domText += `<li>${f.label}: <span style="font-weight:600;color:${found ? '#ea4335' : '#388e3c'};">${found ? 'Detected' : 'Not detected'}</span></li>`;
      });
      
      // Dynamic features
      if (dynamicFeatures.length > 0) {
        domText += '<li style="margin-top:8px;font-weight:600;color:#9ba0a6;">Dynamic Behavior:</li>';
        dynamicFeatures.forEach(f => {
          const value = dom[f.key];
          let isSuspicious = false;
          let displayValue = '';
          
          if (f.isCount) {
            // For count-based features
            const count = typeof value === 'number' ? value : 0;
            isSuspicious = count >= (f.threshold || 1);
            displayValue = count > 0 ? `${count} detected` : 'None';
          } else {
            // For boolean features
            isSuspicious = value === true;
            displayValue = value ? 'Detected' : 'Not detected';
          }
          
          if (isSuspicious) hasIssues = true;
          domText += `<li style="margin-left:8px;">${f.label}: <span style="font-weight:600;color:${isSuspicious ? '#ea4335' : '#388e3c'};">${displayValue}</span></li>`;
        });
      }
      if (!hasIssues) {
        domText += '<li style="color:#388e3c;">No suspicious elements detected in the page structure.</li>';
      }
    }
    domText += '</ul></div>';
  }

  detailsElement.innerHTML = modelHtml + gsbHtml + vtHtml + domText;
}

function showResult(message, type) {
  const resultElement = document.getElementById('check-result');
  resultElement.className = `result ${type}`;
  resultElement.style.display = 'block';
  document.getElementById('result-text').textContent = message;
  document.getElementById('check-details').innerHTML = '';
}

function loadHistory() {
  const historyList = document.getElementById('history-list');
  chrome.storage.local.get(['analysisHistory'], function (result) {
    let history = result.analysisHistory || [];
    const seen = new Map();
    history.forEach(item => {
      if (!seen.has(item.url) || seen.get(item.url).timestamp < item.timestamp) {
        seen.set(item.url, item);
      }
    });
    history = Array.from(seen.values());
    history.sort((a, b) => b.timestamp - a.timestamp);
    if (history.length === 0) {
      historyList.innerHTML = '<p>No history available yet.</p>';
      return;
    }
    let historyHtml = '';
    history.forEach(item => {
      const date = new Date(item.timestamp).toLocaleString();
      const url = item.url || 'Unknown URL';
      let score = (typeof item.score === 'number' && !isNaN(item.score) && item.score >= 0 && item.score <= 100) ? item.score : null;
      let statusClass = '';
      let statusText = '';
      // Проверка на whitelist
      if (item.prediction && item.prediction.security_checks && item.prediction.security_checks.whitelist && item.prediction.security_checks.whitelist.checked && item.prediction.security_checks.whitelist.status === 'safe') {
        score = 10;
        statusClass = 'status-safe';
        statusText = 'Safe (Whitelist)';
      } else if (score === null) {
        statusClass = 'status-warning';
        statusText = 'Unknown';
      } else if (score < 30) {
        statusClass = 'status-safe';
        statusText = 'Safe';
      } else if (score < 70) {
        statusClass = 'status-warning';
        statusText = 'Suspicious';
      } else {
        statusClass = 'status-danger';
        statusText = 'Dangerous';
      }
      historyHtml += `
        <div class="history-item">
          <div class="history-url" title="${url}" data-url="${url}"><strong>${url}</strong></div>
          <div>Score: <span class="${statusClass}">${score !== null ? score + '/100' : 'N/A'} (${statusText})</span></div>
          <div>Date: ${date}</div>
        </div>
      `;
    });
    historyList.innerHTML = historyHtml;
    
    // Add click handlers for copying URLs
    historyList.querySelectorAll('.history-url').forEach(element => {
      element.addEventListener('click', async function() {
        const url = this.getAttribute('data-url') || this.textContent.trim();
        try {
          await navigator.clipboard.writeText(url);
          // Visual feedback
          const originalBg = this.style.backgroundColor;
          this.style.backgroundColor = 'rgba(108, 141, 255, 0.3)';
          setTimeout(() => {
            this.style.backgroundColor = originalBg;
          }, 300);
        } catch (err) {
          console.error('Failed to copy URL:', err);
          // Fallback: select text
          const range = document.createRange();
          range.selectNodeContents(this);
          const selection = window.getSelection();
          selection.removeAllRanges();
          selection.addRange(range);
        }
      });
    });
    
    console.log('Loaded history:', history);
  });
}

function truncateUrl(url, maxLength) {
  if (url.length <= maxLength) return url;
  return url.substring(0, maxLength - 3) + '...';
}

function formatUrlForDisplay(url) {
  try {
    const parsed = new URL(url);
    const domain = parsed.hostname;
    const path = parsed.pathname;
    const search = parsed.search;
    
    // Если URL короткий, возвращаем как есть
    if (url.length <= 60) return url;
    
    // Показываем домен + начало пути (макс 40 символов пути)
    let displayPath = path;
    if (displayPath.length > 40) {
      displayPath = path.substring(0, 37) + '...';
    }
    
    // Если есть query параметры, показываем только начало
    let displaySearch = search;
    if (displaySearch.length > 30) {
      displaySearch = search.substring(0, 27) + '...';
    }
    
    return domain + displayPath + displaySearch;
  } catch (e) {
    // Если не удалось распарсить, просто обрезаем
    if (url.length <= 60) return url;
    return url.substring(0, 57) + '...';
  }
}

function loadSettings() {
  chrome.storage.local.get(['settings'], function (result) {
    const settings = result.settings || {
      enableProtection: true,
      showWarnings: true,
      blockHighRisk: true
    };

    document.getElementById('enable-protection').checked = settings.enableProtection;
    document.getElementById('show-warnings').checked = settings.showWarnings;
    document.getElementById('block-high-risk').checked = settings.blockHighRisk;
  });
}

function saveSettings() {
  const settings = {
    enableProtection: document.getElementById('enable-protection').checked,
    showWarnings: document.getElementById('show-warnings').checked,
    blockHighRisk: document.getElementById('block-high-risk').checked
  };

  chrome.storage.local.set({ settings: settings }, function () {
    const settingsTab = document.getElementById('settings-tab');
    const notification = document.createElement('div');
    notification.textContent = 'Settings saved!';
    notification.style.color = 'green';
    notification.style.marginTop = '10px';
    settingsTab.appendChild(notification);

    setTimeout(() => {
      notification.remove();
    }, 3000);

    chrome.runtime.sendMessage({ action: 'settingsUpdated', settings: settings });
  });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'analysisResult') {
    displayAnalysisResult(message.score, message.url, 'result-text', 'check-details', message.prediction, message.domAnalysis);
    sendResponse({ received: true });
  }
});

// Load API keys on activation tab open
function loadApiKeys() {
  chrome.storage.local.get(['apiKeys'], function(result) {
    const apiKeys = result.apiKeys || {};
    if (apiKeys.googleSafeBrowsing) {
      document.getElementById('gsb-api-key').value = apiKeys.googleSafeBrowsing;
      updateApiStatus('gsb', true);
    } else {
      updateApiStatus('gsb', false);
    }
    if (apiKeys.virusTotal) {
      document.getElementById('vt-api-key').value = apiKeys.virusTotal;
      updateApiStatus('vt', true);
    } else {
      updateApiStatus('vt', false);
    }
  });
}

function updateApiStatus(service, isActive) {
  const statusElement = document.getElementById(`${service}-status`);
  if (isActive) {
    statusElement.textContent = '✓ Active';
    statusElement.className = 'api-status active';
  } else {
    statusElement.textContent = 'Using default key (limited)';
    statusElement.className = 'api-status inactive';
  }
}

async function saveApiKeys() {
  const gsbKey = document.getElementById('gsb-api-key').value.trim();
  const vtKey = document.getElementById('vt-api-key').value.trim();
  const messageElement = document.getElementById('api-save-message');

  // Validate keys if provided
  if (gsbKey) {
    const gsbBtn = document.querySelector('.validate-key-btn[data-service="gsb"]');
    gsbBtn.disabled = true;
    gsbBtn.textContent = 'Validating...';
    const gsbValid = await validateApiKey('gsb', gsbKey, gsbBtn);
    if (!gsbValid) {
      messageElement.textContent = 'Warning: Google Safe Browsing key validation failed. Saving anyway...';
      messageElement.style.display = 'block';
      messageElement.style.color = '#fbbc04';
    }
  }

  if (vtKey) {
    const vtBtn = document.querySelector('.validate-key-btn[data-service="vt"]');
    vtBtn.disabled = true;
    vtBtn.textContent = 'Validating...';
    const vtValid = await validateApiKey('vt', vtKey, vtBtn);
    if (!vtValid) {
      messageElement.textContent = 'Warning: VirusTotal key validation failed. Saving anyway...';
      messageElement.style.display = 'block';
      messageElement.style.color = '#fbbc04';
    }
  }

  const apiKeys = {};
  if (gsbKey) {
    apiKeys.googleSafeBrowsing = gsbKey;
    updateApiStatus('gsb', true);
  } else {
    delete apiKeys.googleSafeBrowsing;
    updateApiStatus('gsb', false);
  }

  if (vtKey) {
    apiKeys.virusTotal = vtKey;
    updateApiStatus('vt', true);
  } else {
    delete apiKeys.virusTotal;
    updateApiStatus('vt', false);
  }

  chrome.storage.local.set({ apiKeys: apiKeys }, function() {
    if (messageElement.textContent.indexOf('Warning') === -1) {
      messageElement.textContent = 'API keys saved successfully!';
      messageElement.style.color = '#34a853';
    }
    messageElement.style.display = 'block';
    
    // Notify background script to update API keys
    chrome.runtime.sendMessage({ action: 'updateApiKeys', apiKeys: apiKeys });
    
    setTimeout(() => {
      messageElement.style.display = 'none';
    }, 5000);
  });
}

function resetApiKeys() {
  document.getElementById('gsb-api-key').value = '';
  document.getElementById('vt-api-key').value = '';
  updateApiStatus('gsb', false);
  updateApiStatus('vt', false);
  
  chrome.storage.local.remove('apiKeys', function() {
    const messageElement = document.getElementById('api-save-message');
    messageElement.textContent = 'API keys reset to default';
    messageElement.style.display = 'block';
    messageElement.style.color = '#9da5b4';
    
    chrome.runtime.sendMessage({ action: 'updateApiKeys', apiKeys: {} });
    
    setTimeout(() => {
      messageElement.style.display = 'none';
    }, 3000);
  });
}

async function validateApiKey(service, key, buttonElement) {
  if (!key) {
    showValidationResult(service, false, 'Please enter an API key first');
    return false;
  }

  if (buttonElement) {
    buttonElement.disabled = true;
    buttonElement.classList.add('validating');
    buttonElement.textContent = 'Validating...';
  }

  try {
    // Send validation request to background script
    const response = await new Promise((resolve) => {
      chrome.runtime.sendMessage({
        action: 'validateApiKey',
        service: service,
        key: key
      }, (response) => {
        if (chrome.runtime.lastError) {
          resolve({ success: false, error: chrome.runtime.lastError.message });
        } else {
          resolve(response || { success: false, error: 'No response' });
        }
      });
    });

    if (response.success) {
      showValidationResult(service, true, '✓ Valid API key');
      if (buttonElement) {
        buttonElement.style.background = 'rgba(52, 168, 83, 0.2)';
        buttonElement.style.borderColor = 'rgba(52, 168, 83, 0.3)';
        buttonElement.style.color = '#34a853';
      }
      return true;
    } else {
      showValidationResult(service, false, response.error || 'Invalid API key');
      if (buttonElement) {
        buttonElement.style.background = 'rgba(234, 67, 53, 0.2)';
        buttonElement.style.borderColor = 'rgba(234, 67, 53, 0.3)';
        buttonElement.style.color = '#ea4335';
      }
      return false;
    }
  } catch (error) {
    showValidationResult(service, false, 'Validation failed: ' + error.message);
    if (buttonElement) {
      buttonElement.style.background = 'rgba(234, 67, 53, 0.2)';
      buttonElement.style.borderColor = 'rgba(234, 67, 53, 0.3)';
      buttonElement.style.color = '#ea4335';
    }
    return false;
  } finally {
    if (buttonElement) {
      buttonElement.disabled = false;
      buttonElement.classList.remove('validating');
      buttonElement.textContent = 'Validate Key';
      
      // Reset button style after 3 seconds
      setTimeout(() => {
        buttonElement.style.background = '';
        buttonElement.style.borderColor = '';
        buttonElement.style.color = '';
      }, 3000);
    }
  }
}

function showValidationResult(service, isValid, message) {
  const statusElement = document.getElementById(`${service}-status`);
  statusElement.textContent = message;
  if (isValid) {
    statusElement.className = 'api-status active';
    statusElement.style.color = '#34a853';
  } else {
    statusElement.className = 'api-status inactive';
    statusElement.style.color = '#ea4335';
  }
}
