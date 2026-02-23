// Configuration
const CONFIG = {
  ML_SERVER_URL: 'http://localhost:5000',
  CACHE_DURATION: 24 * 60 * 60 * 1000, // 24 hours
  MAX_RETRIES: 3,
  RETRY_DELAY: 1000, // 1 second
  SCORE_THRESHOLDS: {
    HIGH: 50,    // Changed to match server's prediction_threshold
    MEDIUM: 30   // Changed to be lower than HIGH
  }
};

// Cache for URL analysis results
let urlCache = new Map();

// Cache for URL predictions
const predictionCache = new Map();
const CACHE_TIMEOUT = 5000; // 5 seconds

// Initialize blocking rules on installation
chrome.runtime.onInstalled.addListener(() => {
  console.log("Phishing prevention extension installed");
  // Clear old cache on installation
  urlCache.clear();
});

// Debounced navigation handler
let navigationTimeout;
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  clearTimeout(navigationTimeout);
  navigationTimeout = setTimeout(() => {
    // Check settings before analyzing
    chrome.storage.local.get(['settings'], (result) => {
      const settings = result.settings || { enableProtection: true };
      if (!settings.enableProtection) {
        console.log('Phishing protection is disabled. Skipping analysis.');
        return;
      }
      analyzeUrl(details.url, details.tabId, settings, details.frameId, details.tabId);
    });
  }, 500); // 500ms debounce
});

// Main URL analysis function
async function analyzeUrl(url, tabId, settings = {}, frameId = 0, navigationTabId = null) {
  console.log("Analyzing URL:", url);

  // Check cache first
  const cachedResult = getCachedResult(url);
  if (cachedResult !== null && cachedResult !== undefined) {
    handleAnalysisResult(cachedResult, tabId, url, settings, frameId, navigationTabId);
    return cachedResult;
  }

  try {
    const phishingScore = await analyzeUrlWithModel(url);
    if (phishingScore === null || phishingScore === undefined) {
      notifyUser(tabId, "error", url, null, "Unable to analyze this URL. Please try again later.", settings);
      return null;
    }
    handleAnalysisResult(phishingScore, tabId, url, settings, frameId, navigationTabId);
    return phishingScore;
  } catch (error) {
    notifyUser(tabId, "error", url, null, "An error occurred while analyzing this URL.", settings);
    return null;
  }
}

function handleAnalysisResult(result, tabId, url, settings = {}, frameId = 0, navigationTabId = null) {
  settings = settings || {};
  const blockHighRisk = settings.blockHighRisk !== false;

  // Use user-defined thresholds, fallback to defaults if not set
  const blockingThreshold = typeof settings.blockingThreshold === 'number' ? settings.blockingThreshold : CONFIG.SCORE_THRESHOLDS.HIGH;
  const warningThreshold = typeof settings.warningThreshold === 'number' ? settings.warningThreshold : CONFIG.SCORE_THRESHOLDS.MEDIUM;

  // Получаем score и prediction
  let score = null;
  let riskLevel = 'low';
  let prediction = result;

  // Проверка на whitelist
  if (result.security_checks && result.security_checks.whitelist && result.security_checks.whitelist.checked && result.security_checks.whitelist.status === 'safe') {
    score = 10;
    riskLevel = 'low';
  } else if (result.security_checks && result.security_checks.model && result.security_checks.model.checked) {
    score = result.security_checks.model.confidence;
    if (score >= blockingThreshold) riskLevel = 'high';
    else if (score >= warningThreshold) riskLevel = 'medium';
    else riskLevel = 'low';
  } else if (typeof result.result !== 'undefined') {
    score = result.result;
    if (score >= blockingThreshold) riskLevel = 'high';
    else if (score >= warningThreshold) riskLevel = 'medium';
    else riskLevel = 'low';
  }

  // Не отправлять баннер, если score невалидный
  if (typeof score !== 'number' || isNaN(score) || score < 0 || score > 100) {
    return;
  }

  if (riskLevel === 'high') {
    if (blockHighRisk && navigationTabId !== null) {
      chrome.tabs.update(navigationTabId, { url: 'about:blank' });
    }
    notifyUser(tabId, 'high', url, score, null, settings, prediction);
  } else if (riskLevel === 'medium') {
    notifyUser(tabId, 'medium', url, score, null, settings, prediction);
  } else {
    notifyUser(tabId, 'low', url, score, null, settings, prediction);
  }
  storeAnalysisResult(url, score, result, true);
}

// Проверка валидности URL (только http/https)
function isValidUrl(url) {
  try {
        const parsed = new URL(url);
        return ['http:', 'https:'].includes(parsed.protocol) && parsed.hostname;
    } catch {
        return false;
    }
}

// Получение DOM-признаков из content script
function getDomFeatures(url) {
    return new Promise((resolve) => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (!tabs || tabs.length === 0) {
                resolve(Array(8).fill(0));
                return;
    }
            const currentTab = tabs[0];
            // Проверяем, что URL совпадает с активной вкладкой
            if (!currentTab.url || currentTab.url !== url) {
                resolve(Array(8).fill(0));
                return;
            }
            try {
                chrome.tabs.sendMessage(currentTab.id, { action: 'getDomFeatures' }, (response) => {
                    if (chrome.runtime.lastError || !response || !Array.isArray(response.features)) {
                        resolve(Array(8).fill(0));
                        return;
                    }
                    resolve(response.features);
                });
  } catch (error) {
                resolve(Array(8).fill(0));
    }
        });
    });
}

// Извлечение 15 базовых признаков из URL
function extractFeaturesFromUrl(url) {
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    const path = urlObj.pathname;
        let features = [
      /^\d{1,3}(\.\d{1,3}){3}$/.test(domain) ? 1 : 0, // UsingIP
      url.length > 75 ? 1 : 0, // LongURL
      url.length < 54 ? 1 : 0, // ShortURL
      /@/.test(url) ? 1 : 0, // Symbol@
      path.includes('//') ? 1 : 0, // Redirecting//
      domain.includes('-') ? 1 : 0, // PrefixSuffix-
      domain.split('.').length > 2 ? 1 : 0, // SubDomains
      urlObj.protocol === 'https:' ? 1 : 0, // HTTPS
            domain.length > 10 ? 1 : 0, // DomainRegLen
      /https/.test(domain) ? 1 : 0, // HTTPSDomainURL
      /\bmail\b/.test(url) ? 1 : 0, // InfoEmail
            /\.(php|asp|jsp|html|htm)$/i.test(path) ? 1 : 0, // RequestURL
            /[^a-zA-Z0-9]/.test(domain) ? 1 : 0, // AbnormalURL
            /[0-9]{4}/.test(domain) ? 1 : 0, // AgeofDomain
            /\.(com|net|org|edu|gov|mil|biz|info|name|museum|coop|aero|asia|jobs|mobi)$/i.test(domain) ? 1 : 0 // DNSRecording
        ];
        // DOM features (8)
        // Они добавляются отдельно в analyzeUrlWithModel
    return features;
  } catch (error) {
        return Array(15).fill(0);
    }
}

// Главная функция анализа URL
async function analyzeUrlWithModel(url, retryCount = 0) {
    try {
        if (!isValidUrl(url)) {
            throw new Error('Invalid URL format. Only http(s) URLs are allowed.');
        }
        // features вычисляем только для локального анализа, но не отправляем на сервер
        // let baseFeatures = extractFeaturesFromUrl(url);
        // let domFeatures = await getDomFeatures(url);
        // ...
        // let features = [...];
        // console.log('features.length:', features.length, features);
        // const featureNames = [...];
        // features.forEach(...);
        const response = await fetch(CONFIG.ML_SERVER_URL + '/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Server error response:', errorText);
            throw new Error(`Server error: ${response.status} ${response.statusText}`);
        }
        const data = await response.json();
        if (data.status !== 'success') {
            throw new Error(data.error || 'Server did not return a valid result');
        }
        cacheResult(url, data);
        return data;  // Возвращаем весь объект ответа
    } catch (error) {
        if (retryCount < CONFIG.MAX_RETRIES) {
            await new Promise(resolve => setTimeout(resolve, CONFIG.RETRY_DELAY));
            return analyzeUrlWithModel(url, retryCount + 1);
        }
        throw error;
  }
}

function cacheResult(url, data) {
    let score = null;
    if (typeof data.risk_score !== 'undefined') {
        score = data.risk_score;
    } else if (typeof data.result !== 'undefined') {
        score = data.result;
    } else if (data.risk_scores && typeof data.risk_scores.combined !== 'undefined') {
        score = data.risk_scores.combined;
    } else if (data.risk_scores && typeof data.risk_scores.model !== 'undefined') {
        score = data.risk_scores.model;
    }
    urlCache.set(url, {
        score: score,
        prediction: data,
        timestamp: Date.now()
    });
}

function getCachedResult(url) {
    const cached = urlCache.get(url);
    if (cached && (Date.now() - cached.timestamp) < CONFIG.CACHE_DURATION) {
        return {
            result: cached.score,
            prediction: cached.prediction
        };
    }
    return null;
}

function notifyUser(tabId, riskLevel, url, score, customMessage = null, settings = {}, prediction = null) {
  settings = settings || {};
  if (settings.enableProtection === false) return;
  if (settings.showWarnings === false && riskLevel !== 'error') return;
  if (!url || (!url.startsWith('http://') && !url.startsWith('https://'))) {
    return;
  }
  // Для баннера отправляем только результат модели или whitelist
  let modelScore = null;
  if (prediction && prediction.security_checks && prediction.security_checks.whitelist && prediction.security_checks.whitelist.checked && prediction.security_checks.whitelist.status === 'safe') {
    modelScore = 10;
  } else if (prediction && prediction.security_checks && prediction.security_checks.model && prediction.security_checks.model.checked) {
    modelScore = prediction.security_checks.model.confidence;
  } else if (typeof score !== 'undefined') {
    modelScore = score;
  }
  // Не отправлять баннер, если score невалидный или riskLevel невалидный
  if (typeof modelScore !== 'number' || isNaN(modelScore) || modelScore < 0 || modelScore > 100 || !['high', 'medium', 'low', 'error'].includes(riskLevel)) {
    console.warn('notifyUser: invalid score or riskLevel', {modelScore, riskLevel, url, prediction});
    return;
  }
  const message = {
    type: 'phishing-alert',
    riskLevel: riskLevel,
    url: url,
    score: modelScore
  };
  console.log('notifyUser: sending message to content.js', message);
  if (tabId) {
    chrome.tabs.sendMessage(tabId, message).catch(error => {
      console.error('Error sending notification to tab:', error);
    });
  }

  let notificationMessage;
  if (customMessage) {
    notificationMessage = customMessage;
  } else if (riskLevel === 'error') {
    notificationMessage = 'Unable to analyze this URL. Please try again later.';
  } else {
    notificationMessage = `Risk level: ${riskLevel.toUpperCase()}. The site ${url} might be a phishing attempt (Score: ${score}/100).`;
  }

  // Показываем уведомление только если разрешено
  if (settings.showNotifications !== false) {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/warning.png',
      title: 'Phishing Alert',
      message: notificationMessage
    });
  }
  // Воспроизводим звук только если разрешено
  if (settings.playSound === true) {
    try {
      const audio = new Audio('icons/alert.mp3');
      audio.play();
    } catch (e) {
      console.warn('Could not play sound:', e);
    }
  }
}

function storeAnalysisResult(url, score, prediction, isModelUsed) {
  if (typeof score !== 'number' || isNaN(score) || score < 0 || score > 100) {
    console.error("Invalid score, not saving to history:", score);
    return;
  }

  chrome.storage.local.get(['analysisHistory'], (result) => {
    const history = result.analysisHistory || [];
    history.push({
      url: url,
      score: score,
            prediction: prediction,
      source: isModelUsed ? "trained_model" : "unknown",
      timestamp: Date.now()
    });

    if (history.length > 100) {
      history.shift(); // Удаляем старые записи, если их больше 100
    }

    chrome.storage.local.set({ analysisHistory: history }, () => {
            console.log("Saved analysis result:", { url, score, prediction });
    });
  });
}

// Debounce function to prevent too frequent requests
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Get cached prediction
function getCachedPrediction(url) {
    const cached = predictionCache.get(url);
    if (cached && (Date.now() - cached.timestamp) < CACHE_TIMEOUT) {
        return cached.result;
    }
    return null;
}

// Set cached prediction
function setCachedPrediction(url, result) {
    predictionCache.set(url, {
        timestamp: Date.now(),
        result: result
    });
}

// Clean old cache entries
function cleanCache() {
    const now = Date.now();
    for (const [url, data] of predictionCache.entries()) {
        if (now - data.timestamp > CACHE_TIMEOUT) {
            predictionCache.delete(url);
        }
    }
}

// Получение подробного DOM-анализа из content script с повторной попыткой (до 3 раз)
async function getDomAnalysis(url, attempt = 1) {
    return new Promise((resolve) => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (!tabs || tabs.length === 0) {
                console.warn('getDomAnalysis: no active tabs');
                resolve(null);
                return;
            }
            const currentTab = tabs[0];
            if (!currentTab.url || currentTab.url !== url) {
                console.warn('getDomAnalysis: tab URL mismatch', {currentTabUrl: currentTab.url, expected: url});
                resolve(null);
                return;
            }
            try {
                console.log(`[background.js] getDomAnalysis attempt ${attempt} for ${url}`);
                chrome.tabs.sendMessage(currentTab.id, { action: 'getDomAnalysis' }, (response) => {
                    if (chrome.runtime.lastError) {
                        console.warn('getDomAnalysis: chrome.runtime.lastError', chrome.runtime.lastError);
                        if (attempt < 3) {
                            setTimeout(() => {
                                getDomAnalysis(url, attempt + 1).then(resolve);
                            }, 1000); // Увеличиваем задержку до 1 секунды
                        } else {
                            resolve({ domAnalysis: null, error: chrome.runtime.lastError.message });
                        }
                        return;
                    }
                    if (!response || !response.domAnalysis) {
                        console.warn('getDomAnalysis: invalid response', response);
                        if (attempt < 3) {
                            setTimeout(() => {
                                getDomAnalysis(url, attempt + 1).then(resolve);
                            }, 1000);
                        } else {
                            resolve({ domAnalysis: null, error: 'Invalid response from content script' });
                        }
                        return;
                    }
                    console.log('[background.js] getDomAnalysis result:', response.domAnalysis);
                    resolve(response);
                });
            } catch (error) {
                console.error('getDomAnalysis: exception', error);
                if (attempt < 3) {
                    setTimeout(() => {
                        getDomAnalysis(url, attempt + 1).then(resolve);
                    }, 1000);
                } else {
                    resolve({ domAnalysis: null, error: error.message });
                }
            }
        });
    });
}

// Check URL with ML server
async function checkUrl(url) {
    try {
        // Clean old cache entries
        cleanCache();

        // Check cache first
        const cached = getCachedPrediction(url);
        if (cached) {
            console.log('Using cached prediction for:', url);
            return cached;
      }

        // Validate URL
        if (!isValidUrl(url)) {
            console.error('Invalid URL format:', url);
            return {
                error: 'Invalid URL format. URL must start with http:// or https:// and contain a valid domain.',
                status: 'error'
            };
        }

        const response = await fetch('http://localhost:5000/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const result = await response.json();
        
        // Cache successful predictions
        if (result.status === 'success') {
            setCachedPrediction(url, result);
        }

        let domAnalysis = null;
        if (result && typeof result === 'object' && result.domAnalysis) {
            domAnalysis = result.domAnalysis;
        }

        return {
            success: !!result,
            score: result && result.security_checks && result.security_checks.model ? result.security_checks.model.confidence : null,
            prediction: result,
            domAnalysis: domAnalysis
        };
    } catch (error) {
        console.error('Error checking URL:', error);
        return {
            error: 'Failed to check URL. Please try again later.',
            status: 'error'
        };
    }
}

// Debounced version of checkUrl
const debouncedCheckUrl = debounce(checkUrl, 500);

// ГЛАВНЫЙ обработчик сообщений
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'checkUrl') {
        checkUrl(request.url).then(response => {
            sendResponse(response);
        });
        return true;
    }
    if (request.action === 'getDomAnalysisForCurrentTab') {
        chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
            if (!tabs || tabs.length === 0) {
                sendResponse({ domAnalysis: null, error: 'No active tab' });
                return;
            }
            const currentTab = tabs[0];
            const result = await getDomAnalysis(currentTab.url);
            sendResponse(result);
        });
        return true;
    }
});

// Handle installation and updates
chrome.runtime.onInstalled.addListener((details) => {
    if (details.reason === 'install') {
        // Open options page on first install
        chrome.runtime.openOptionsPage();
    }
});

// Handle browser action click
chrome.action.onClicked.addListener((tab) => {
    chrome.tabs.sendMessage(tab.id, { action: 'checkCurrentUrl' });
});

// Periodic cache cleanup
setInterval(cleanCache, CACHE_TIMEOUT);