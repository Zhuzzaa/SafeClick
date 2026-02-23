// Load saved options when the options page is opened
document.addEventListener('DOMContentLoaded', () => {
  loadOptions();

  // Add event listeners for saving and resetting options
  document.getElementById('save-options').addEventListener('click', saveOptions);
  document.getElementById('reset-options').addEventListener('click', resetOptions);

  // Update displayed values for range inputs
  const warningThresholdInput = document.getElementById('warning-threshold');
  const blockingThresholdInput = document.getElementById('blocking-threshold');

  warningThresholdInput.addEventListener('input', () => {
    document.getElementById('warning-threshold-value').textContent = warningThresholdInput.value;
  });

  blockingThresholdInput.addEventListener('input', () => {
    document.getElementById('blocking-threshold-value').textContent = blockingThresholdInput.value;
  });
});

// Load options from Chrome storage
function loadOptions() {
  chrome.storage.local.get(['settings'], (result) => {
    if (chrome.runtime.lastError) {
      console.error('Error loading options:', chrome.runtime.lastError);
      return;
    }

    const settings = result.settings || getDefaultSettings();

    // Set values in the UI
    document.getElementById('enable-protection').checked = settings.enableProtection;
    document.getElementById('show-warnings').checked = settings.showWarnings;
    document.getElementById('block-high-risk').checked = settings.blockHighRisk;
    document.getElementById('show-notifications').checked = settings.showNotifications;
    document.getElementById('play-sound').checked = settings.playSound;

    const warningThreshold = document.getElementById('warning-threshold');
    warningThreshold.value = settings.warningThreshold;
    document.getElementById('warning-threshold-value').textContent = warningThreshold.value;

    const blockingThreshold = document.getElementById('blocking-threshold');
    blockingThreshold.value = settings.blockingThreshold;
    document.getElementById('blocking-threshold-value').textContent = blockingThreshold.value;
  });
}

// Save options to Chrome storage
function saveOptions() {
  const settings = {
    enableProtection: document.getElementById('enable-protection').checked,
    showWarnings: document.getElementById('show-warnings').checked,
    blockHighRisk: document.getElementById('block-high-risk').checked,
    showNotifications: document.getElementById('show-notifications').checked,
    playSound: document.getElementById('play-sound').checked,
    warningThreshold: parseInt(document.getElementById('warning-threshold').value, 10),
    blockingThreshold: parseInt(document.getElementById('blocking-threshold').value, 10)
  };

  chrome.storage.local.set({ settings: settings }, () => {
    if (chrome.runtime.lastError) {
      console.error('Error saving options:', chrome.runtime.lastError);
      return;
    }

    // Show saved message
    const saveMessage = document.getElementById('save-message');
    saveMessage.style.display = 'block';

    // Hide message after 2 seconds
    setTimeout(() => {
      saveMessage.style.display = 'none';
    }, 2000);

    // Notify background script about settings change
    chrome.runtime.sendMessage({ action: 'settingsUpdated', settings: settings });
  });
}

// Reset options to default values
function resetOptions() {
  const defaultSettings = getDefaultSettings();

  chrome.storage.local.set({ settings: defaultSettings }, () => {
    if (chrome.runtime.lastError) {
      console.error('Error resetting options:', chrome.runtime.lastError);
      return;
    }

    // Reload options in the UI
    loadOptions();

    // Show reset message
    const saveMessage = document.getElementById('save-message');
    saveMessage.textContent = 'Options reset to default!';
    saveMessage.style.display = 'block';

    // Hide message after 2 seconds
    setTimeout(() => {
      saveMessage.style.display = 'none';
      saveMessage.textContent = 'Options saved!';
    }, 2000);

    // Notify background script about settings reset
    chrome.runtime.sendMessage({ action: 'settingsUpdated', settings: defaultSettings });
  });
}

// Get default settings
function getDefaultSettings() {
  return {
    enableProtection: true,
    showWarnings: true,
    blockHighRisk: true,
    showNotifications: true,
    playSound: true,
    warningThreshold: 30,
    blockingThreshold: 50
  };
}