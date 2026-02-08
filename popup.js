const SETTING_KEY = 'preferWpNostrLock';
const DEFAULT_VALUE = true;

document.addEventListener('DOMContentLoaded', async () => {
  const checkbox = document.getElementById('prefer-lock');
  const status = document.getElementById('status');

  try {
    const result = await chrome.storage.local.get(SETTING_KEY);
    const value = typeof result[SETTING_KEY] === 'boolean'
      ? result[SETTING_KEY]
      : DEFAULT_VALUE;
    checkbox.checked = value;
  } catch (e) {
    status.textContent = 'Einstellungen konnten nicht geladen werden.';
    return;
  }

  checkbox.addEventListener('change', async () => {
    try {
      await chrome.storage.local.set({ [SETTING_KEY]: checkbox.checked });
      status.textContent = checkbox.checked
        ? 'Lock aktiviert.'
        : 'Lock deaktiviert.';
    } catch (e) {
      status.textContent = 'Speichern fehlgeschlagen.';
    }
  });
});
