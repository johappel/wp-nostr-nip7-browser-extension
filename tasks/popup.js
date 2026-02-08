document.addEventListener('DOMContentLoaded', init);

async function init() {
  const loading = document.getElementById('loading');
  const setupView = document.getElementById('setup-view');
  const activeView = document.getElementById('active-view');
  
  try {
    // Status vom Background Script abfragen
    const status = await chrome.runtime.sendMessage({ type: 'NOSTR_GET_STATUS' });
    
    loading.classList.add('hidden');

    if (!status.hasKey) {
      // Setup erforderlich
      setupView.classList.remove('hidden');
      document.getElementById('btn-setup').onclick = triggerSetup;
    } else if (status.locked) {
      // Gesperrt -> Zeige "Entsperren" (wir nutzen active view mit angepasstem Text)
      activeView.classList.remove('hidden');
      updateActiveView(true, null);
    } else {
      // Bereit
      activeView.classList.remove('hidden');
      updateActiveView(false, status.npub);
    }
  } catch (e) {
    console.error('Failed to init popup:', e);
    loading.innerHTML = '<p class="error">Fehler beim Laden</p>';
  }
}

function updateActiveView(isLocked, npub) {
  const statusEl = document.querySelector('.status-indicator');
  const keyEl = document.getElementById('npub-display');
  const actionBtn = document.getElementById('btn-lock');

  if (isLocked) {
    statusEl.textContent = 'Gesperrt';
    statusEl.className = 'status-indicator locked';
    keyEl.textContent = '••••••••••••••••';
    keyEl.title = 'Zum Entsperren klicken';
    keyEl.onclick = triggerUnlock;
    
    actionBtn.textContent = 'Entsperren';
    actionBtn.className = 'btn-primary';
    actionBtn.onclick = triggerUnlock;
  } else {
    statusEl.textContent = 'Aktiv';
    statusEl.className = 'status-indicator online';
    
    // Npub formatieren (kürzen)
    const shortNpub = npub.slice(0, 10) + '...' + npub.slice(-10);
    keyEl.textContent = shortNpub;
    keyEl.title = 'Klicken um Npub zu kopieren';
    
    keyEl.onclick = () => {
      navigator.clipboard.writeText(npub);
      const original = keyEl.textContent;
      keyEl.textContent = 'Kopiert!';
      setTimeout(() => keyEl.textContent = original, 1000);
    };

    actionBtn.textContent = 'Sperren';
    actionBtn.className = 'btn-secondary';
    actionBtn.onclick = async () => {
      await chrome.runtime.sendMessage({ type: 'NOSTR_LOCK' });
      window.close(); // Popup schließen
    };
  }
}

async function triggerSetup() {
  // Ruft getPublicKey auf, was den Setup-Dialog im Background triggert
  chrome.runtime.sendMessage({ type: 'NOSTR_GET_PUBLIC_KEY' });
  window.close();
}

async function triggerUnlock() {
  // Ruft getPublicKey auf, was den Unlock-Dialog im Background triggert
  chrome.runtime.sendMessage({ type: 'NOSTR_GET_PUBLIC_KEY' });
  window.close();
}