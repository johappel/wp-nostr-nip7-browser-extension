const SETTING_KEY = 'preferWpNostrLock';
const DEFAULT_VALUE = true;
const VIEWER_CACHE_KEY = 'nostrViewerProfileCacheV1';
const DEFAULT_UNLOCK_CACHE_POLICY = 'session';
const FALLBACK_UNLOCK_CACHE_POLICIES = ['off', '5m', '15m', '30m', '60m', 'session'];
const DM_RELAY_KEY = 'dmRelayUrl';

const UNLOCK_CACHE_POLICY_LABELS = {
  off: 'Immer nachfragen',
  '5m': '5 Minuten',
  '15m': '15 Minuten',
  '30m': '30 Minuten',
  '60m': '60 Minuten',
  session: 'Bis Browser-Neustart'
};

let contactsRequestScope = 'global';
let contactsRequestWpApi = null;

// ========================================
// View-Router
// ========================================

function switchView(viewId) {
  // Alle Views deaktivieren
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  
  // Ziel-View aktivieren
  const view = document.getElementById(`view-${viewId}`);
  const navItem = document.querySelector(`[data-view="${viewId}"]`);
  if (view) view.classList.add('active');
  if (navItem) navItem.classList.add('active');
  
  // View-spezifische Initialisierung
  onViewActivated(viewId);
}

// View-spezifische Aktionen bei Aktivierung
async function onViewActivated(viewId) {
  // Diese Funktion wird nach dem View-Wechsel aufgerufen
  // und aktualisiert den Zustand der jeweiligen View
  
  // Ensure we are subscribed to DMs when viewing relevant pages
  if (['home', 'conversation', 'chat'].includes(viewId)) {
     try {
       const dmRelayResult = await chrome.storage.local.get(['dmRelayUrl']);
       chrome.runtime.sendMessage({ 
         type: 'NOSTR_SUBSCRIBE_DMS',
         payload: { relayUrl: dmRelayResult.dmRelayUrl }
       }).catch(() => {}); // catch harmless errors
     } catch(e) {}
  }

  switch (viewId) {
    case 'home':
      // Kontakte laden, wenn noch nicht geladen
      if (currentContacts.length === 0) {
        await loadContacts(false);
      }
      break;
    case 'keys':
      // Protection Row und Cloud-Backup werden beim Laden aktualisiert
      break;
    case 'settings':
      // Scope-Anzeige aktualisieren
      const scopeSpan = document.getElementById('active-scope');
      if (scopeSpan) {
        // Der Scope wird beim Laden gesetzt
      }
      break;
  }
}

// ========================================
// Dialog-Management
// ========================================

function openDialog(dialogId) {
  const overlay = document.getElementById('dialog-overlay');
  const dialog = document.getElementById(dialogId);
  if (overlay) {
    overlay.classList.add('open');
    overlay.setAttribute('aria-hidden', 'false');
  }
  if (dialog) {
    dialog.classList.add('open');
  }
}

function closeDialog() {
  const overlay = document.getElementById('dialog-overlay');
  if (overlay) {
    overlay.classList.remove('open');
    overlay.setAttribute('aria-hidden', 'true');
  }
  document.querySelectorAll('.dialog.open').forEach(d => d.classList.remove('open'));
}

// ========================================
// Status-Management
// ========================================

let statusTimeout = null;

function showStatus(message, isError = false) {
  const status = document.getElementById('status');
  if (!status) return;
  
  status.textContent = message;
  status.classList.toggle('error', isError);
  status.classList.add('visible');
  
  // Auto-Hide nach 4 Sekunden
  if (statusTimeout) clearTimeout(statusTimeout);
  statusTimeout = setTimeout(() => {
    status.classList.remove('visible');
  }, 4000);
}

// ========================================
// User Hero Update
// ========================================

function updateUserHero(viewer, runtimeStatus) {
  const heroAvatar = document.getElementById('hero-avatar');
  const heroName = document.getElementById('hero-name');
  const heroNip05 = document.getElementById('hero-nip05');
  
  if (!heroAvatar || !heroName || !heroNip05) return;
  
  const avatarUrl = String(viewer?.avatarUrl || '').trim();
  const displayName = String(viewer?.displayName || viewer?.userLogin || 'Gast').trim();
  const nip05 = String(viewer?.profileNip05 || '').trim();
  
  if (avatarUrl) {
    heroAvatar.innerHTML = `<img src="${escapeHtml(avatarUrl)}" alt="Avatar">`;
  } else {
    heroAvatar.innerHTML = '<span style="font-size: 20px;">👤</span>';
  }
  
  heroName.textContent = displayName;
  heroNip05.textContent = nip05 || '(keine NIP-05)';
}

// ========================================
// Connection Status Update
// ========================================

function updateConnectionStatus(connected) {
  const statusDot = document.querySelector('.status-dot');
  const statusText = document.querySelector('.status-text');
  
  if (statusDot) {
    statusDot.classList.toggle('offline', !connected);
  }
  if (statusText) {
    statusText.textContent = connected ? 'Connected' : 'Offline';
  }
}

// ========================================
// Main Initialization
// ========================================

document.addEventListener('DOMContentLoaded', async () => {
  const checkbox = document.getElementById('prefer-lock');
  const status = document.getElementById('status');
  const refreshUserButton = document.getElementById('refresh-user');
  const profileCard = document.getElementById('profile-card');
  const profileHint = document.getElementById('profile-hint');
  const instanceCard = document.getElementById('instance-card');
  const publishProfileButton = document.getElementById('publish-profile');
  const unlockCachePolicySelect = document.getElementById('unlock-cache-policy');
  const unlockCacheState = document.getElementById('unlock-cache-state');
  const unlockCacheHint = document.getElementById('unlock-cache-hint');
  const exportKeyButton = document.getElementById('export-key');
  const backupOutputToggleButton = document.getElementById('backup-output-toggle');
  const backupOutputCopyButton = document.getElementById('backup-output-copy');
  const backupDownloadButton = document.getElementById('backup-download');
  const importKeyButton = document.getElementById('import-key');
  const createKeyButton = document.getElementById('create-key');
  const importNsecInput = document.getElementById('import-nsec');
  const backupOutput = document.getElementById('backup-output');
  const cloudBackupMeta = document.getElementById('cloud-backup-meta');
  const cloudBackupEnableButton = document.getElementById('backup-enable-cloud');
  const cloudBackupRestoreButton = document.getElementById('backup-restore-cloud');
  const cloudBackupDeleteButton = document.getElementById('backup-delete-cloud');
  const protectionRow = document.getElementById('protection-row');
  const userHero = document.getElementById('user-hero');
  const dialogOverlay = document.getElementById('dialog-overlay');
  const dialogClose = document.getElementById('dialog-close');
  const footerNav = document.getElementById('footer-nav');
  const dmRelayInput = document.getElementById('dm-relay-url');
  const saveDmRelayButton = document.getElementById('save-dm-relay');
  const extensionVersionSpan = document.getElementById('extension-version');
  const activeScopeSpan = document.getElementById('active-scope');
  const refreshProfileButton = document.getElementById('refresh-profile');
  
  let activeScope = 'global';
  let activeWpApi = null;
  let activeAuthBroker = null;
  let activeViewer = null;
  let activeRuntimeStatus = null;

  // ========================================
  // Event Listeners: Navigation & Dialogs
  // ========================================

  // Footer Navigation
  if (footerNav) {
    footerNav.addEventListener('click', (e) => {
      const navItem = e.target.closest('.nav-item');
      if (!navItem) return;
      const viewId = navItem.dataset.view;
      if (viewId) switchView(viewId);
    });
  }
  
  // Initialize contact list events
  initContactListEvents();

  // Chat View Events (TASK-20)
  const conversationBack = document.getElementById('conversation-back');
  const sendMessageBtn = document.getElementById('send-message');
  const messageInput = document.getElementById('message-input');

  if (conversationBack) conversationBack.addEventListener('click', closeConversation);
  
  if (sendMessageBtn) sendMessageBtn.addEventListener('click', sendMessage);
  
  if (messageInput) {
    messageInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        sendMessage();
      }
    });
  }

  // User Hero → Profil-Dialog
  if (userHero) {
    userHero.addEventListener('click', () => {
      openDialog('dialog-profile');
    });
    userHero.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        openDialog('dialog-profile');
      }
    });
  }

  // Dialog schließen
  if (dialogClose) {
    dialogClose.addEventListener('click', closeDialog);
  }
  
  if (dialogOverlay) {
    dialogOverlay.addEventListener('click', (e) => {
      if (e.target === dialogOverlay) {
        closeDialog();
      }
    });
  }

  // ESC-Taste schließt Dialog
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeDialog();
    }
  });

  // ========================================
  // Load Initial Data
  // ========================================

  try {
    const result = await chrome.storage.local.get(SETTING_KEY);
    const value = typeof result[SETTING_KEY] === 'boolean'
      ? result[SETTING_KEY]
      : DEFAULT_VALUE;
    if (checkbox) checkbox.checked = value;
  } catch (e) {
    showStatus('Einstellungen konnten nicht geladen werden.', true);
  }

  const initialViewer = await loadViewerContext(null, status);
  await persistViewerCache(initialViewer);
  activeViewer = initialViewer;
  activeScope = initialViewer?.scope || 'global';
  activeWpApi = sanitizeWpApi(initialViewer?.wpApi);
  activeAuthBroker = sanitizeAuthBroker(initialViewer?.authBroker);
  const initialSigner = await refreshSignerIdentity(protectionRow, activeScope, !initialViewer?.isLoggedIn);
  activeRuntimeStatus = initialSigner?.runtimeStatus || null;
  activeScope = initialSigner?.scope || activeScope;
  setContactRequestContext(activeScope, activeWpApi);
  
  // UI aktualisieren
  renderProfileCard(profileCard, profileHint, activeViewer, activeRuntimeStatus);
  renderInstanceCard(instanceCard, activeViewer);
  updateUserHero(activeViewer, activeRuntimeStatus);
  updateConnectionStatus(Boolean(activeRuntimeStatus?.hasKey));
  await refreshUnlockState(unlockCacheState, unlockCacheHint, unlockCachePolicySelect, activeScope);
  await refreshCloudBackupState(cloudBackupMeta, {
    enableButton: cloudBackupEnableButton,
    restoreButton: cloudBackupRestoreButton,
    deleteButton: cloudBackupDeleteButton
  }, activeScope, activeWpApi);

  // ========================================
  // Version & Scope Info
  // ========================================

  if (extensionVersionSpan) {
    try {
      const manifest = chrome.runtime.getManifest();
      extensionVersionSpan.textContent = manifest.version || 'unbekannt';
    } catch {
      extensionVersionSpan.textContent = 'unbekannt';
    }
  }

  if (activeScopeSpan) {
    activeScopeSpan.textContent = activeScope || 'global';
  }

  // ========================================
  // DM-Relay Initialisierung
  // ========================================

  if (dmRelayInput) {
    const currentDmRelay = await loadDmRelay();
    dmRelayInput.value = currentDmRelay;
  }

  // ========================================
  // Event Listeners: DM-Relay
  // ========================================

  if (saveDmRelayButton && dmRelayInput) {
    saveDmRelayButton.addEventListener('click', async () => {
      const url = String(dmRelayInput.value || '').trim();
      saveDmRelayButton.disabled = true;
      try {
        const saved = await saveDmRelay(url);
        dmRelayInput.value = saved;
        showStatus(saved
          ? `Nachrichten-Relay gespeichert: ${saved}`
          : 'Nachrichten-Relay entfernt (verwendet Gegenüber-Relay).');
      } catch (e) {
        showStatus(`Fehler: ${e.message || e}`, true);
      } finally {
        saveDmRelayButton.disabled = false;
      }
    });
  }

  // ========================================
  // Event Listeners: Refresh Profile Dialog
  // ========================================

  if (refreshProfileButton) {
    refreshProfileButton.addEventListener('click', async () => {
      refreshProfileButton.disabled = true;
      try {
        const viewer = await loadViewerContext(null, status);
        await persistViewerCache(viewer);
        activeViewer = viewer;
        activeScope = viewer?.scope || 'global';
        activeWpApi = sanitizeWpApi(viewer?.wpApi);
        activeAuthBroker = sanitizeAuthBroker(viewer?.authBroker);
        
        const signerContext = await refreshSignerIdentity(protectionRow, activeScope, !viewer?.isLoggedIn);
        activeRuntimeStatus = signerContext?.runtimeStatus || null;
        activeScope = signerContext?.scope || activeScope;
        setContactRequestContext(activeScope, activeWpApi);
        
        renderProfileCard(profileCard, profileHint, activeViewer, activeRuntimeStatus);
        updateUserHero(activeViewer, activeRuntimeStatus);
        updateConnectionStatus(Boolean(activeRuntimeStatus?.hasKey));
        
        if (activeScopeSpan) {
          activeScopeSpan.textContent = activeScope || 'global';
        }
        
        showStatus('Profil aktualisiert.');
      } catch (e) {
        showStatus(`Aktualisierung fehlgeschlagen: ${e.message || e}`, true);
      } finally {
        refreshProfileButton.disabled = false;
      }
    });
  }

  // ========================================
  // Event Listeners: Settings
  // ========================================

  if (checkbox) {
    checkbox.addEventListener('change', async () => {
      try {
        await chrome.storage.local.set({ [SETTING_KEY]: checkbox.checked });
        showStatus(checkbox.checked ? 'Lock aktiviert.' : 'Lock deaktiviert.');
      } catch (e) {
        showStatus('Speichern fehlgeschlagen.', true);
      }
    });
  }

  if (unlockCachePolicySelect) {
    unlockCachePolicySelect.addEventListener('change', async () => {
      const selectedPolicy = normalizeUnlockCachePolicy(unlockCachePolicySelect.value);
      unlockCachePolicySelect.disabled = true;
      try {
        const response = await chrome.runtime.sendMessage({
          type: 'NOSTR_SET_UNLOCK_CACHE_POLICY',
          payload: { policy: selectedPolicy, scope: activeScope }
        });
        if (response?.error) throw new Error(response.error);
        const updatedPolicy = normalizeUnlockCachePolicy(response?.result?.policy || selectedPolicy);
        unlockCachePolicySelect.value = updatedPolicy;
        await refreshUnlockState(unlockCacheState, unlockCacheHint, unlockCachePolicySelect, activeScope);
        showStatus(`ReLogin-Dauer gespeichert: ${formatUnlockCachePolicyLabel(updatedPolicy)}.`);
      } catch (e) {
        showStatus(`ReLogin-Dauer konnte nicht gespeichert werden: ${e.message || e}`, true);
        await refreshUnlockState(unlockCacheState, unlockCacheHint, unlockCachePolicySelect, activeScope);
      } finally {
        unlockCachePolicySelect.disabled = false;
      }
    });
  }

  // ========================================
  // Event Listeners: Refresh
  // ========================================

  if (refreshUserButton) {
    refreshUserButton.addEventListener('click', async () => {
      refreshUserButton.disabled = true;
      try {
        const viewer = await loadViewerContext(null, status);
        await persistViewerCache(viewer);
        activeViewer = viewer;
        activeScope = viewer?.scope || 'global';
        activeWpApi = sanitizeWpApi(viewer?.wpApi);
        activeAuthBroker = sanitizeAuthBroker(viewer?.authBroker);
        const signerContext = await refreshSignerIdentity(protectionRow, activeScope, !viewer?.isLoggedIn);
        activeRuntimeStatus = signerContext?.runtimeStatus || null;
        activeScope = signerContext?.scope || activeScope;
        setContactRequestContext(activeScope, activeWpApi);
        renderProfileCard(profileCard, profileHint, activeViewer, activeRuntimeStatus);
        renderInstanceCard(instanceCard, activeViewer);
        updateUserHero(activeViewer, activeRuntimeStatus);
        updateConnectionStatus(Boolean(activeRuntimeStatus?.hasKey));
        await refreshUnlockState(unlockCacheState, unlockCacheHint, unlockCachePolicySelect, activeScope);
        await refreshCloudBackupState(cloudBackupMeta, {
          enableButton: cloudBackupEnableButton,
          restoreButton: cloudBackupRestoreButton,
          deleteButton: cloudBackupDeleteButton
        }, activeScope, activeWpApi);
        if (viewer?.pending) {
          showStatus('Profilkontext wird noch geladen. Bitte in 1-2 Sekunden erneut aktualisieren.');
        } else if (viewer?.isCached) {
          showStatus('Profil aus Extension-Speicher geladen.');
        } else {
          showStatus(viewer?.isLoggedIn
            ? 'Profilinformationen aktualisiert.'
            : 'Kein eingeloggter WordPress-Benutzer auf aktivem Tab.');
        }
      } catch (e) {
        showStatus(`Profilinformationen konnten nicht geladen werden: ${e.message || e}`, true);
      } finally {
        refreshUserButton.disabled = false;
      }
    });
  }

  // ========================================
  // Event Listeners: Profile Publish
  // ========================================

  if (publishProfileButton) {
    publishProfileButton.addEventListener('click', async () => {
      if (!hasProfileContext(activeViewer)) {
        showStatus('Kein Profilkontext verfügbar. Öffne eine WordPress-Seite und lade das Popup neu.', true);
        return;
      }

      const profilePayload = buildProfilePublishPayload(activeViewer);
      if (!profilePayload.relays.length) {
        showStatus('Kein Profil-Relay konfiguriert. Bitte in WordPress "Profil-Relay (kind:0)" setzen.', true);
        return;
      }

      publishProfileButton.disabled = true;
      showStatus('Sende Profil-Event (kind:0) an Relay...');
      try {
        const response = await chrome.runtime.sendMessage({
          type: 'NOSTR_PUBLISH_PROFILE',
          payload: {
            scope: activeScope,
            relays: profilePayload.relays,
            profile: profilePayload.profile,
            expectedPubkey: activeRuntimeStatus?.pubkeyHex || null,
            origin: activeViewer?.origin || null,
            authBroker: activeAuthBroker
          }
        });
        if (response?.error) throw new Error(response.error);
        const result = response?.result || {};
        const relay = String(result.relay || profilePayload.relays[0] || '').trim();
        const pubkey = String(result.pubkey || activeRuntimeStatus?.pubkeyHex || '').trim();
        showStatus(relay
          ? `Profil veröffentlicht auf ${relay} (${formatShortHex(pubkey)}).`
          : `Profil veröffentlicht (${formatShortHex(pubkey)}).`);
      } catch (e) {
        showStatus(`Profil-Publish fehlgeschlagen: ${e.message || e}`, true);
      } finally {
        publishProfileButton.disabled = false;
      }
    });
  }

  // ========================================
  // Event Listeners: Key Export
  // ========================================

  if (exportKeyButton) {
    exportKeyButton.addEventListener('click', async () => {
      exportKeyButton.disabled = true;
      try {
        const response = await chrome.runtime.sendMessage({
          type: 'NOSTR_EXPORT_NSEC',
          payload: { scope: activeScope }
        });
        if (response?.error) throw new Error(response.error);
        const nsec = String(response?.result?.nsec || '').trim();
        if (!nsec) throw new Error('Export lieferte keinen nsec');

        if (backupOutput) {
          backupOutput.value = nsec;
          backupOutput.type = 'password';
        }
        showStatus('Schlüssel exportiert (verborgen). Nutze 👁 zum Anzeigen.');
      } catch (e) {
        showStatus(`Export fehlgeschlagen: ${e.message || e}`, true);
      } finally {
        exportKeyButton.disabled = false;
      }
    });
  }

  if (backupOutputToggleButton && backupOutput) {
    backupOutputToggleButton.addEventListener('click', () => {
      const isHidden = backupOutput.type === 'password';
      backupOutput.type = isHidden ? 'text' : 'password';
      backupOutputToggleButton.textContent = isHidden ? '🙈' : '👁';
      backupOutputToggleButton.title = isHidden ? 'Verbergen' : 'Anzeigen';
    });
  }

  if (backupOutputCopyButton && backupOutput) {
    backupOutputCopyButton.addEventListener('click', async () => {
      const nsec = String(backupOutput.value || '').trim();
      if (!nsec) {
        showStatus('Kein exportierter Schlüssel zum Kopieren vorhanden.', true);
        return;
      }
      try {
        await navigator.clipboard.writeText(nsec);
        showStatus('Exportierter Schlüssel wurde kopiert.');
      } catch {
        showStatus('Kopieren des exportierten Schlüssels fehlgeschlagen.', true);
      }
    });
  }

  if (backupDownloadButton) {
    backupDownloadButton.addEventListener('click', async () => {
      backupDownloadButton.disabled = true;
      try {
        // Fetch nsec directly from background – no prior export needed
        const exportResponse = await chrome.runtime.sendMessage({
          type: 'NOSTR_EXPORT_NSEC',
          payload: { scope: activeScope }
        });
        if (exportResponse?.error) throw new Error(exportResponse.error);
        const nsec = String(exportResponse?.result?.nsec || '').trim();
        if (!nsec) throw new Error('Export lieferte keinen nsec');

        const response = await chrome.runtime.sendMessage({ type: 'getPublicKey', payload: { scope: activeScope } });
        const npub = String(response?.result || '').trim();
        const displayName = String(activeViewer?.displayName || activeViewer?.userLogin || '').trim();
        const namePart = displayName ? `-${displayName.toLowerCase().replace(/[^a-z0-9_-]/g, '-').slice(0, 24)}` : '';
        const datePart = new Date().toISOString().split('T')[0];
        const content = `Nostr Backup\n===========\n\n${npub ? `npub: ${npub}\n` : ''}nsec: ${nsec}\n\n!! GEHEIM HALTEN \u2013 NIEMALS TEILEN !!\n\nWiederherstellen / anderer Browser:\n1. WP Nostr Signer Extension installieren\n2. Extension-Popup oeffnen (Klick auf das Extension-Icon)\n3. Im Bereich "Schluessel" den nsec in das Import-Feld einfuegen\n4. "Importieren" klicken\n`;
        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `nostr-backup${namePart}-${datePart}.txt`;
        a.click();
        URL.revokeObjectURL(url);
        showStatus('Backup-Datei heruntergeladen.');
      } catch (e) {
        showStatus(`Download fehlgeschlagen: ${e.message || e}`, true);
      } finally {
        backupDownloadButton.disabled = false;
      }
    });
  }

  // ========================================
  // Event Listeners: Key Import
  // ========================================

  if (importKeyButton && importNsecInput) {
    importKeyButton.addEventListener('click', async () => {
      const nsec = String(importNsecInput.value || '').trim();
      if (!nsec) {
        showStatus('Bitte zuerst einen nsec eingeben.', true);
        return;
      }

      const confirmed = confirm('Das ersetzt den bestehenden Nostr-Schlüssel für dieses Profil. Fortfahren?');
      if (!confirmed) return;

      importKeyButton.disabled = true;
      try {
        const response = await chrome.runtime.sendMessage({
          type: 'NOSTR_IMPORT_NSEC',
          payload: { scope: activeScope, nsec, wpApi: activeWpApi }
        });
        if (response?.error) throw new Error(response.error);
        const pubkey = String(response?.result?.pubkey || '');
        importNsecInput.value = '';
        if (backupOutput) backupOutput.value = '';
        const signerContext = await refreshSignerIdentity(protectionRow, activeScope, true);
        activeRuntimeStatus = signerContext?.runtimeStatus || null;
        activeScope = signerContext?.scope || activeScope;
        setContactRequestContext(activeScope, activeWpApi);
        renderProfileCard(profileCard, profileHint, activeViewer, activeRuntimeStatus);
        updateUserHero(activeViewer, activeRuntimeStatus);
        await refreshUnlockState(unlockCacheState, unlockCacheHint, unlockCachePolicySelect, activeScope);
        showStatus(pubkey
          ? `Schlüssel wiederhergestellt (${formatShortHex(pubkey)}). Seite neu laden und ggf. erneut verknüpfen.`
          : 'Schlüssel importiert. Seite neu laden.');
      } catch (e) {
        showStatus(`Import fehlgeschlagen: ${e.message || e}`, true);
      } finally {
        importKeyButton.disabled = false;
      }
    });
  }

  // ========================================
  // Event Listeners: Key Create
  // ========================================

  if (createKeyButton) {
    createKeyButton.addEventListener('click', async () => {
      const confirmed = confirm('Neue Schlüssel erstellen? Das ersetzt die aktuelle Nostr-Identität für dieses Profil.');
      if (!confirmed) return;

      createKeyButton.disabled = true;
      try {
        const response = await chrome.runtime.sendMessage({
          type: 'NOSTR_CREATE_NEW_KEY',
          payload: { scope: activeScope, wpApi: activeWpApi }
        });
        if (response?.error) throw new Error(response.error);
        const pubkey = String(response?.result?.pubkey || '').trim();

        if (importNsecInput) importNsecInput.value = '';
        if (backupOutput) backupOutput.value = '';

        const signerContext = await refreshSignerIdentity(protectionRow, activeScope, false);
        activeRuntimeStatus = signerContext?.runtimeStatus || null;
        activeScope = signerContext?.scope || activeScope;
        setContactRequestContext(activeScope, activeWpApi);
        renderProfileCard(profileCard, profileHint, activeViewer, activeRuntimeStatus);
        updateUserHero(activeViewer, activeRuntimeStatus);
        updateConnectionStatus(Boolean(activeRuntimeStatus?.hasKey));
        await refreshUnlockState(unlockCacheState, unlockCacheHint, unlockCachePolicySelect, activeScope);
        await refreshCloudBackupState(cloudBackupMeta, {
          enableButton: cloudBackupEnableButton,
          restoreButton: cloudBackupRestoreButton,
          deleteButton: cloudBackupDeleteButton
        }, activeScope, activeWpApi);

        showStatus(pubkey
          ? `Neue Schlüssel erstellt (${formatShortHex(pubkey)}).`
          : 'Neue Schlüssel erstellt.');
      } catch (e) {
        showStatus(`Neue Schlüssel konnten nicht erstellt werden: ${e.message || e}`, true);
      } finally {
        createKeyButton.disabled = false;
      }
    });
  }

  // ========================================
  // Event Listeners: Cloud Backup
  // ========================================

  if (cloudBackupEnableButton) {
    cloudBackupEnableButton.addEventListener('click', async () => {
      if (!activeWpApi) {
        showStatus('Schlüsselkopie ist nur auf einem eingeloggten WordPress-Tab verfügbar.', true);
        return;
      }
      setCloudButtonsDisabled({
        enableButton: cloudBackupEnableButton,
        restoreButton: cloudBackupRestoreButton,
        deleteButton: cloudBackupDeleteButton
      }, true);
      showStatus('Speichere Schlüsselkopie in WordPress...');
      try {
        const response = await chrome.runtime.sendMessage({
          type: 'NOSTR_BACKUP_ENABLE',
          payload: { scope: activeScope, wpApi: activeWpApi, authBroker: activeAuthBroker }
        });
        if (response?.error) throw new Error(response.error);
        showStatus('Schlüsselkopie in WordPress gespeichert.');
        await refreshCloudBackupState(cloudBackupMeta, {
          enableButton: cloudBackupEnableButton,
          restoreButton: cloudBackupRestoreButton,
          deleteButton: cloudBackupDeleteButton
        }, activeScope, activeWpApi);
      } catch (e) {
        showStatus(`Speichern der Schlüsselkopie fehlgeschlagen: ${e.message || e}`, true);
        await refreshCloudBackupState(cloudBackupMeta, {
          enableButton: cloudBackupEnableButton,
          restoreButton: cloudBackupRestoreButton,
          deleteButton: cloudBackupDeleteButton
        }, activeScope, activeWpApi);
      }
    });
  }

  if (cloudBackupRestoreButton) {
    cloudBackupRestoreButton.addEventListener('click', async () => {
      if (!activeWpApi) {
        showStatus('Wiederherstellen ist nur auf einem eingeloggten WordPress-Tab verfügbar.', true);
        return;
      }
      const confirmed = confirm('Wiederherstellen aus WordPress ersetzt den lokalen Nostr-Schlüssel. Fortfahren?');
      if (!confirmed) return;

      setCloudButtonsDisabled({
        enableButton: cloudBackupEnableButton,
        restoreButton: cloudBackupRestoreButton,
        deleteButton: cloudBackupDeleteButton
      }, true);
      showStatus('Stelle aus WordPress-Schlüsselkopie wieder her...');
      try {
        const response = await chrome.runtime.sendMessage({
          type: 'NOSTR_BACKUP_RESTORE',
          payload: { scope: activeScope, wpApi: activeWpApi, authBroker: activeAuthBroker }
        });
        if (response?.error) throw new Error(response.error);
        const pubkey = String(response?.result?.pubkey || '');
        showStatus(pubkey
          ? `Wiederherstellung erfolgreich (${formatShortHex(pubkey)}). Seite neu laden.`
          : 'Wiederherstellung erfolgreich. Seite neu laden.');
        const signerContext = await refreshSignerIdentity(protectionRow, activeScope, true);
        activeRuntimeStatus = signerContext?.runtimeStatus || null;
        activeScope = signerContext?.scope || activeScope;
        setContactRequestContext(activeScope, activeWpApi);
        renderProfileCard(profileCard, profileHint, activeViewer, activeRuntimeStatus);
        updateUserHero(activeViewer, activeRuntimeStatus);
        await refreshUnlockState(unlockCacheState, unlockCacheHint, unlockCachePolicySelect, activeScope);
        await refreshCloudBackupState(cloudBackupMeta, {
          enableButton: cloudBackupEnableButton,
          restoreButton: cloudBackupRestoreButton,
          deleteButton: cloudBackupDeleteButton
        }, activeScope, activeWpApi);
      } catch (e) {
        showStatus(`Wiederherstellung fehlgeschlagen: ${e.message || e}`, true);
        await refreshCloudBackupState(cloudBackupMeta, {
          enableButton: cloudBackupEnableButton,
          restoreButton: cloudBackupRestoreButton,
          deleteButton: cloudBackupDeleteButton
        }, activeScope, activeWpApi);
      }
    });
  }

  if (cloudBackupDeleteButton) {
    cloudBackupDeleteButton.addEventListener('click', async () => {
      if (!activeWpApi) {
        showStatus('Löschen der Schlüsselkopie ist nur auf einem eingeloggten WordPress-Tab verfügbar.', true);
        return;
      }
      const confirmed = confirm('Schlüsselkopie in WordPress wirklich löschen?');
      if (!confirmed) return;

      setCloudButtonsDisabled({
        enableButton: cloudBackupEnableButton,
        restoreButton: cloudBackupRestoreButton,
        deleteButton: cloudBackupDeleteButton
      }, true);
      showStatus('Lösche Schlüsselkopie in WordPress...');
      try {
        const response = await chrome.runtime.sendMessage({
          type: 'NOSTR_BACKUP_DELETE',
          payload: { scope: activeScope, wpApi: activeWpApi, authBroker: activeAuthBroker }
        });
        if (response?.error) throw new Error(response.error);
        showStatus('Schlüsselkopie in WordPress gelöscht.');
        await refreshCloudBackupState(cloudBackupMeta, {
          enableButton: cloudBackupEnableButton,
          restoreButton: cloudBackupRestoreButton,
          deleteButton: cloudBackupDeleteButton
        }, activeScope, activeWpApi);
      } catch (e) {
        showStatus(`Schlüsselkopie konnte nicht gelöscht werden: ${e.message || e}`, true);
        await refreshCloudBackupState(cloudBackupMeta, {
          enableButton: cloudBackupEnableButton,
          restoreButton: cloudBackupRestoreButton,
          deleteButton: cloudBackupDeleteButton
        }, activeScope, activeWpApi);
      }
    });
  }

  // ========================================
  // Event Delegation: Copy Buttons
  // ========================================

  document.addEventListener('click', async (event) => {
    const copyButton = event.target?.closest?.('[data-copy-value]');
    if (!copyButton) return;

    const value = String(copyButton.getAttribute('data-copy-value') || '').trim();
    if (!value) {
      showStatus('Kein Wert zum Kopieren vorhanden.', true);
      return;
    }

    try {
      await navigator.clipboard.writeText(value);
      showStatus('In die Zwischenablage kopiert.');
    } catch {
      showStatus('Kopieren fehlgeschlagen.', true);
    }
  });

  // ========================================
  // Initial Contact Load (Home View is active by default)
  // ========================================
  
  await loadContacts(false);

});

// ========================================
// Helper Functions
// ========================================

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = String(text || '');
  return div.innerHTML;
}

function sanitizeWpApi(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const restUrl = String(raw.restUrl || '').trim();
  const nonce = String(raw.nonce || '').trim();
  if (!restUrl || !nonce) return null;
  return { restUrl, nonce };
}

function sanitizeAuthBroker(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const enabled = raw.enabled === true || raw.enabled === 1 || raw.enabled === '1';
  const url = String(raw.url || raw.authBrokerUrl || '').trim();
  const origin = String(raw.origin || raw.authBrokerOrigin || '').trim();
  const rpId = String(raw.rpId || raw.authBrokerRpId || '').trim().toLowerCase();
  if (!enabled && !url) return null;
  if (!url) return null;
  try {
    const parsed = new URL(url);
    if (!/^https?:$/i.test(parsed.protocol)) return null;
    return {
      enabled,
      url: parsed.href,
      origin: origin || parsed.origin,
      rpId: rpId || parsed.hostname.toLowerCase()
    };
  } catch {
    return null;
  }
}

function setContactRequestContext(scope, wpApi) {
  contactsRequestScope = normalizeScope(scope);
  contactsRequestWpApi = sanitizeWpApi(wpApi);
}

function hasProfileContext(viewer) {
  if (!viewer || typeof viewer !== 'object') return false;
  if (Number(viewer.userId) > 0) return true;
  if (String(viewer.displayName || '').trim()) return true;
  if (String(viewer.userLogin || '').trim()) return true;
  if (String(viewer.avatarUrl || '').trim()) return true;
  if (String(viewer.profileNip05 || '').trim()) return true;
  if (String(viewer.primaryDomain || '').trim()) return true;
  return false;
}

async function persistViewerCache(viewer) {
  if (!hasProfileContext(viewer)) return;

  let existing = null;
  try {
    const current = await chrome.storage.local.get([VIEWER_CACHE_KEY]);
    existing = current?.[VIEWER_CACHE_KEY] || null;
  } catch {
    existing = null;
  }

  const origin = String(viewer?.origin || '').trim();
  const validOrigin = /^https?:\/\//i.test(origin) ? origin : null;
  const userId = Number(viewer?.userId) || null;
  const fallbackScope = validOrigin && userId ? buildWpScope(validOrigin, userId) : 'global';
  const existingScope = String(existing?.scope || '').trim();
  const scope = normalizeScope(viewer?.scope || existingScope || fallbackScope);
  const primaryDomain = String(viewer?.primaryDomain || '').trim() || String(existing?.primaryDomain || '').trim() || null;

  const cacheEntry = {
    userId,
    displayName: String(viewer?.displayName || '').trim() || null,
    avatarUrl: String(viewer?.avatarUrl || '').trim() || null,
    pubkey: String(viewer?.pubkey || '').trim() || null,
    userLogin: String(viewer?.userLogin || '').trim() || null,
    profileRelayUrl: String(viewer?.profileRelayUrl || '').trim() || null,
    profileNip05: String(viewer?.profileNip05 || '').trim() || null,
    primaryDomain,
    origin: validOrigin || String(existing?.origin || '').trim() || null,
    scope,
    updatedAt: Date.now()
  };

  try {
    await chrome.storage.local.set({ [VIEWER_CACHE_KEY]: cacheEntry });
  } catch {
    // Optionaler UX-Cache - Fehler soll Popup nicht blockieren.
  }
}

async function loadViewerCache() {
  try {
    const stored = await chrome.storage.local.get([VIEWER_CACHE_KEY]);
    const raw = stored?.[VIEWER_CACHE_KEY];
    if (!raw || typeof raw !== 'object') return null;

    const origin = String(raw.origin || '').trim();
    const validOrigin = /^https?:\/\//i.test(origin) ? origin : null;
    const userId = Number(raw.userId) || null;
    const fallbackScope = validOrigin && userId ? buildWpScope(validOrigin, userId) : 'global';

    return {
      isLoggedIn: false,
      isCached: true,
      source: 'cache',
      userId,
      displayName: String(raw.displayName || '').trim() || null,
      avatarUrl: String(raw.avatarUrl || '').trim() || null,
      pubkey: String(raw.pubkey || '').trim() || null,
      userLogin: String(raw.userLogin || '').trim() || null,
      profileRelayUrl: String(raw.profileRelayUrl || '').trim() || null,
      profileNip05: String(raw.profileNip05 || '').trim() || null,
      primaryDomain: String(raw.primaryDomain || '').trim() || null,
      origin: validOrigin,
      activeSiteOrigin: null,
      scope: normalizeScope(raw.scope || fallbackScope),
      updatedAt: typeof raw.updatedAt === 'number' ? raw.updatedAt : null
    };
  } catch {
    return null;
  }
}

async function getPrimaryDomainFromDomainSync(activeOrigin) {
  const activeHost = extractHost(activeOrigin);
  if (!activeHost) return null;
  try {
    const response = await chrome.runtime.sendMessage({ type: 'NOSTR_GET_DOMAIN_SYNC_STATE' });
    if (response?.error) return null;
    const configs = Array.isArray(response?.result?.configs) ? response.result.configs : [];
    if (!configs.length) return null;

    const direct = configs.find((item) => String(item?.host || '').trim().toLowerCase() === activeHost);
    if (direct?.primaryDomain) return String(direct.primaryDomain).trim();

    const byPrimaryHost = configs.find((item) => extractHost(item?.primaryDomain || '') === activeHost);
    if (byPrimaryHost?.primaryDomain) return String(byPrimaryHost.primaryDomain).trim();

    if (configs.length === 1) {
      return String(configs[0]?.primaryDomain || '').trim() || null;
    }
    return null;
  } catch {
    return null;
  }
}

async function applyPrimaryDomainFallback(context, activeOrigin) {
  const currentPrimary = String(context?.primaryDomain || '').trim();
  if (currentPrimary) return context;

  const resolved = await getPrimaryDomainFromDomainSync(activeOrigin || context?.origin || '');
  if (!resolved) return context;
  return { ...context, primaryDomain: resolved };
}

function setCloudButtonsDisabled(buttons, disabled) {
  if (!buttons) return;
  if (buttons.enableButton) buttons.enableButton.disabled = disabled;
  if (buttons.restoreButton) buttons.restoreButton.disabled = disabled;
  if (buttons.deleteButton) buttons.deleteButton.disabled = disabled;
}

async function refreshCloudBackupState(metaNode, buttons, scope, wpApi) {
  if (!metaNode) return;
  if (!wpApi) {
    metaNode.textContent = 'Schlüsselkopie ist nur auf aktivem, eingeloggtem WordPress-Tab verfügbar.';
    setCloudButtonsDisabled(buttons, true);
    return;
  }

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'NOSTR_BACKUP_STATUS',
      payload: { scope: normalizeScope(scope), wpApi }
    });
    if (response?.error) throw new Error(response.error);
    const data = response?.result || {};
    if (!data.hasBackup) {
      metaNode.textContent = 'Keine Schlüsselkopie in WordPress vorhanden.';
      if (buttons?.enableButton) buttons.enableButton.disabled = false;
      if (buttons?.restoreButton) buttons.restoreButton.disabled = true;
      if (buttons?.deleteButton) buttons.deleteButton.disabled = true;
      return;
    }

    const updatedText = typeof data.updatedAt === 'number'
      ? new Date(data.updatedAt * 1000).toLocaleString()
      : 'unbekannt';
    const hasMatchInfo = typeof data.restoreLikelyAvailable === 'boolean';
    const restoreLikelyAvailable = data.restoreLikelyAvailable !== false;
    let restoreHint = '';
    if (hasMatchInfo && !restoreLikelyAvailable && data.restoreUnavailableReason === 'credential_mismatch') {
      restoreHint = ' Wiederherstellen ist für diesen Browser deaktiviert (Passkey-Credential stammt vermutlich aus anderem Browser).';
    } else if (!hasMatchInfo || !data.passkeyCredentialFingerprint) {
      restoreHint = ' Restore-Kompatibilität kann nicht vorab geprüft werden.';
    }

    metaNode.textContent = `Schlüsselkopie vorhanden für ${formatShortHex(data.pubkey || '')}. Letztes Update: ${updatedText}.${restoreHint}`;
    if (buttons?.enableButton) buttons.enableButton.disabled = false;
    if (buttons?.restoreButton) buttons.restoreButton.disabled = !restoreLikelyAvailable;
    if (buttons?.deleteButton) buttons.deleteButton.disabled = false;
  } catch (error) {
    metaNode.textContent = `Status der Schlüsselkopie konnte nicht geladen werden: ${error.message || error}`;
    setCloudButtonsDisabled(buttons, false);
    if (buttons?.restoreButton) buttons.restoreButton.disabled = true;
    if (buttons?.deleteButton) buttons.deleteButton.disabled = true;
  }
}

async function refreshSignerIdentity(cardNode, requestedScope, allowFallback = true) {
  try {
    let activeScope = normalizeScope(requestedScope);
    let runtimeStatus = await getScopedRuntimeStatus(activeScope);

    if (allowFallback && !runtimeStatus?.hasKey) {
      const info = await chrome.runtime.sendMessage({
        type: 'NOSTR_GET_KEY_SCOPE_INFO',
        payload: { requestedScope: activeScope }
      });
      if (!info?.error) {
        const preferredScope = normalizeScope(info?.result?.preferredScope || activeScope);
        if (preferredScope !== activeScope) {
          activeScope = preferredScope;
          runtimeStatus = await getScopedRuntimeStatus(activeScope);
        }
      }
    }

    renderProtectionRow(cardNode, runtimeStatus);
    return { scope: activeScope, runtimeStatus };
  } catch (error) {
    if (cardNode) {
      cardNode.innerHTML = `<p class="empty">Schutzart konnte nicht geladen werden: ${escapeHtml(error.message || String(error))}</p>`;
    }
    return { scope: normalizeScope(requestedScope), runtimeStatus: null };
  }
}

async function getScopedRuntimeStatus(scope) {
  const response = await chrome.runtime.sendMessage({
    type: 'NOSTR_GET_STATUS',
    payload: { scope: normalizeScope(scope) }
  });
  if (response?.error) throw new Error(response.error);
  return response?.result || null;
}

function renderProtectionRow(rowNode, runtimeStatus) {
  if (!rowNode) return;

  if (!runtimeStatus || !runtimeStatus.hasKey) {
    rowNode.innerHTML = '';
    return;
  }

  const currentMode = String(runtimeStatus.protectionMode || '');

  rowNode.innerHTML = `
    <div class="wp-user-meta protection-row">
      <strong>Schutzart:</strong>
      <select id="protection-mode-select" class="protection-select">
        <option value="passkey" ${currentMode === 'passkey' ? 'selected' : ''}>🔐 Passkey</option>
        <option value="password" ${currentMode === 'password' ? 'selected' : ''}>🔑 Passwort</option>
        <option value="none" ${currentMode === 'none' ? 'selected' : ''}>🔓 Ohne Schutz</option>
      </select>
      <span id="protection-change-status" class="protection-status"></span>
    </div>
  `;

  const protectionSelect = rowNode.querySelector('#protection-mode-select');
  if (protectionSelect) {
    protectionSelect.addEventListener('change', async () => {
      const newMode = protectionSelect.value;
      const statusEl = rowNode.querySelector('#protection-change-status');
      protectionSelect.disabled = true;
      if (statusEl) { statusEl.textContent = 'Wird ge\u00e4ndert...'; statusEl.className = 'protection-status changing'; }

      try {
        const response = await chrome.runtime.sendMessage({
          type: 'NOSTR_CHANGE_PROTECTION',
          payload: { mode: newMode, scope: runtimeStatus.keyScope }
        });
        if (response?.error) throw new Error(response.error);
        if (statusEl) { statusEl.textContent = '\u2713 Gespeichert'; statusEl.className = 'protection-status success'; }
        setTimeout(() => { if (statusEl) statusEl.textContent = ''; }, 2500);
      } catch (err) {
        if (statusEl) { statusEl.textContent = '\u2717 ' + (err.message || 'Fehler'); statusEl.className = 'protection-status error'; }
        protectionSelect.value = currentMode;
        setTimeout(() => { if (statusEl) statusEl.textContent = ''; }, 4000);
      } finally {
        protectionSelect.disabled = false;
      }
    });
  }
}

function renderProfileCard(cardNode, hintNode, viewer, runtimeStatus) {
  if (!cardNode) return;

  if (!hasProfileContext(viewer)) {
    cardNode.innerHTML = '<p class="empty">Kein Profilkontext verfügbar.</p>';
    if (hintNode) {
      hintNode.textContent = 'Öffne eine WordPress-Seite mit WP-Nostr, damit Profildaten geladen werden.';
    }
    return;
  }

  const avatarUrl = String(viewer.avatarUrl || '').trim();
  const displayName = String(viewer.displayName || viewer.userLogin || `User #${viewer.userId || ''}`).trim();
  const userLogin = String(viewer.userLogin || '').trim();
  const pubkeyHex = String(runtimeStatus?.pubkeyHex || '').trim();
  const npub = String(runtimeStatus?.npub || '').trim();
  const nip05 = String(viewer.profileNip05 || '').trim();
  const relays = parseRelayList(viewer.profileRelayUrl);
  const missingFields = getMissingProfileFields(viewer);
  const fromCacheText = viewer?.isCached
    ? '<div class="wp-user-meta"><strong>Quelle:</strong> Extension-Speicher (zuletzt geladenes WP-Profil)</div>'
    : '';

  cardNode.innerHTML = `
    <div class="profile-main">
      ${avatarUrl
        ? `<img class="wp-user-avatar" src="${escapeHtml(avatarUrl)}" alt="Avatar" />`
        : '<div class="wp-user-avatar"></div>'}
      <div>
        <div class="wp-user-name">${escapeHtml(displayName || '-')}</div>
        <div class="wp-user-meta"><strong>Login:</strong> ${escapeHtml(userLogin || '-')}</div>
        <div class="wp-user-meta"><strong>Status:</strong> ${missingFields.length ? 'Profil unvollständig' : 'Profil vollständig'}</div>
      </div>
    </div>
    <div class="profile-copy-grid">
      ${renderCopyLine('Npub', npub)}
      ${renderCopyLine('Pubkey (hex)', pubkeyHex)}
    </div>
    <div class="wp-user-meta"><strong>NIP-05:</strong> ${escapeHtml(nip05 || '(nicht gesetzt)')}</div>
    <div class="wp-user-meta"><strong>Relay(s):</strong> ${escapeHtml(relays.length ? relays.join(', ') : '(kein Profil-Relay konfiguriert)')}</div>
    ${fromCacheText}
    ${missingFields.length
      ? `<div class="wp-user-meta"><strong>Fehlende Angaben:</strong> ${escapeHtml(missingFields.join(', '))}</div>`
      : '<div class="wp-user-meta"><strong>Fehlende Angaben:</strong> keine</div>'}
    ${npub ? `<div class="wp-user-meta"><a href="https://njump.me/${encodeURIComponent(npub)}" target="_blank" rel="noopener noreferrer">Profil öffnen (njump)</a></div>` : ''}
  `;

  if (!hintNode) return;
  hintNode.textContent = viewer?.isCached
    ? 'Profil stammt aus dem Extension-Speicher. Für aktuelle WP-Daten kurz auf einer WP-Seite neu laden.'
    : 'Per Klick auf "Profil an Nostr senden" werden Anzeigename, Avatar und NIP-05 als kind:0 Event veröffentlicht.';
}

function renderInstanceCard(cardNode, viewer) {
  if (!cardNode) return;

  const activeOrigin = String(viewer?.activeSiteOrigin || '').trim();
  const profileOrigin = String(viewer?.origin || '').trim();
  const primaryDomain = String(viewer?.primaryDomain || '').trim();

  if (!activeOrigin && !profileOrigin && !primaryDomain) {
    cardNode.innerHTML = '<p class="empty">Keine Instanz-Informationen verfügbar.</p>';
    return;
  }
  const activeHost = extractHost(activeOrigin);
  const primaryHost = extractHost(primaryDomain);
  let statusText = 'Primary Domain nicht gesetzt';
  if (primaryHost && !activeHost) {
    statusText = 'Primary Domain gespeichert';
  } else if (primaryHost) {
    statusText = activeHost === primaryHost
      ? 'Aktive Website entspricht der Primary Domain'
      : 'Aktive Website weicht von der Primary Domain ab';
  }

  cardNode.innerHTML = `
    <div class="wp-user-meta"><strong>Aktive Website:</strong> ${escapeHtml(activeOrigin || '(kein WP-Tab aktiv)')}</div>
    <div class="wp-user-meta"><strong>Zuletzt geladen aus:</strong> ${escapeHtml(profileOrigin || '(nicht verfügbar)')}</div>
    <div class="wp-user-meta"><strong>Primary Domain:</strong> ${escapeHtml(primaryDomain || '(nicht gesetzt)')}</div>
    <div class="wp-user-meta"><strong>Status:</strong> ${escapeHtml(statusText)}</div>
  `;
}

function getMissingProfileFields(viewer) {
  const missing = [];
  const displayName = String(viewer?.displayName || '').trim();
  const avatarUrl = String(viewer?.avatarUrl || '').trim();
  const nip05 = String(viewer?.profileNip05 || '').trim();

  if (!displayName) missing.push('Anzeigename');
  if (!avatarUrl) missing.push('Avatar');
  if (!nip05) missing.push('NIP-05 (empfohlen)');
  return missing;
}

function renderCopyLine(label, value) {
  const text = String(value || '').trim();
  const display = text || '(nicht verfügbar)';
  const copyAttr = text ? ` data-copy-value="${escapeHtml(text)}"` : '';
  const disabledAttr = text ? '' : ' disabled';
  return `
    <div class="copy-line">
      <div class="copy-value"><strong>${escapeHtml(label)}:</strong> ${escapeHtml(display)}</div>
      <button class="btn-copy" type="button"${copyAttr}${disabledAttr}>Kopieren</button>
    </div>
  `;
}

function buildProfilePublishPayload(viewer) {
  const relays = parseRelayList(viewer?.profileRelayUrl);
  const profile = {};

  const userLogin = String(viewer?.userLogin || '').trim();
  const displayName = String(viewer?.displayName || '').trim();
  const avatarUrl = String(viewer?.avatarUrl || '').trim();
  const nip05 = String(viewer?.profileNip05 || '').trim();
  const website = String(viewer?.origin || '').trim();

  if (userLogin) profile.name = userLogin;
  if (displayName) profile.display_name = displayName;
  if (avatarUrl) profile.picture = avatarUrl;
  if (nip05) profile.nip05 = nip05;
  if (website) profile.website = website;

  return { relays, profile };
}

function parseRelayList(rawRelays) {
  const items = String(rawRelays || '')
    .split(/[\s,;]+/g)
    .map((value) => normalizeRelayUrl(value))
    .filter(Boolean);
  return Array.from(new Set(items));
}

function normalizeRelayUrl(input) {
  const value = String(input || '').trim();
  if (!value) return null;

  let candidate = value;
  if (/^https?:\/\//i.test(candidate)) {
    candidate = candidate.replace(/^http:\/\//i, 'ws://').replace(/^https:\/\//i, 'wss://');
  }
  if (!/^wss?:\/\//i.test(candidate)) {
    candidate = `wss://${candidate.replace(/^\/+/, '')}`;
  }

  try {
    const parsed = new URL(candidate);
    if (!/^wss?:$/i.test(parsed.protocol)) return null;
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch {
    return null;
  }
}


function extractHost(input) {
  const value = String(input || '').trim();
  if (!value) return '';
  try {
    return String(new URL(value).host || '').trim().toLowerCase();
  } catch {
    return value.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase();
  }
}

function normalizeScope(scope) {
  const value = String(scope || '').trim();
  if (!value) return 'global';
  if (!/^[a-zA-Z0-9:._-]{1,120}$/.test(value)) return 'global';
  return value;
}

function formatProtectionMode(mode) {
  switch (String(mode || '')) {
    case 'passkey': return 'Passkey';
    case 'none': return 'Kein Passwort';
    case 'password': return 'Passwort';
    default: return 'Unbekannt';
  }
}

function setUnlockStateBadge(unlockCacheState, runtimeStatus) {
  if (!unlockCacheState) return;
  const isActive = Boolean(runtimeStatus?.hasKey) && !Boolean(runtimeStatus?.locked);
  unlockCacheState.textContent = isActive ? 'aktiv' : 'inaktiv';
  unlockCacheState.classList.toggle('state-active', isActive);
  unlockCacheState.classList.toggle('state-inactive', !isActive);
}

function normalizeUnlockCachePolicy(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (FALLBACK_UNLOCK_CACHE_POLICIES.includes(normalized)) return normalized;
  return DEFAULT_UNLOCK_CACHE_POLICY;
}

function getAllowedUnlockPolicies(runtimeStatus) {
  const rawPolicies = runtimeStatus?.unlockCacheAllowedPolicies;
  if (!Array.isArray(rawPolicies) || rawPolicies.length === 0) {
    return FALLBACK_UNLOCK_CACHE_POLICIES;
  }

  const allowed = rawPolicies
    .map((entry) => normalizeUnlockCachePolicy(entry))
    .filter((entry, index, arr) => arr.indexOf(entry) === index);

  return allowed.length ? allowed : FALLBACK_UNLOCK_CACHE_POLICIES;
}

function formatUnlockCachePolicyLabel(policy) {
  return UNLOCK_CACHE_POLICY_LABELS[normalizeUnlockCachePolicy(policy)] || 'Unbekannt';
}

function updateUnlockPolicySelect(unlockCachePolicySelect, runtimeStatus) {
  if (!unlockCachePolicySelect) return;

  const allowedPolicies = getAllowedUnlockPolicies(runtimeStatus);
  const selectedPolicy = normalizeUnlockCachePolicy(runtimeStatus?.unlockCachePolicy);
  const existingOptions = Array.from(unlockCachePolicySelect.options).map((option) => option.value);
  const sameOptions = existingOptions.length === allowedPolicies.length
    && existingOptions.every((value, index) => value === allowedPolicies[index]);

  if (!sameOptions) {
    unlockCachePolicySelect.innerHTML = '';
    for (const policy of allowedPolicies) {
      const option = document.createElement('option');
      option.value = policy;
      option.textContent = formatUnlockCachePolicyLabel(policy);
      unlockCachePolicySelect.appendChild(option);
    }
  }

  unlockCachePolicySelect.value = allowedPolicies.includes(selectedPolicy)
    ? selectedPolicy
    : normalizeUnlockCachePolicy(allowedPolicies[0]);
}

async function refreshUnlockState(unlockCacheState, unlockCacheHint, unlockCachePolicySelect, scope) {
  try {
    const response = await chrome.runtime.sendMessage({
      type: 'NOSTR_GET_STATUS',
      payload: { scope }
    });
    const runtimeStatus = response?.result;
    if (response?.error) throw new Error(response.error);

    setUnlockStateBadge(unlockCacheState, runtimeStatus);
    updateUnlockPolicySelect(unlockCachePolicySelect, runtimeStatus);
    if (unlockCacheHint) unlockCacheHint.textContent = formatUnlockCacheHint(runtimeStatus);
  } catch {
    setUnlockStateBadge(unlockCacheState, null);
    updateUnlockPolicySelect(unlockCachePolicySelect, null);
    if (unlockCacheHint) unlockCacheHint.textContent = 'ReLogin-Status konnte nicht geladen werden.';
  }
}

async function loadViewerContext(cardNode, statusNode) {
  const cachedViewer = await loadViewerCache();
  const tabContext = await getActiveTabContext();
  const origin = tabContext?.origin || null;
  if (!origin) {
    renderViewerCard(cardNode, null, null);
    if (cachedViewer) {
      const context = {
        ...cachedViewer,
        isLoggedIn: false,
        isCached: true,
        source: 'cache',
        activeSiteOrigin: null,
        wpApi: null,
        authBroker: null
      };
      return await applyPrimaryDomainFallback(context, cachedViewer?.origin || '');
    }
    return await applyPrimaryDomainFallback(
      { isLoggedIn: false, scope: 'global', origin: null, activeSiteOrigin: null, wpApi: null, authBroker: null },
      ''
    );
  }

  const viewerFromTab = await getViewerFromActiveTab(tabContext?.id);
  if (viewerFromTab?.pending) {
    renderViewerCard(cardNode, { pending: true }, origin);
    if (cachedViewer) {
      const context = {
        ...cachedViewer,
        isLoggedIn: false,
        pending: true,
        isCached: true,
        source: 'cache',
        activeSiteOrigin: origin,
        wpApi: sanitizeWpApi(viewerFromTab.wpApi),
        authBroker: sanitizeAuthBroker(viewerFromTab.authBroker)
      };
      return await applyPrimaryDomainFallback(context, origin);
    }
    const context = {
      isLoggedIn: false,
      pending: true,
      scope: 'global',
      origin,
      activeSiteOrigin: origin,
      wpApi: sanitizeWpApi(viewerFromTab.wpApi),
      authBroker: sanitizeAuthBroker(viewerFromTab.authBroker)
    };
    return await applyPrimaryDomainFallback(context, origin);
  }
  if (viewerFromTab?.viewer) {
    const viewer = viewerFromTab.viewer;
    if (viewerFromTab.source) viewer.source = viewerFromTab.source;
    const scope = viewer?.isLoggedIn && viewer?.userId
      ? buildWpScope(origin, viewer.userId)
      : (cachedViewer?.scope || 'global');
    renderViewerCard(cardNode, viewer, origin);
    const context = {
      ...viewer,
      scope,
      origin,
      activeSiteOrigin: origin,
      wpApi: sanitizeWpApi(viewerFromTab.wpApi),
      authBroker: sanitizeAuthBroker(viewerFromTab.authBroker || viewer.authBroker)
    };
    const withPrimary = await applyPrimaryDomainFallback(context, origin);
    await persistViewerCache(withPrimary);
    return withPrimary;
  }

  try {
    const viewer = await fetchWpViewer(origin);
    viewer.source = 'rest';
    const scope = viewer?.isLoggedIn && viewer?.userId
      ? buildWpScope(origin, viewer.userId)
      : (cachedViewer?.scope || 'global');
    renderViewerCard(cardNode, viewer, origin);
    const context = {
      ...viewer,
      scope,
      origin,
      activeSiteOrigin: origin,
      wpApi: null,
      authBroker: sanitizeAuthBroker(viewer.authBroker)
    };
    const withPrimary = await applyPrimaryDomainFallback(context, origin);
    await persistViewerCache(withPrimary);
    return withPrimary;
  } catch (error) {
    const errorText = String(error?.message || error || '');
    const likelyNoWpEndpoint =
      errorText.includes('HTTP 404') ||
      errorText.includes('HTTP 403') ||
      errorText.includes('Failed to fetch') ||
      errorText.includes('NetworkError');

    if (likelyNoWpEndpoint) {
      renderViewerCard(cardNode, null, origin);
      if (cachedViewer) {
        const context = {
          ...cachedViewer,
          isLoggedIn: false,
          isCached: true,
          source: 'cache',
          activeSiteOrigin: origin,
          wpApi: null,
          authBroker: null
        };
        return await applyPrimaryDomainFallback(context, origin);
      }
      return await applyPrimaryDomainFallback(
        { isLoggedIn: false, scope: 'global', origin: null, activeSiteOrigin: origin, wpApi: null, authBroker: null },
        origin
      );
    }

    renderViewerCard(cardNode, null, origin, error);
    if (statusNode) {
      statusNode.textContent = `WP-Viewer konnte nicht geladen werden: ${error.message || error}`;
    }
    if (cachedViewer) {
      const context = {
        ...cachedViewer,
        isLoggedIn: false,
        isCached: true,
        source: 'cache',
        activeSiteOrigin: origin,
        wpApi: null,
        authBroker: null
      };
      return await applyPrimaryDomainFallback(context, origin);
    }
    return await applyPrimaryDomainFallback(
      { isLoggedIn: false, scope: 'global', origin: null, activeSiteOrigin: origin, wpApi: null, authBroker: null },
      origin
    );
  }
}

async function getActiveTabContext() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = tabs?.[0];
  if (!tab?.url) return null;

  try {
    const url = new URL(tab.url);
    if (!/^https?:$/i.test(url.protocol)) return { id: tab.id ?? null, origin: null };
    return { id: tab.id ?? null, origin: url.origin };
  } catch {
    return { id: tab.id ?? null, origin: null };
  }
}

async function getViewerFromActiveTab(tabId) {
  if (typeof tabId !== 'number') return null;
  try {
    const response = await chrome.tabs.sendMessage(tabId, { type: 'NOSTR_GET_PAGE_CONTEXT' });
    if (response?.pending === true) {
      return {
        pending: true,
        wpApi: sanitizeWpApi(response?.wpApi),
        authBroker: sanitizeAuthBroker(response?.authBroker)
      };
    }
    const viewer = response?.viewer;
    if (!viewer || typeof viewer !== 'object') return null;
    const source = String(response?.source || '').trim().toLowerCase();
    return {
      pending: false,
      source: source === 'rest' ? 'rest' : 'dom',
      wpApi: sanitizeWpApi(response?.wpApi),
      authBroker: sanitizeAuthBroker(response?.authBroker || viewer?.authBroker),
      viewer: {
        isLoggedIn: viewer.isLoggedIn === true,
        userId: Number(viewer.userId) || null,
        displayName: viewer.displayName || null,
        avatarUrl: viewer.avatarUrl || null,
        pubkey: viewer.pubkey || null,
        userLogin: viewer.userLogin || null,
        profileRelayUrl: viewer.profileRelayUrl || null,
        profileNip05: viewer.profileNip05 || null,
        primaryDomain: viewer.primaryDomain || null,
        authBroker: sanitizeAuthBroker(viewer?.authBroker)
      }
    };
  } catch {
    return null;
  }
}

async function fetchWpViewer(origin) {
  const response = await fetch(`${origin}/wp-json/nostr/v1/viewer`, {
    method: 'GET',
    credentials: 'include',
    cache: 'no-store'
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  const viewer = await response.json();
  if (!viewer || typeof viewer !== 'object') {
    throw new Error('Invalid viewer payload');
  }
  viewer.authBroker = sanitizeAuthBroker({
    enabled: viewer.authBrokerEnabled,
    url: viewer.authBrokerUrl,
    origin: viewer.authBrokerOrigin,
    rpId: viewer.authBrokerRpId
  });
  viewer.userLogin = viewer.userLogin || null;
  viewer.profileRelayUrl = viewer.profileRelayUrl || null;
  viewer.profileNip05 = viewer.profileNip05 || null;
  viewer.primaryDomain = viewer.primaryDomain || null;
  return viewer;
}

function renderViewerCard(cardNode, viewer, origin, error = null) {
  if (!cardNode) return;

  if (error) {
    cardNode.innerHTML = `<p class="empty">Fehler beim Laden: ${escapeHtml(error.message || String(error))}</p>`;
    return;
  }

  if (viewer?.pending) {
    cardNode.innerHTML = `
      <p class="empty">
        ${origin
          ? `WP-Kontext auf ${escapeHtml(origin)} wird noch geladen...`
          : 'Kein aktiver WordPress-Tab erkannt.'}
      </p>
    `;
    return;
  }

  if (!viewer || !viewer.isLoggedIn) {
    const loggedOutText = viewer?.source === 'rest'
      ? `Tab-Kontext nicht verfügbar. REST meldet auf ${escapeHtml(origin || '-')} aktuell keinen WP-Login.`
      : (origin
          ? `Auf ${escapeHtml(origin)} ist aktuell kein WordPress-Benutzer eingeloggt.`
          : 'Kein aktiver WordPress-Tab erkannt.');
    cardNode.innerHTML = `
      <p class="empty">
        ${loggedOutText}
      </p>
    `;
    return;
  }

  const avatarUrl = String(viewer.avatarUrl || '').trim();
  const displayName = String(viewer.displayName || `User #${viewer.userId}`);
  const pubkey = String(viewer.pubkey || '');
  const userLogin = String(viewer.userLogin || '').trim();
  const userId = Number(viewer.userId) || 0;

  cardNode.innerHTML = `
    <div class="wp-user-main">
      ${avatarUrl
        ? `<img class="wp-user-avatar" src="${escapeHtml(avatarUrl)}" alt="Avatar" />`
        : '<div class="wp-user-avatar"></div>'}
      <div>
        <div class="wp-user-name">${escapeHtml(displayName)}</div>
        <div class="hint">User ID: ${escapeHtml(String(userId))}</div>
      </div>
    </div>
    <div class="wp-user-meta"><strong>Domain:</strong> ${escapeHtml(origin || '-')}</div>
    <div class="wp-user-meta"><strong>Login:</strong> ${escapeHtml(userLogin || '-')}</div>
    <div class="wp-user-meta"><strong>Avatar URL:</strong> ${escapeHtml(avatarUrl || '-')}</div>
    <div class="wp-user-meta"><strong>WP registrierter Pubkey:</strong> ${escapeHtml(pubkey || 'noch nicht registriert')}</div>
  `;
}

function buildWpScope(origin, userId) {
  try {
    const url = new URL(origin);
    const host = String(url.host || '').trim().toLowerCase();
    const normalizedUserId = Number(userId) || 0;
    if (!host || normalizedUserId <= 0) return 'global';
    return `wp:${host}:u:${normalizedUserId}`;
  } catch {
    return 'global';
  }
}

function formatUnlockCacheHint(runtimeStatus) {
  const hasKey = Boolean(runtimeStatus?.hasKey);
  const locked = Boolean(runtimeStatus?.locked);
  const expiresAt = runtimeStatus?.cacheExpiresAt;

  if (!hasKey) {
    return 'Noch kein lokaler Nostr-Schlüssel eingerichtet.';
  }

  const expiryText = (typeof expiresAt === 'number')
    ? new Date(expiresAt).toLocaleTimeString()
    : null;

  if (locked) {
    return 'ReLogin ist derzeit nicht aktiv.';
  }

  if (expiryText) {
    return `ReLogin ist aktiv bis ca. ${expiryText}.`;
  }

  return 'ReLogin ist aktiv.';
}

function formatShortHex(hex) {
  const value = String(hex || '').trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(value)) return value || 'unbekannt';
  return `${value.slice(0, 12)}...${value.slice(-8)}`;
}

// ========================================
// DM-Relay Functions (für TASK-19/20)
// ========================================

async function loadDmRelay() {
  try {
    const result = await chrome.storage.local.get([DM_RELAY_KEY]);
    return String(result[DM_RELAY_KEY] || '').trim();
  } catch {
    return '';
  }
}

async function saveDmRelay(url) {
  const normalized = normalizeRelayUrl(url);
  if (url && !normalized) {
    throw new Error('Ungültige Relay-URL');
  }
  await chrome.storage.local.set({ [DM_RELAY_KEY]: normalized || '' });
  return normalized;
}

// ========================================
// Contact List Functions (TASK-18)
// ========================================

let currentContacts = [];
let currentContactFilter = 'all';
let contactSearchQuery = '';

async function loadContacts(forceRefresh = false) {
  const contactList = document.getElementById('contact-list');
  if (!contactList) return;
  
  // Show loading state
  contactList.innerHTML = '<div class="contact-loading"><p class="empty">Kontakte werden geladen...</p></div>';
  
  try {
    // Fetch from background
    const requestType = forceRefresh ? 'NOSTR_REFRESH_CONTACTS' : 'NOSTR_GET_CONTACTS';
    const response = await chrome.runtime.sendMessage({
      type: requestType,
      payload: {
        scope: contactsRequestScope,
        wpApi: contactsRequestWpApi
      }
    });
    
    if (response?.error) {
      throw new Error(response.error);
    }
    
    currentContacts = response?.result?.contacts || [];
    renderContacts(currentContacts, currentContactFilter, contactSearchQuery);
    
    // Show status
    const count = currentContacts.length;
    if (count > 0) {
      showStatus(`${count} Kontakt${count !== 1 ? 'e' : ''} geladen.`);
    }
  } catch (error) {
    renderContactError(error.message || error);
    showStatus(`Fehler beim Laden der Kontakte: ${error.message || error}`, true);
  }
}

function getContactSources(contact) {
  const sources = new Set();
  const rawSources = Array.isArray(contact?.sources) ? contact.sources : [];
  for (const source of rawSources) {
    const normalized = String(source || '').trim().toLowerCase();
    if (!normalized) continue;
    if (normalized === 'wp') {
      sources.add('wordpress');
      continue;
    }
    if (normalized === 'both' || normalized === 'merged') {
      sources.add('nostr');
      sources.add('wordpress');
      continue;
    }
    sources.add(normalized);
  }

  const rawSource = String(contact?.source || '').trim().toLowerCase();
  if (rawSource === 'wp') {
    sources.add('wordpress');
  } else if (rawSource === 'both' || rawSource === 'merged') {
    sources.add('nostr');
    sources.add('wordpress');
  } else if (rawSource) {
    sources.add(rawSource);
  }

  if (!sources.size) {
    sources.add('nostr');
  }
  return Array.from(sources);
}

function renderContacts(contacts, sourceFilter = 'all', searchQuery = '') {
  const contactList = document.getElementById('contact-list');
  if (!contactList) return;
  
  // Filter by source
  let filtered = contacts;
  if (sourceFilter !== 'all') {
    filtered = filtered.filter(c => {
      const sources = getContactSources(c);
      if (sourceFilter === 'nostr') return sources.includes('nostr');
      if (sourceFilter === 'wordpress') return sources.includes('wordpress');
      return true;
    });
  }
  
  // Filter by search query
  if (searchQuery && searchQuery.trim()) {
    const query = searchQuery.toLowerCase().trim();
    filtered = filtered.filter(c => {
      const name = String(c.displayName || c.name || '').toLowerCase();
      const nip05 = String(c.nip05 || '').toLowerCase();
      const npub = String(c.npub || '').toLowerCase();
      return name.includes(query) || nip05.includes(query) || npub.includes(query);
    });
  }
  
  // Sort by displayName
  filtered.sort((a, b) => {
    const nameA = String(a.displayName || a.name || '').toLowerCase();
    const nameB = String(b.displayName || b.name || '').toLowerCase();
    return nameA.localeCompare(nameB);
  });
  
  if (filtered.length === 0) {
    if (contacts.length === 0) {
      renderEmptyContacts('Keine Kontakte gefunden. Verbinde deine Nostr-Identität oder logge dich in WordPress ein.');
    } else {
      renderEmptyContacts('Keine Kontakte entsprechen dem Filter.');
    }
    return;
  }
  
  const html = filtered.map(contact => renderContactItem(contact)).join('');
  contactList.innerHTML = html;
  
  // Add click handlers -> Open Conversation
  contactList.querySelectorAll('.contact-item').forEach(item => {
    item.addEventListener('click', (e) => {
      // Prevent clicking if selecting text or something? No, standard click.
      const pubkey = item.dataset.pubkey;
      if (pubkey) {
        openConversation(pubkey);
      }
    });

    // Handle Enter key for accessibility
    item.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        const pubkey = item.dataset.pubkey;
        if (pubkey) openConversation(pubkey);
      }
    });
  });
}

// CSP-compliant avatar error handling (replaces inline onerror)
document.addEventListener('error', function(e) {
  if (e.target.tagName === 'IMG' && e.target.dataset.fallback === 'avatar') {
    const parent = e.target.parentElement;
    if (parent) {
      parent.innerHTML = '<span class="contact-avatar-placeholder">👤</span>';
    }
  }
}, true); // 'true' = capture phase to catch img errors

function renderContactItem(contact) {
  const pubkey = String(contact.pubkey || '');
  const displayName = String(contact.displayName || contact.name || '').trim() || formatShortHex(pubkey);
  const nip05 = String(contact.nip05 || '').trim();
  const avatarUrl = String(contact.picture || contact.avatarUrl || '').trim();
  
  // Determine source badge not needed for chat view usually, but good for info
  // We use the CSS from TASK-20 which expects specific structure
  
  const avatarHtml = avatarUrl
    ? `<img src="${escapeHtml(avatarUrl)}" class="contact-avatar-img" alt="" data-fallback="avatar" />`
    : '<span class="contact-avatar-placeholder">👤</span>';
  
  // Placeholder for last message (TASK-20 optional: "preview")
  const previewText = nip05 || formatShortHex(pubkey);

  return `
    <div class="contact-item" data-pubkey="${escapeHtml(pubkey)}" tabindex="0" role="button">
      <div class="contact-avatar">${avatarHtml}</div>
      <div class="contact-info">
        <div class="contact-name">${escapeHtml(displayName)}</div>
        <div class="contact-preview">${escapeHtml(previewText)}</div>
      </div>
      <div class="contact-meta">
         <!-- Time / Unread badge placeholders -->
      </div>
    </div>
  `;
}

function renderEmptyContacts(message) {
  const contactList = document.getElementById('contact-list');
  if (!contactList) return;
  
  contactList.innerHTML = `
    <div class="contact-empty">
      <p class="empty">${escapeHtml(message)}</p>
    </div>
  `;
}

function renderContactError(error) {
  const contactList = document.getElementById('contact-list');
  if (!contactList) return;
  
  contactList.innerHTML = `
    <div class="contact-error">
      <p class="empty">Fehler: ${escapeHtml(error)}</p>
    </div>
  `;
}

function initContactListEvents() {
  // Refresh button
  const refreshButton = document.getElementById('refresh-contacts');
  if (refreshButton) {
    refreshButton.addEventListener('click', async () => {
      refreshButton.disabled = true;
      try {
        await loadContacts(true);
      } finally {
        refreshButton.disabled = false;
      }
    });
  }
  
  // Search input
  const searchInput = document.getElementById('contact-search-input');
  if (searchInput) {
    let searchTimeout = null;
    searchInput.addEventListener('input', () => {
      if (searchTimeout) clearTimeout(searchTimeout);
      searchTimeout = setTimeout(() => {
        contactSearchQuery = searchInput.value;
        renderContacts(currentContacts, currentContactFilter, contactSearchQuery);
      }, 200);
    });
  }

  const toggleAddButton = document.getElementById('toggle-add-contact');
  const addContactForm = document.getElementById('contact-add-form');
  const addContactInput = document.getElementById('add-contact-input');
  const addContactSubmit = document.getElementById('add-contact-submit');

  const closeAddContactForm = (clearInput = true) => {
    if (addContactForm) {
      addContactForm.hidden = true;
    }
    if (clearInput && addContactInput) {
      addContactInput.value = '';
    }
  };

  if (toggleAddButton && addContactForm) {
    toggleAddButton.addEventListener('click', () => {
      const nextHidden = !addContactForm.hidden;
      addContactForm.hidden = nextHidden;
      if (!nextHidden && addContactInput) {
        addContactInput.focus();
        addContactInput.select();
      }
      if (nextHidden && addContactInput) {
        addContactInput.value = '';
      }
    });
  }

  const submitAddContact = async () => {
    const value = String(addContactInput?.value || '').trim();
    if (!value) {
      showStatus('Bitte einen Pubkey (hex oder npub) eingeben.', true);
      return;
    }

    if (addContactSubmit) addContactSubmit.disabled = true;
    if (toggleAddButton) toggleAddButton.disabled = true;
    if (addContactInput) addContactInput.disabled = true;

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'NOSTR_ADD_CONTACT',
        payload: {
          scope: contactsRequestScope,
          contact: value
        }
      });

      if (response?.error) {
        throw new Error(response.error);
      }

      const result = response?.result || {};
      if (result.alreadyExists) {
        showStatus('Kontakt ist bereits in deiner Nostr-Kontaktliste.');
      } else {
        showStatus('Kontakt wurde hinzugefügt.');
      }

      closeAddContactForm(true);
      await loadContacts(true);
    } catch (error) {
      showStatus(`Kontakt konnte nicht hinzugefügt werden: ${error.message || error}`, true);
    } finally {
      if (addContactSubmit) addContactSubmit.disabled = false;
      if (toggleAddButton) toggleAddButton.disabled = false;
      if (addContactInput) addContactInput.disabled = false;
    }
  };

  if (addContactSubmit) {
    addContactSubmit.addEventListener('click', submitAddContact);
  }

  if (addContactInput) {
    addContactInput.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        closeAddContactForm(true);
      }
      if (event.key === 'Enter') {
        event.preventDefault();
        submitAddContact();
      }
    });
  }
  
  // Filter buttons
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentContactFilter = btn.dataset.source || 'all';
      renderContacts(currentContacts, currentContactFilter, contactSearchQuery);
    });
  });
}

// ========================================
// TASK-20: Chat Logic & Helpers
// ========================================

let activeConversationPubkey = null;

function formatRelativeTime(unixTimestamp) {
  if (!unixTimestamp) return '';
  const diff = Math.floor(Date.now() / 1000) - unixTimestamp;
  if (diff < 60) return 'jetzt';
  if (diff < 3600) return `${Math.floor(diff / 60)}m`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h`;
  if (diff < 604800) return `${Math.floor(diff / 86400)}d`;
  return new Date(unixTimestamp * 1000).toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit' });
}

function formatMessageTime(unixTimestamp) {
  if (!unixTimestamp) return '';
  return new Date(unixTimestamp * 1000).toLocaleTimeString('de-DE', { 
    hour: '2-digit', 
    minute: '2-digit' 
  });
}

function renderMinimalMarkdown(text) {
  if (!text) return '';
  let escaped = escapeHtml(text);
  escaped = escaped.replace(/`([^`]+)`/g, '<code>$1</code>');
  escaped = escaped.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  escaped = escaped.replace(/(?<![<code>])\*([^*]+)\*(?![<])/g, '<em>$1</em>');
  escaped = escaped.replace(
    /\[([^\]]+)\]\(([^)]+)\)/g,
    '<a href="$2" rel="nofollow noopener noreferrer" target="_blank">$1</a>'
  );
  escaped = escaped.replace(/^- (.+)$/gm, '• $1');
  escaped = escaped.replace(/\n/g, '<br>');
  return escaped;
}

// Live Update Listener for new messages
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'NOSTR_NEW_DM') {
    const newMessage = message.payload;
    if (!newMessage) return;

    // 1. If chat is open for this contact, append message
    if (activeConversationPubkey && 
        (newMessage.senderPubkey === activeConversationPubkey || newMessage.recipientPubkey === activeConversationPubkey)) {
      appendNewMessage(newMessage);
    }
    
    // 2. Refresh contact list snippet if visible (Home view)
    const homeView = document.getElementById('view-home');
    if (homeView && homeView.classList.contains('active')) {
       // Refresh list without full reload to update snippets/unread counts
       loadContacts(false); 
    }
  }
});

function appendNewMessage(msg) {
  const messageList = document.getElementById('message-list');
  if (!messageList) return;
  
  // Remove "empty" placeholder if present
  const empty = messageList.querySelector('.empty');
  if (empty) empty.remove();
  
  const isOutgoing = msg.direction === 'out'; 
  const timeStr = formatMessageTime(msg.createdAt);
  
  const div = document.createElement('div');
  div.className = `message-bubble ${isOutgoing ? 'message-out' : 'message-in'} message-new`;
  div.innerHTML = `
    <div class="message-content">${renderMinimalMarkdown(msg.content)}</div>
    <div class="message-time">${timeStr}</div>
  `;
  
  messageList.appendChild(div);
  
  // Scroll to bottom
  setTimeout(() => {
    messageList.scrollTop = messageList.scrollHeight;
  }, 50);
}

// Conversation Management
function openConversation(contactPubkey) {
  console.log('Opening conversation with', contactPubkey);
  const contact = currentContacts.find(c => c.pubkey === contactPubkey) || { pubkey: contactPubkey };
  
  // Header Update
  const nameEl = document.getElementById('conversation-name');
  const avatarEl = document.getElementById('conversation-avatar');
  
  if (nameEl) nameEl.textContent = contact.displayName || contact.name || formatShortHex(contactPubkey);
  if (avatarEl) {
    avatarEl.src = contact.picture || contact.avatarUrl || '';
    avatarEl.onerror = function() {
       this.src = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj48Y2lyY2xlIGN4PSI1MCIgY3k9IjUwIiByPSI1MCIgZmlsbD0iI2UzZTNiOCIvPjwvc3ZnPg==';
    };
  }
  
  activeConversationPubkey = contactPubkey;
  
  // Switch View
  switchView('conversation');
  
  // Load Messages
  loadConversationMessages(contactPubkey);
}

function closeConversation() {
  activeConversationPubkey = null;
  switchView('home');
}

async function loadConversationMessages(contactPubkey) {
  const messageList = document.getElementById('message-list');
  const relayStatus = document.getElementById('conversation-relays');
  if (!messageList) return;
  
  messageList.innerHTML = '<p class="empty">Nachrichten werden geladen...</p>';
  if (relayStatus) relayStatus.style.display = 'none';
  
  try {
    const dmRelayInput = document.getElementById('dm-relay-url');
    // Multirelay-Support: Split by comma
    const rawRelayUrl = dmRelayInput?.value || '';
    const relayUrls = rawRelayUrl.split(',').map(r => r.trim()).filter(Boolean);

    // We request DMs with this specific contact
    const response = await chrome.runtime.sendMessage({
      type: 'NOSTR_GET_DMS',
      payload: {
        scope: contactsRequestScope,
        relayUrl: relayUrls.length > 0 ? relayUrls : null, // Pass array or null
        contactPubkey: contactPubkey,
        limit: 50
      }
    });

    // Display used relays if available in response
    if (relayStatus && response?.result?.relays) {
       const usedRelays = Array.isArray(response.result.relays) ? response.result.relays : [response.result.relays];
       relayStatus.innerHTML = `Relays: ${usedRelays.map(r => `<span class="relay-tag">${new URL(r).hostname}</span>`).join('')}`;
       relayStatus.style.display = 'flex';
    }
    
    // Error Handling
    if (response?.error) {
       console.error('DM Fetch Error:', response.error);
       messageList.innerHTML = `<p class="empty error">Fehler: ${escapeHtml(response.error.message || response.error)}</p>`;
       return;
    }
    
    const messages = response?.result?.messages || [];
    renderMessages(messages, contactPubkey);
    
    // Scroll to bottom
    setTimeout(() => {
      messageList.scrollTop = messageList.scrollHeight;
    }, 50);

  } catch (error) {
    console.error('Message Load Failed:', error);
    messageList.innerHTML = `<p class="empty error">Fehler beim Laden: ${escapeHtml(error.message)}</p>`;
  }
}

function renderMessages(messages, contactPubkey) {
  const messageList = document.getElementById('message-list');
  if (!messageList) return;
  
  if (!messages || messages.length === 0) {
    messageList.innerHTML = '<p class="empty">Noch keine Nachrichten. Schreibe die erste!</p>';
    return;
  }
  
  // Sortier-Sicherheit (Chronologisch aufsteigend für Chat-View)
  messages.sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0));
  
  const html = messages.map(msg => {
    // Determine direction
    // If we sent it, direction is 'out'. If contact sent it, 'in'.
    const isOutgoing = msg.direction === 'out'; 
    const timeStr = formatMessageTime(msg.createdAt);
    
    return `
      <div class="message-bubble ${isOutgoing ? 'message-out' : 'message-in'}">
        <div class="message-content">${renderMinimalMarkdown(msg.content)}</div>
        <div class="message-time">${timeStr}</div>
      </div>
    `;
  }).join('');
  
  messageList.innerHTML = html;
}

async function sendMessage() {
  const input = document.getElementById('message-input');
  const sendButton = document.getElementById('send-message');
  
  if (!input || !activeConversationPubkey) return;
  
  const content = input.value.trim();
  if (!content) return;
  
  if (sendButton) sendButton.disabled = true;
  input.disabled = true;
  
  try {
    const dmRelayInput = document.getElementById('dm-relay-url');
    const relayUrl = dmRelayInput?.value || null;
    
    const response = await chrome.runtime.sendMessage({
      type: 'NOSTR_SEND_DM',
      payload: {
        recipientPubkey: activeConversationPubkey,
        content: content,
        scope: contactsRequestScope,
        relayUrl: relayUrl
      }
    });

    if (response?.error) {
       throw new Error(response.error);
    }
    
    // Success: Optimistic Append
    const messageList = document.getElementById('message-list');
    if (messageList) {
       const hasEmpty = messageList.querySelector('.empty');
       if (hasEmpty) hasEmpty.remove();
       
       const tempMsg = {
         direction: 'out',
         content: content,
         createdAt: Math.floor(Date.now() / 1000)
       };
       
       const div = document.createElement('div');
       div.className = 'message-bubble message-out';
       div.innerHTML = `
        <div class="message-content">${renderMinimalMarkdown(tempMsg.content)}</div>
        <div class="message-time">${formatMessageTime(tempMsg.createdAt)}</div>
       `;
       messageList.appendChild(div);
       messageList.scrollTop = messageList.scrollHeight;
    }
    
    input.value = '';

  } catch (error) {
    showStatus(`Senden fehlgeschlagen: ${error.message}`, true);
  } finally {
    if (sendButton) sendButton.disabled = false;
    input.disabled = false;
    input.focus();
  }
}
