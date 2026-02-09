const SETTING_KEY = 'preferWpNostrLock';
const DEFAULT_VALUE = true;
const VIEWER_CACHE_KEY = 'nostrViewerProfileCacheV1';

document.addEventListener('DOMContentLoaded', async () => {
  const checkbox = document.getElementById('prefer-lock');
  const status = document.getElementById('status');
  const refreshUserButton = document.getElementById('refresh-user');
  const profileCard = document.getElementById('profile-card');
  const profileHint = document.getElementById('profile-hint');
  const instanceCard = document.getElementById('instance-card');
  const publishProfileButton = document.getElementById('publish-profile');
  const unlockCacheState = document.getElementById('unlock-cache-state');
  const unlockCacheHint = document.getElementById('unlock-cache-hint');
  const exportKeyButton = document.getElementById('export-key');
  const backupOutputCopyButton = document.getElementById('backup-output-copy');
  const importKeyButton = document.getElementById('import-key');
  const createKeyButton = document.getElementById('create-key');
  const importNsecInput = document.getElementById('import-nsec');
  const backupOutput = document.getElementById('backup-output');
  const cloudBackupMeta = document.getElementById('cloud-backup-meta');
  const cloudBackupEnableButton = document.getElementById('backup-enable-cloud');
  const cloudBackupRestoreButton = document.getElementById('backup-restore-cloud');
  const cloudBackupDeleteButton = document.getElementById('backup-delete-cloud');
  let activeScope = 'global';
  let activeWpApi = null;
  let activeAuthBroker = null;
  let activeViewer = null;
  let activeRuntimeStatus = null;

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

  const initialViewer = await loadViewerContext(null, status);
  await persistViewerCache(initialViewer);
  activeViewer = initialViewer;
  activeScope = initialViewer?.scope || 'global';
  activeWpApi = sanitizeWpApi(initialViewer?.wpApi);
  activeAuthBroker = sanitizeAuthBroker(initialViewer?.authBroker);
  const initialSigner = await refreshSignerIdentity(null, activeScope, !initialViewer?.isLoggedIn);
  activeRuntimeStatus = initialSigner?.runtimeStatus || null;
  activeScope = initialSigner?.scope || activeScope;
  renderProfileCard(profileCard, profileHint, activeViewer, activeRuntimeStatus);
  renderInstanceCard(instanceCard, activeViewer);
  await ensureFixedUnlockPolicy(activeScope);
  await refreshUnlockState(unlockCacheState, unlockCacheHint, activeScope);
  await refreshCloudBackupState(cloudBackupMeta, {
    enableButton: cloudBackupEnableButton,
    restoreButton: cloudBackupRestoreButton,
    deleteButton: cloudBackupDeleteButton
  }, activeScope, activeWpApi);

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

  refreshUserButton.addEventListener('click', async () => {
    refreshUserButton.disabled = true;
    try {
      const viewer = await loadViewerContext(null, status);
      await persistViewerCache(viewer);
      activeViewer = viewer;
      activeScope = viewer?.scope || 'global';
      activeWpApi = sanitizeWpApi(viewer?.wpApi);
      activeAuthBroker = sanitizeAuthBroker(viewer?.authBroker);
      const signerContext = await refreshSignerIdentity(null, activeScope, !viewer?.isLoggedIn);
      activeRuntimeStatus = signerContext?.runtimeStatus || null;
      activeScope = signerContext?.scope || activeScope;
      renderProfileCard(profileCard, profileHint, activeViewer, activeRuntimeStatus);
      renderInstanceCard(instanceCard, activeViewer);
      await ensureFixedUnlockPolicy(activeScope);
      await refreshUnlockState(unlockCacheState, unlockCacheHint, activeScope);
      await refreshCloudBackupState(cloudBackupMeta, {
        enableButton: cloudBackupEnableButton,
        restoreButton: cloudBackupRestoreButton,
        deleteButton: cloudBackupDeleteButton
      }, activeScope, activeWpApi);
      if (viewer?.pending) {
        status.textContent = 'Profilkontext wird noch geladen. Bitte in 1-2 Sekunden erneut aktualisieren.';
      } else if (viewer?.isCached) {
        status.textContent = 'Profil aus Extension-Speicher geladen.';
      } else {
        status.textContent = viewer?.isLoggedIn
          ? 'Profilinformationen aktualisiert.'
          : 'Kein eingeloggter WordPress-Benutzer auf aktivem Tab.';
      }
    } catch (e) {
      status.textContent = `Profilinformationen konnten nicht geladen werden: ${e.message || e}`;
    } finally {
      refreshUserButton.disabled = false;
    }
  });

  publishProfileButton.addEventListener('click', async () => {
    if (!hasProfileContext(activeViewer)) {
      status.textContent = 'Kein Profilkontext verfügbar. Öffne eine WordPress-Seite und lade das Popup neu.';
      return;
    }

    const profilePayload = buildProfilePublishPayload(activeViewer);
    if (!profilePayload.relays.length) {
      status.textContent = 'Kein Profil-Relay konfiguriert. Bitte in WordPress "Profil-Relay (kind:0)" setzen.';
      return;
    }

    publishProfileButton.disabled = true;
    status.textContent = 'Sende Profil-Event (kind:0) an Relay...';
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
      status.textContent = relay
        ? `Profil veröffentlicht auf ${relay} (${formatShortHex(pubkey)}).`
        : `Profil veröffentlicht (${formatShortHex(pubkey)}).`;
    } catch (e) {
      status.textContent = `Profil-Publish fehlgeschlagen: ${e.message || e}`;
    } finally {
      publishProfileButton.disabled = false;
    }
  });

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

      backupOutput.value = nsec;
      status.textContent = 'Schlüssel exportiert. Du kannst ihn im Feld kopieren.';
    } catch (e) {
      status.textContent = `Export fehlgeschlagen: ${e.message || e}`;
    } finally {
      exportKeyButton.disabled = false;
    }
  });

  backupOutputCopyButton.addEventListener('click', async () => {
    const nsec = String(backupOutput.value || '').trim();
    if (!nsec) {
      status.textContent = 'Kein exportierter Schlüssel zum Kopieren vorhanden.';
      return;
    }
    try {
      await navigator.clipboard.writeText(nsec);
      status.textContent = 'Exportierter Schlüssel wurde kopiert.';
    } catch {
      status.textContent = 'Kopieren des exportierten Schlüssels fehlgeschlagen.';
    }
  });

  importKeyButton.addEventListener('click', async () => {
    const nsec = String(importNsecInput.value || '').trim();
    if (!nsec) {
      status.textContent = 'Bitte zuerst einen nsec eingeben.';
      return;
    }

    const confirmed = confirm('Das ersetzt den bestehenden Nostr-Schlüssel für dieses Profil. Fortfahren?');
    if (!confirmed) return;

    importKeyButton.disabled = true;
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'NOSTR_IMPORT_NSEC',
        payload: { scope: activeScope, nsec }
      });
      if (response?.error) throw new Error(response.error);
      const pubkey = String(response?.result?.pubkey || '');
      importNsecInput.value = '';
      backupOutput.value = '';
      const signerContext = await refreshSignerIdentity(null, activeScope, true);
      activeRuntimeStatus = signerContext?.runtimeStatus || null;
      activeScope = signerContext?.scope || activeScope;
      renderProfileCard(profileCard, profileHint, activeViewer, activeRuntimeStatus);
      await refreshUnlockState(unlockCacheState, unlockCacheHint, activeScope);
      status.textContent = pubkey
        ? `Schlüssel wiederhergestellt (${formatShortHex(pubkey)}). Seite neu laden und ggf. erneut verknüpfen.`
        : 'Schlüssel importiert. Seite neu laden.';
    } catch (e) {
      status.textContent = `Import fehlgeschlagen: ${e.message || e}`;
    } finally {
      importKeyButton.disabled = false;
    }
  });

  createKeyButton.addEventListener('click', async () => {
    const confirmed = confirm('Neue Schlüssel erstellen? Das ersetzt die aktuelle Nostr-Identität für dieses Profil.');
    if (!confirmed) return;

    createKeyButton.disabled = true;
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'NOSTR_CREATE_NEW_KEY',
        payload: { scope: activeScope }
      });
      if (response?.error) throw new Error(response.error);
      const pubkey = String(response?.result?.pubkey || '').trim();

      importNsecInput.value = '';
      backupOutput.value = '';

      const signerContext = await refreshSignerIdentity(null, activeScope, false);
      activeRuntimeStatus = signerContext?.runtimeStatus || null;
      activeScope = signerContext?.scope || activeScope;
      renderProfileCard(profileCard, profileHint, activeViewer, activeRuntimeStatus);
      await refreshUnlockState(unlockCacheState, unlockCacheHint, activeScope);
      await refreshCloudBackupState(cloudBackupMeta, {
        enableButton: cloudBackupEnableButton,
        restoreButton: cloudBackupRestoreButton,
        deleteButton: cloudBackupDeleteButton
      }, activeScope, activeWpApi);

      status.textContent = pubkey
        ? `Neue Schlüssel erstellt (${formatShortHex(pubkey)}).`
        : 'Neue Schlüssel erstellt.';
    } catch (e) {
      status.textContent = `Neue Schlüssel konnten nicht erstellt werden: ${e.message || e}`;
    } finally {
      createKeyButton.disabled = false;
    }
  });

  cloudBackupEnableButton.addEventListener('click', async () => {
    if (!activeWpApi) {
      status.textContent = 'Schlüsselkopie ist nur auf einem eingeloggten WordPress-Tab verfügbar.';
      return;
    }
    setCloudButtonsDisabled({
      enableButton: cloudBackupEnableButton,
      restoreButton: cloudBackupRestoreButton,
      deleteButton: cloudBackupDeleteButton
    }, true);
    status.textContent = 'Speichere Schlüsselkopie in WordPress...';
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'NOSTR_BACKUP_ENABLE',
        payload: { scope: activeScope, wpApi: activeWpApi, authBroker: activeAuthBroker }
      });
      if (response?.error) throw new Error(response.error);
      status.textContent = 'Schlüsselkopie in WordPress gespeichert.';
      await refreshCloudBackupState(cloudBackupMeta, {
        enableButton: cloudBackupEnableButton,
        restoreButton: cloudBackupRestoreButton,
        deleteButton: cloudBackupDeleteButton
      }, activeScope, activeWpApi);
    } catch (e) {
      status.textContent = `Speichern der Schlüsselkopie fehlgeschlagen: ${e.message || e}`;
      await refreshCloudBackupState(cloudBackupMeta, {
        enableButton: cloudBackupEnableButton,
        restoreButton: cloudBackupRestoreButton,
        deleteButton: cloudBackupDeleteButton
      }, activeScope, activeWpApi);
    }
  });

  cloudBackupRestoreButton.addEventListener('click', async () => {
    if (!activeWpApi) {
      status.textContent = 'Wiederherstellen ist nur auf einem eingeloggten WordPress-Tab verfügbar.';
      return;
    }
    const confirmed = confirm('Wiederherstellen aus WordPress ersetzt den lokalen Nostr-Schlüssel. Fortfahren?');
    if (!confirmed) return;

    setCloudButtonsDisabled({
      enableButton: cloudBackupEnableButton,
      restoreButton: cloudBackupRestoreButton,
      deleteButton: cloudBackupDeleteButton
    }, true);
    status.textContent = 'Stelle aus WordPress-Schlüsselkopie wieder her...';
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'NOSTR_BACKUP_RESTORE',
        payload: { scope: activeScope, wpApi: activeWpApi, authBroker: activeAuthBroker }
      });
      if (response?.error) throw new Error(response.error);
      const pubkey = String(response?.result?.pubkey || '');
      status.textContent = pubkey
        ? `Wiederherstellung erfolgreich (${formatShortHex(pubkey)}). Seite neu laden.`
        : 'Wiederherstellung erfolgreich. Seite neu laden.';
      const signerContext = await refreshSignerIdentity(null, activeScope, true);
      activeRuntimeStatus = signerContext?.runtimeStatus || null;
      activeScope = signerContext?.scope || activeScope;
      renderProfileCard(profileCard, profileHint, activeViewer, activeRuntimeStatus);
      await refreshUnlockState(unlockCacheState, unlockCacheHint, activeScope);
      await refreshCloudBackupState(cloudBackupMeta, {
        enableButton: cloudBackupEnableButton,
        restoreButton: cloudBackupRestoreButton,
        deleteButton: cloudBackupDeleteButton
      }, activeScope, activeWpApi);
    } catch (e) {
      status.textContent = `Wiederherstellung fehlgeschlagen: ${e.message || e}`;
      await refreshCloudBackupState(cloudBackupMeta, {
        enableButton: cloudBackupEnableButton,
        restoreButton: cloudBackupRestoreButton,
        deleteButton: cloudBackupDeleteButton
      }, activeScope, activeWpApi);
    }
  });

  cloudBackupDeleteButton.addEventListener('click', async () => {
    if (!activeWpApi) {
      status.textContent = 'Löschen der Schlüsselkopie ist nur auf einem eingeloggten WordPress-Tab verfügbar.';
      return;
    }
    const confirmed = confirm('Schlüsselkopie in WordPress wirklich löschen?');
    if (!confirmed) return;

    setCloudButtonsDisabled({
      enableButton: cloudBackupEnableButton,
      restoreButton: cloudBackupRestoreButton,
      deleteButton: cloudBackupDeleteButton
    }, true);
    status.textContent = 'Lösche Schlüsselkopie in WordPress...';
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'NOSTR_BACKUP_DELETE',
        payload: { scope: activeScope, wpApi: activeWpApi, authBroker: activeAuthBroker }
      });
      if (response?.error) throw new Error(response.error);
      status.textContent = 'Schlüsselkopie in WordPress gelöscht.';
      await refreshCloudBackupState(cloudBackupMeta, {
        enableButton: cloudBackupEnableButton,
        restoreButton: cloudBackupRestoreButton,
        deleteButton: cloudBackupDeleteButton
      }, activeScope, activeWpApi);
    } catch (e) {
      status.textContent = `Schlüsselkopie konnte nicht gelöscht werden: ${e.message || e}`;
      await refreshCloudBackupState(cloudBackupMeta, {
        enableButton: cloudBackupEnableButton,
        restoreButton: cloudBackupRestoreButton,
        deleteButton: cloudBackupDeleteButton
      }, activeScope, activeWpApi);
    }
  });

  document.addEventListener('click', async (event) => {
    const copyButton = event.target?.closest?.('[data-copy-value]');
    if (!copyButton) return;

    const value = String(copyButton.getAttribute('data-copy-value') || '').trim();
    if (!value) {
      status.textContent = 'Kein Wert zum Kopieren vorhanden.';
      return;
    }

    try {
      await navigator.clipboard.writeText(value);
      status.textContent = 'In die Zwischenablage kopiert.';
    } catch {
      status.textContent = 'Kopieren fehlgeschlagen.';
    }
  });

});

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

  const origin = String(viewer?.origin || '').trim();
  const validOrigin = /^https?:\/\//i.test(origin) ? origin : null;
  const userId = Number(viewer?.userId) || null;
  const fallbackScope = validOrigin && userId ? buildWpScope(validOrigin, userId) : 'global';
  const scope = normalizeScope(viewer?.scope || fallbackScope);

  const cacheEntry = {
    userId,
    displayName: String(viewer?.displayName || '').trim() || null,
    avatarUrl: String(viewer?.avatarUrl || '').trim() || null,
    pubkey: String(viewer?.pubkey || '').trim() || null,
    userLogin: String(viewer?.userLogin || '').trim() || null,
    profileRelayUrl: String(viewer?.profileRelayUrl || '').trim() || null,
    profileNip05: String(viewer?.profileNip05 || '').trim() || null,
    primaryDomain: String(viewer?.primaryDomain || '').trim() || null,
    origin: validOrigin,
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

    renderSignerCard(cardNode, runtimeStatus);
    return { scope: activeScope, runtimeStatus };
  } catch (error) {
    if (cardNode) {
      cardNode.innerHTML = `<p class="empty">Signer-Status konnte nicht geladen werden: ${escapeHtml(error.message || String(error))}</p>`;
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

function renderSignerCard(cardNode, runtimeStatus) {
  if (!cardNode) return;

  if (!runtimeStatus || !runtimeStatus.hasKey) {
    cardNode.innerHTML = `
      <p class="empty">Kein lokaler Nostr-Schlüssel eingerichtet.</p>
      <p class="hint">Importiere einen nsec oder richte zuerst einen Schlüssel ein.</p>
    `;
    return;
  }

  const locked = Boolean(runtimeStatus.locked);
  const npub = String(runtimeStatus.npub || '').trim();
  const pubkeyHex = String(runtimeStatus.pubkeyHex || '').trim();
  const mode = formatProtectionMode(runtimeStatus.protectionMode);
  const lockState = locked ? 'nicht aktiv' : 'aktiv';
  const profileUrl = npub ? `https://njump.me/${encodeURIComponent(npub)}` : '';

  cardNode.innerHTML = `
    <div class="wp-user-meta"><strong>Schutzart:</strong> ${escapeHtml(mode)}</div>
    <div class="wp-user-meta"><strong>Login für sensible Aktionen:</strong> ${escapeHtml(lockState)}</div>
    <div class="wp-user-meta"><strong>Pubkey (hex):</strong> ${escapeHtml(pubkeyHex || 'noch nicht verfügbar')}</div>
    <div class="wp-user-meta"><strong>Npub:</strong> ${escapeHtml(npub || 'noch nicht verfügbar')}</div>
    <div class="signer-badges">
      <span class="badge">Public Key ist immer sichtbar</span>
      <span class="badge warn">Login nur für Signieren und Schlüsseländerungen</span>
    </div>
    ${profileUrl ? `<div class="wp-user-meta"><a href="${profileUrl}" target="_blank" rel="noopener noreferrer">Profil öffnen (njump)</a></div>` : ''}
  `;
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

async function ensureFixedUnlockPolicy(scope) {
  try {
    await chrome.runtime.sendMessage({
      type: 'NOSTR_SET_UNLOCK_CACHE_POLICY',
      payload: { policy: '15m', scope }
    });
  } catch {
    // Nicht blockierend: UI soll auch ohne Policy-Write nutzbar bleiben.
  }
}

async function refreshUnlockState(unlockCacheState, unlockCacheHint, scope) {
  try {
    const response = await chrome.runtime.sendMessage({
      type: 'NOSTR_GET_STATUS',
      payload: { scope }
    });
    const runtimeStatus = response?.result;
    if (response?.error) throw new Error(response.error);

    setUnlockStateBadge(unlockCacheState, runtimeStatus);
    unlockCacheHint.textContent = formatUnlockCacheHint(runtimeStatus);
  } catch {
    setUnlockStateBadge(unlockCacheState, null);
    unlockCacheHint.textContent = 'ReLogin-Status konnte nicht geladen werden.';
  }
}

async function loadViewerContext(cardNode, statusNode) {
  const cachedViewer = await loadViewerCache();
  const tabContext = await getActiveTabContext();
  const origin = tabContext?.origin || null;
  if (!origin) {
    renderViewerCard(cardNode, null, null);
    if (cachedViewer) {
      return {
        ...cachedViewer,
        isLoggedIn: false,
        isCached: true,
        source: 'cache',
        activeSiteOrigin: null,
        wpApi: null,
        authBroker: null
      };
    }
    return { isLoggedIn: false, scope: 'global', origin: null, activeSiteOrigin: null, wpApi: null, authBroker: null };
  }

  const viewerFromTab = await getViewerFromActiveTab(tabContext?.id);
  if (viewerFromTab?.pending) {
    renderViewerCard(cardNode, { pending: true }, origin);
    if (cachedViewer) {
      return {
        ...cachedViewer,
        isLoggedIn: false,
        pending: true,
        isCached: true,
        source: 'cache',
        activeSiteOrigin: origin,
        wpApi: sanitizeWpApi(viewerFromTab.wpApi),
        authBroker: sanitizeAuthBroker(viewerFromTab.authBroker)
      };
    }
    return {
      isLoggedIn: false,
      pending: true,
      scope: 'global',
      origin,
      activeSiteOrigin: origin,
      wpApi: sanitizeWpApi(viewerFromTab.wpApi),
      authBroker: sanitizeAuthBroker(viewerFromTab.authBroker)
    };
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
    await persistViewerCache(context);
    return context;
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
    await persistViewerCache(context);
    return context;
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
        return {
          ...cachedViewer,
          isLoggedIn: false,
          isCached: true,
          source: 'cache',
          activeSiteOrigin: origin,
          wpApi: null,
          authBroker: null
        };
      }
      return { isLoggedIn: false, scope: 'global', origin: null, activeSiteOrigin: origin, wpApi: null, authBroker: null };
    }

    renderViewerCard(cardNode, null, origin, error);
    if (statusNode) {
      statusNode.textContent = `WP-Viewer konnte nicht geladen werden: ${error.message || error}`;
    }
    if (cachedViewer) {
      return {
        ...cachedViewer,
        isLoggedIn: false,
        isCached: true,
        source: 'cache',
        activeSiteOrigin: origin,
        wpApi: null,
        authBroker: null
      };
    }
    return { isLoggedIn: false, scope: 'global', origin: null, activeSiteOrigin: origin, wpApi: null, authBroker: null };
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
