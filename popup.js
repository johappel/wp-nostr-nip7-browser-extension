const SETTING_KEY = 'preferWpNostrLock';
const DEFAULT_VALUE = true;

document.addEventListener('DOMContentLoaded', async () => {
  const checkbox = document.getElementById('prefer-lock');
  const status = document.getElementById('status');
  const refreshUserButton = document.getElementById('refresh-user');
  const wpUserCard = document.getElementById('wp-user-card');
  const signerCard = document.getElementById('signer-card');
  const unlockCacheSelect = document.getElementById('unlock-cache-policy');
  const unlockCacheHint = document.getElementById('unlock-cache-hint');
  const exportKeyButton = document.getElementById('export-key');
  const importKeyButton = document.getElementById('import-key');
  const importNsecInput = document.getElementById('import-nsec');
  const backupOutput = document.getElementById('backup-output');
  const cloudBackupMeta = document.getElementById('cloud-backup-meta');
  const cloudBackupEnableButton = document.getElementById('backup-enable-cloud');
  const cloudBackupRestoreButton = document.getElementById('backup-restore-cloud');
  const cloudBackupDeleteButton = document.getElementById('backup-delete-cloud');
  const syncNowButton = document.getElementById('sync-now');
  const syncList = document.getElementById('sync-list');
  const syncMeta = document.getElementById('sync-meta');
  const manualPrimaryDomain = document.getElementById('manual-primary-domain');
  const manualDomainSecret = document.getElementById('manual-domain-secret');
  const manualAddButton = document.getElementById('manual-add');
  let activeScope = 'global';
  let activeWpApi = null;
  let activeAuthBroker = null;

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

  const initialViewer = await loadViewerContext(wpUserCard, status);
  activeScope = initialViewer?.scope || 'global';
  activeWpApi = sanitizeWpApi(initialViewer?.wpApi);
  activeAuthBroker = sanitizeAuthBroker(initialViewer?.authBroker);
  const initialSigner = await refreshSignerIdentity(signerCard, activeScope, !initialViewer?.isLoggedIn);
  activeScope = initialSigner?.scope || activeScope;
  await refreshUnlockState(unlockCacheSelect, unlockCacheHint, activeScope);
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
      const viewer = await loadViewerContext(wpUserCard, status);
      activeScope = viewer?.scope || 'global';
      activeWpApi = sanitizeWpApi(viewer?.wpApi);
      activeAuthBroker = sanitizeAuthBroker(viewer?.authBroker);
      const signerContext = await refreshSignerIdentity(signerCard, activeScope, !viewer?.isLoggedIn);
      activeScope = signerContext?.scope || activeScope;
      await refreshUnlockState(unlockCacheSelect, unlockCacheHint, activeScope);
      await refreshCloudBackupState(cloudBackupMeta, {
        enableButton: cloudBackupEnableButton,
        restoreButton: cloudBackupRestoreButton,
        deleteButton: cloudBackupDeleteButton
      }, activeScope, activeWpApi);
      if (viewer?.pending) {
        status.textContent = 'WP-User-Kontext wird noch geladen. Bitte in 1-2 Sekunden erneut aktualisieren.';
      } else {
        status.textContent = viewer?.isLoggedIn
          ? 'WordPress-User aktualisiert.'
          : 'Kein eingeloggter WordPress-User auf aktivem Tab.';
      }
    } catch (e) {
      status.textContent = `WP-User konnte nicht geladen werden: ${e.message || e}`;
    } finally {
      refreshUserButton.disabled = false;
    }
  });

  unlockCacheSelect.addEventListener('change', async () => {
    const selectedPolicy = normalizeUnlockPolicy(unlockCacheSelect.value);
    unlockCacheSelect.disabled = true;
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'NOSTR_SET_UNLOCK_CACHE_POLICY',
        payload: { policy: selectedPolicy, scope: activeScope }
      });
      if (response?.error) throw new Error(response.error);

      unlockCacheSelect.value = normalizeUnlockPolicy(response?.result?.policy);
      const statusResponseScoped = await chrome.runtime.sendMessage({
        type: 'NOSTR_GET_STATUS',
        payload: { scope: activeScope }
      });
      unlockCacheHint.textContent = formatUnlockCacheHint(statusResponseScoped?.result);
      status.textContent = 'Unlock-Cache aktualisiert.';
    } catch (e) {
      status.textContent = `Unlock-Cache konnte nicht gespeichert werden: ${e.message || e}`;
    } finally {
      unlockCacheSelect.disabled = false;
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
      try {
        await navigator.clipboard.writeText(nsec);
        status.textContent = 'Schluessel exportiert und in die Zwischenablage kopiert.';
      } catch {
        status.textContent = 'Schluessel exportiert. Bitte sicher speichern.';
      }
    } catch (e) {
      status.textContent = `Export fehlgeschlagen: ${e.message || e}`;
    } finally {
      exportKeyButton.disabled = false;
    }
  });

  importKeyButton.addEventListener('click', async () => {
    const nsec = String(importNsecInput.value || '').trim();
    if (!nsec) {
      status.textContent = 'Bitte zuerst einen nsec eingeben.';
      return;
    }

    const confirmed = confirm('Import ueberschreibt den bestehenden Schluessel im aktiven WP-User-Scope. Fortfahren?');
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
      const signerContext = await refreshSignerIdentity(signerCard, activeScope, true);
      activeScope = signerContext?.scope || activeScope;
      await refreshUnlockState(unlockCacheSelect, unlockCacheHint, activeScope);
      status.textContent = pubkey
        ? `Schluessel importiert (${formatShortHex(pubkey)}). Seite neu laden und ggf. erneut verknuepfen.`
        : 'Schluessel importiert. Seite neu laden.';
    } catch (e) {
      status.textContent = `Import fehlgeschlagen: ${e.message || e}`;
    } finally {
      importKeyButton.disabled = false;
    }
  });

  cloudBackupEnableButton.addEventListener('click', async () => {
    if (!activeWpApi) {
      status.textContent = 'Cloud-Backup ist nur auf einem eingeloggten WordPress-Tab verfuegbar.';
      return;
    }
    setCloudButtonsDisabled({
      enableButton: cloudBackupEnableButton,
      restoreButton: cloudBackupRestoreButton,
      deleteButton: cloudBackupDeleteButton
    }, true);
    status.textContent = 'Speichere Cloud-Backup...';
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'NOSTR_BACKUP_ENABLE',
        payload: { scope: activeScope, wpApi: activeWpApi, authBroker: activeAuthBroker }
      });
      if (response?.error) throw new Error(response.error);
      status.textContent = 'Cloud-Backup gespeichert.';
      await refreshCloudBackupState(cloudBackupMeta, {
        enableButton: cloudBackupEnableButton,
        restoreButton: cloudBackupRestoreButton,
        deleteButton: cloudBackupDeleteButton
      }, activeScope, activeWpApi);
    } catch (e) {
      status.textContent = `Cloud-Backup fehlgeschlagen: ${e.message || e}`;
      await refreshCloudBackupState(cloudBackupMeta, {
        enableButton: cloudBackupEnableButton,
        restoreButton: cloudBackupRestoreButton,
        deleteButton: cloudBackupDeleteButton
      }, activeScope, activeWpApi);
    }
  });

  cloudBackupRestoreButton.addEventListener('click', async () => {
    if (!activeWpApi) {
      status.textContent = 'Restore ist nur auf einem eingeloggten WordPress-Tab verfuegbar.';
      return;
    }
    const confirmed = confirm('Cloud-Restore ersetzt den lokalen Schluessel im aktiven Scope. Fortfahren?');
    if (!confirmed) return;

    setCloudButtonsDisabled({
      enableButton: cloudBackupEnableButton,
      restoreButton: cloudBackupRestoreButton,
      deleteButton: cloudBackupDeleteButton
    }, true);
    status.textContent = 'Stelle aus Cloud-Backup wieder her...';
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'NOSTR_BACKUP_RESTORE',
        payload: { scope: activeScope, wpApi: activeWpApi, authBroker: activeAuthBroker }
      });
      if (response?.error) throw new Error(response.error);
      const pubkey = String(response?.result?.pubkey || '');
      status.textContent = pubkey
        ? `Cloud-Restore erfolgreich (${formatShortHex(pubkey)}). Seite neu laden.`
        : 'Cloud-Restore erfolgreich. Seite neu laden.';
      const signerContext = await refreshSignerIdentity(signerCard, activeScope, true);
      activeScope = signerContext?.scope || activeScope;
      await refreshUnlockState(unlockCacheSelect, unlockCacheHint, activeScope);
      await refreshCloudBackupState(cloudBackupMeta, {
        enableButton: cloudBackupEnableButton,
        restoreButton: cloudBackupRestoreButton,
        deleteButton: cloudBackupDeleteButton
      }, activeScope, activeWpApi);
    } catch (e) {
      status.textContent = `Cloud-Restore fehlgeschlagen: ${e.message || e}`;
      await refreshCloudBackupState(cloudBackupMeta, {
        enableButton: cloudBackupEnableButton,
        restoreButton: cloudBackupRestoreButton,
        deleteButton: cloudBackupDeleteButton
      }, activeScope, activeWpApi);
    }
  });

  cloudBackupDeleteButton.addEventListener('click', async () => {
    if (!activeWpApi) {
      status.textContent = 'Cloud-Backup-Loeschen ist nur auf einem eingeloggten WordPress-Tab verfuegbar.';
      return;
    }
    const confirmed = confirm('Cloud-Backup fuer diesen WP-User wirklich loeschen?');
    if (!confirmed) return;

    setCloudButtonsDisabled({
      enableButton: cloudBackupEnableButton,
      restoreButton: cloudBackupRestoreButton,
      deleteButton: cloudBackupDeleteButton
    }, true);
    status.textContent = 'Loesche Cloud-Backup...';
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'NOSTR_BACKUP_DELETE',
        payload: { scope: activeScope, wpApi: activeWpApi, authBroker: activeAuthBroker }
      });
      if (response?.error) throw new Error(response.error);
      status.textContent = 'Cloud-Backup geloescht.';
      await refreshCloudBackupState(cloudBackupMeta, {
        enableButton: cloudBackupEnableButton,
        restoreButton: cloudBackupRestoreButton,
        deleteButton: cloudBackupDeleteButton
      }, activeScope, activeWpApi);
    } catch (e) {
      status.textContent = `Cloud-Backup konnte nicht geloescht werden: ${e.message || e}`;
      await refreshCloudBackupState(cloudBackupMeta, {
        enableButton: cloudBackupEnableButton,
        restoreButton: cloudBackupRestoreButton,
        deleteButton: cloudBackupDeleteButton
      }, activeScope, activeWpApi);
    }
  });

  syncNowButton.addEventListener('click', async () => {
    syncNowButton.disabled = true;
    status.textContent = 'Synchronisiere Domains...';
    try {
      const response = await chrome.runtime.sendMessage({ type: 'NOSTR_SYNC_DOMAINS_NOW' });
      if (response?.error) throw new Error(response.error);
      const state = response?.result;
      renderSyncState(state, syncList, syncMeta, status);
      const configCount = Array.isArray(state?.configs) ? state.configs.length : 0;
      status.textContent = configCount > 0
        ? 'Domain-Sync abgeschlossen.'
        : 'Keine Domain-Configs vorhanden.';
    } catch (e) {
      status.textContent = `Domain-Sync fehlgeschlagen: ${e.message || e}`;
    } finally {
      syncNowButton.disabled = false;
    }
  });

  manualAddButton.addEventListener('click', async () => {
    const primaryDomain = manualPrimaryDomain.value.trim();
    const domainSecret = manualDomainSecret.value.trim();
    if (!primaryDomain || !domainSecret) {
      status.textContent = 'Primary Domain und Secret sind erforderlich.';
      return;
    }

    manualAddButton.disabled = true;
    status.textContent = 'Speichere Domain-Config...';
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'NOSTR_UPSERT_DOMAIN_SYNC_CONFIG',
        payload: { primaryDomain, domainSecret }
      });
      if (response?.error) throw new Error(response.error);
      renderSyncState(response?.result, syncList, syncMeta, status);
      status.textContent = 'Domain-Config gespeichert und synchronisiert.';
      manualDomainSecret.value = '';
    } catch (e) {
      status.textContent = `Speichern fehlgeschlagen: ${e.message || e}`;
    } finally {
      manualAddButton.disabled = false;
    }
  });

  await refreshSyncState(syncList, syncMeta, status);
});

async function refreshSyncState(syncList, syncMeta, status) {
  try {
    const response = await chrome.runtime.sendMessage({ type: 'NOSTR_GET_DOMAIN_SYNC_STATE' });
    if (response?.error) throw new Error(response.error);
    renderSyncState(response?.result, syncList, syncMeta, status);
  } catch (e) {
    syncMeta.textContent = 'Domain-Sync-Status konnte nicht geladen werden.';
    status.textContent = `Fehler: ${e.message || e}`;
  }
}

function renderSyncState(state, container, metaNode, statusNode) {
  const configs = Array.isArray(state?.configs) ? state.configs : [];
  const allowedDomains = Array.isArray(state?.allowedDomains) ? state.allowedDomains : [];
  const lastUpdate = state?.lastDomainUpdate ? formatDateTime(state.lastDomainUpdate) : 'nie';

  metaNode.textContent = `Configs: ${configs.length} | Allowed: ${allowedDomains.length} | Letztes Update: ${lastUpdate}`;

  if (!configs.length) {
    container.innerHTML = '<p class="empty">Keine Primary-Domains konfiguriert.</p>';
    return;
  }

  container.innerHTML = '';

  for (const config of configs) {
    const row = document.createElement('div');
    row.className = 'sync-item';

    const lastSync = config.lastSyncAt ? formatDateTime(config.lastSyncAt) : 'nie';
    const statusText = config.lastSyncError
      ? `Fehler: ${config.lastSyncError}`
      : `Letzter Sync: ${lastSync}`;

    row.innerHTML = `
      <div class="sync-main">
        <div class="sync-host">${escapeHtml(config.host)}</div>
        <div class="sync-origin">${escapeHtml(config.primaryDomain || '')}</div>
        <div class="sync-status">${escapeHtml(statusText)}</div>
      </div>
      <button class="btn-danger" type="button" data-host="${escapeHtml(config.host)}">Entfernen</button>
    `;

    const removeButton = row.querySelector('.btn-danger');
    removeButton.addEventListener('click', async () => {
      removeButton.disabled = true;
      try {
        const response = await chrome.runtime.sendMessage({
          type: 'NOSTR_REMOVE_DOMAIN_SYNC_CONFIG',
          payload: { host: config.host }
        });
        if (response?.error) throw new Error(response.error);
        renderSyncState(response?.result, container, metaNode, statusNode);
        if (statusNode) statusNode.textContent = `Config ${config.host} entfernt.`;
      } catch (e) {
        removeButton.disabled = false;
        if (statusNode) statusNode.textContent = `Entfernen fehlgeschlagen: ${e.message || e}`;
      }
    });

    container.appendChild(row);
  }
}

function formatDateTime(timestampMs) {
  try {
    return new Date(timestampMs).toLocaleString();
  } catch {
    return 'unbekannt';
  }
}

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

function setCloudButtonsDisabled(buttons, disabled) {
  if (!buttons) return;
  if (buttons.enableButton) buttons.enableButton.disabled = disabled;
  if (buttons.restoreButton) buttons.restoreButton.disabled = disabled;
  if (buttons.deleteButton) buttons.deleteButton.disabled = disabled;
}

async function refreshCloudBackupState(metaNode, buttons, scope, wpApi) {
  if (!metaNode) return;
  if (!wpApi) {
    metaNode.textContent = 'Cloud-Backup nur auf aktivem, eingeloggtem WordPress-Tab verfuegbar.';
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
      metaNode.textContent = 'Kein Cloud-Backup vorhanden.';
      if (buttons?.enableButton) buttons.enableButton.disabled = false;
      if (buttons?.restoreButton) buttons.restoreButton.disabled = true;
      if (buttons?.deleteButton) buttons.deleteButton.disabled = true;
      return;
    }

    const updatedText = typeof data.updatedAt === 'number'
      ? new Date(data.updatedAt * 1000).toLocaleString()
      : 'unbekannt';
    metaNode.textContent = `Backup vorhanden fuer ${formatShortHex(data.pubkey || '')}. Letztes Update: ${updatedText}.`;
    if (buttons?.enableButton) buttons.enableButton.disabled = false;
    if (buttons?.restoreButton) buttons.restoreButton.disabled = false;
    if (buttons?.deleteButton) buttons.deleteButton.disabled = false;
  } catch (error) {
    metaNode.textContent = `Cloud-Status konnte nicht geladen werden: ${error.message || error}`;
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

    renderSignerCard(cardNode, runtimeStatus, activeScope);
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

function renderSignerCard(cardNode, runtimeStatus, scope) {
  if (!cardNode) return;

  const normalizedScope = normalizeScope(scope);
  if (!runtimeStatus || !runtimeStatus.hasKey) {
    cardNode.innerHTML = `
      <p class="empty">Kein Schluessel im Scope <strong>${escapeHtml(formatScopeLabel(normalizedScope))}</strong> gefunden.</p>
      <p class="hint">Scope: <code>${escapeHtml(normalizedScope)}</code></p>
    `;
    return;
  }

  const locked = Boolean(runtimeStatus.locked);
  const npub = String(runtimeStatus.npub || '').trim();
  const pubkeyHex = String(runtimeStatus.pubkeyHex || '').trim();
  const mode = formatProtectionMode(runtimeStatus.protectionMode);
  const lockState = locked ? 'gesperrt' : 'entsperrt';
  const profileUrl = npub ? `https://njump.me/${encodeURIComponent(npub)}` : '';

  cardNode.innerHTML = `
    <div class="wp-user-meta"><strong>Scope:</strong> ${escapeHtml(formatScopeLabel(normalizedScope))}</div>
    <div class="wp-user-meta"><strong>Technisch:</strong> <code>${escapeHtml(normalizedScope)}</code></div>
    <div class="wp-user-meta"><strong>Schutz:</strong> ${escapeHtml(mode)}</div>
    <div class="wp-user-meta"><strong>Status:</strong> ${escapeHtml(lockState)}</div>
    <div class="wp-user-meta"><strong>Pubkey (hex):</strong> ${escapeHtml(pubkeyHex || 'gesperrt (zum Anzeigen erst entsperren)')}</div>
    <div class="wp-user-meta"><strong>Npub:</strong> ${escapeHtml(npub || 'gesperrt')}</div>
    ${profileUrl ? `<div class="wp-user-meta"><a href="${profileUrl}" target="_blank" rel="noopener noreferrer">Profil oeffnen (njump)</a></div>` : ''}
  `;
}

function normalizeScope(scope) {
  const value = String(scope || '').trim();
  if (!value) return 'global';
  if (!/^[a-zA-Z0-9:._-]{1,120}$/.test(value)) return 'global';
  return value;
}

function formatScopeLabel(scope) {
  const value = normalizeScope(scope);
  if (value === 'global') return 'Global';

  const wpMatch = value.match(/^wp:([^:]+):u:(\d+)$/);
  if (wpMatch) {
    return `WP ${wpMatch[1]} / User ${wpMatch[2]}`;
  }
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

async function refreshUnlockState(unlockCacheSelect, unlockCacheHint, scope) {
  try {
    const response = await chrome.runtime.sendMessage({
      type: 'NOSTR_GET_STATUS',
      payload: { scope }
    });
    const runtimeStatus = response?.result;
    if (response?.error) throw new Error(response.error);

    const policy = normalizeUnlockPolicy(runtimeStatus?.unlockCachePolicy);
    unlockCacheSelect.value = policy;
    unlockCacheHint.textContent = formatUnlockCacheHint(runtimeStatus);
  } catch {
    unlockCacheSelect.value = '15m';
    unlockCacheHint.textContent = 'Unlock-Status konnte nicht geladen werden.';
  }
}

async function loadViewerContext(cardNode, statusNode) {
  const tabContext = await getActiveTabContext();
  const origin = tabContext?.origin || null;
  if (!origin) {
    renderViewerCard(cardNode, null, null);
    return { isLoggedIn: false, scope: 'global', origin: null, wpApi: null, authBroker: null };
  }

  const viewerFromTab = await getViewerFromActiveTab(tabContext?.id);
  if (viewerFromTab?.pending) {
    renderViewerCard(cardNode, { pending: true }, origin);
    return {
      isLoggedIn: false,
      pending: true,
      scope: 'global',
      origin,
      wpApi: sanitizeWpApi(viewerFromTab.wpApi),
      authBroker: sanitizeAuthBroker(viewerFromTab.authBroker)
    };
  }
  if (viewerFromTab?.viewer) {
    const viewer = viewerFromTab.viewer;
    if (viewerFromTab.source) viewer.source = viewerFromTab.source;
    const scope = viewer?.isLoggedIn && viewer?.userId
      ? buildWpScope(origin, viewer.userId)
      : 'global';
    renderViewerCard(cardNode, viewer, origin);
    return {
      ...viewer,
      scope,
      origin,
      wpApi: sanitizeWpApi(viewerFromTab.wpApi),
      authBroker: sanitizeAuthBroker(viewerFromTab.authBroker || viewer.authBroker)
    };
  }

  try {
    const viewer = await fetchWpViewer(origin);
    viewer.source = 'rest';
    const scope = viewer?.isLoggedIn && viewer?.userId
      ? buildWpScope(origin, viewer.userId)
      : 'global';
    renderViewerCard(cardNode, viewer, origin);
    return {
      ...viewer,
      scope,
      origin,
      wpApi: null,
      authBroker: sanitizeAuthBroker(viewer.authBroker)
    };
  } catch (error) {
    const errorText = String(error?.message || error || '');
    const likelyNoWpEndpoint =
      errorText.includes('HTTP 404') ||
      errorText.includes('HTTP 403') ||
      errorText.includes('Failed to fetch') ||
      errorText.includes('NetworkError');

    if (likelyNoWpEndpoint) {
      renderViewerCard(cardNode, null, origin);
      return { isLoggedIn: false, scope: 'global', origin, wpApi: null, authBroker: null };
    }

    renderViewerCard(cardNode, null, origin, error);
    if (statusNode) {
      statusNode.textContent = `WP-Viewer konnte nicht geladen werden: ${error.message || error}`;
    }
    return { isLoggedIn: false, scope: 'global', origin, wpApi: null, authBroker: null };
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
      ? `Tab-Kontext nicht verfuegbar. REST meldet auf ${escapeHtml(origin || '-')} aktuell keinen WP-Login.`
      : (origin
          ? `Auf ${escapeHtml(origin)} ist aktuell kein WordPress-User eingeloggt.`
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
    <div class="wp-user-meta"><strong>Avatar URL:</strong> ${escapeHtml(avatarUrl || '-')}</div>
    <div class="wp-user-meta"><strong>Pubkey:</strong> ${escapeHtml(pubkey || 'noch nicht registriert')}</div>
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

function normalizeUnlockPolicy(value) {
  const normalized = String(value || '').trim().toLowerCase();
  const allowed = new Set(['off', '5m', '15m', '30m', '60m', 'session']);
  if (allowed.has(normalized)) return normalized;
  return '15m';
}

function formatUnlockCacheHint(runtimeStatus) {
  const policy = normalizeUnlockPolicy(runtimeStatus?.unlockCachePolicy);
  const hasKey = Boolean(runtimeStatus?.hasKey);
  const locked = Boolean(runtimeStatus?.locked);
  const expiresAt = runtimeStatus?.cacheExpiresAt;

  if (!hasKey) {
    return `Aktuelle Einstellung: ${formatUnlockPolicyLabel(policy)}. Ein Schluessel ist noch nicht eingerichtet.`;
  }

  if (policy === 'off') {
    return 'Unlock-Cache ist aus. Bei jeder Operation wird erneut nach dem Passwort gefragt.';
  }

  if (policy === 'session') {
    return locked
      ? 'Cache bis Browser-Ende aktiv, aktuell gesperrt.'
      : 'Entsperrt bis zum Ende der Browser-Session (oder bis Lock).';
  }

  const expiryText = (typeof expiresAt === 'number')
    ? new Date(expiresAt).toLocaleTimeString()
    : null;

  if (locked) {
    return `Aktuelle Einstellung: ${formatUnlockPolicyLabel(policy)}. Aktuell gesperrt.`;
  }

  if (expiryText) {
    return `Entsperrt bis ca. ${expiryText} (${formatUnlockPolicyLabel(policy)}).`;
  }

  return `Aktuelle Einstellung: ${formatUnlockPolicyLabel(policy)}.`;
}

function formatUnlockPolicyLabel(policy) {
  switch (policy) {
    case 'off': return 'nie';
    case '5m': return '5 Minuten';
    case '15m': return '15 Minuten';
    case '30m': return '30 Minuten';
    case '60m': return '60 Minuten';
    case 'session': return 'bis Browser-Ende';
    default: return '15 Minuten';
  }
}

function formatShortHex(hex) {
  const value = String(hex || '').trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(value)) return value || 'unbekannt';
  return `${value.slice(0, 12)}...${value.slice(-8)}`;
}
