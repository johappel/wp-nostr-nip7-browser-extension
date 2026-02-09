const SETTING_KEY = 'preferWpNostrLock';
const DEFAULT_VALUE = true;

document.addEventListener('DOMContentLoaded', async () => {
  const checkbox = document.getElementById('prefer-lock');
  const status = document.getElementById('status');
  const unlockCacheSelect = document.getElementById('unlock-cache-policy');
  const unlockCacheHint = document.getElementById('unlock-cache-hint');
  const syncNowButton = document.getElementById('sync-now');
  const syncList = document.getElementById('sync-list');
  const syncMeta = document.getElementById('sync-meta');
  const manualPrimaryDomain = document.getElementById('manual-primary-domain');
  const manualDomainSecret = document.getElementById('manual-domain-secret');
  const manualAddButton = document.getElementById('manual-add');

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

  try {
    const response = await chrome.runtime.sendMessage({ type: 'NOSTR_GET_STATUS' });
    const runtimeStatus = response?.result;
    if (response?.error) throw new Error(response.error);

    const policy = normalizeUnlockPolicy(runtimeStatus?.unlockCachePolicy);
    unlockCacheSelect.value = policy;
    unlockCacheHint.textContent = formatUnlockCacheHint(runtimeStatus);
  } catch (e) {
    unlockCacheSelect.value = '15m';
    unlockCacheHint.textContent = 'Unlock-Status konnte nicht geladen werden.';
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

  unlockCacheSelect.addEventListener('change', async () => {
    const selectedPolicy = normalizeUnlockPolicy(unlockCacheSelect.value);
    unlockCacheSelect.disabled = true;
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'NOSTR_SET_UNLOCK_CACHE_POLICY',
        payload: { policy: selectedPolicy }
      });
      if (response?.error) throw new Error(response.error);

      unlockCacheSelect.value = normalizeUnlockPolicy(response?.result?.policy);
      const statusResponse = await chrome.runtime.sendMessage({ type: 'NOSTR_GET_STATUS' });
      const runtimeStatus = statusResponse?.result;
      unlockCacheHint.textContent = formatUnlockCacheHint(runtimeStatus);
      status.textContent = 'Unlock-Cache aktualisiert.';
    } catch (e) {
      status.textContent = `Unlock-Cache konnte nicht gespeichert werden: ${e.message || e}`;
    } finally {
      unlockCacheSelect.disabled = false;
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
