// Dialog-Logik für Backup, Password und Confirmation

const params = new URLSearchParams(window.location.search);
const type = params.get('type');

document.addEventListener('DOMContentLoaded', () => {
  switch (type) {
    case 'backup':
      showBackupDialog(params.get('npub'), params.get('nsec'));
      break;
    case 'password':
      showPasswordDialog(params.get('mode'));
      break;
    case 'domain':
      showDomainApprovalDialog(params.get('domain'));
      break;
    case 'confirm':
      showConfirmDialog(params.get('domain'), Number(params.get('kind')));
      break;
    default:
      document.getElementById('app').innerHTML = '<p>Unbekannter Dialog-Typ</p>';
  }
});

function showBackupDialog(npub, nsec) {
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="dialog backup">
      <h2>🔐 Dein Nostr Schlüsselpaar</h2>
      <p class="warning">⚠️ WICHTIG: Speichere deinen privaten Schlüssel JETZT!
      Er wird nach Schließen dieses Dialogs nicht mehr angezeigt.</p>
      
      <div class="key-box">
        <label>Öffentlicher Schlüssel (Npub):</label>
        <code id="npub-display">${escapeHtml(npub)}</code>
        <button onclick="copyToClipboard('npub-display')" class="btn-secondary">Kopieren</button>
      </div>
      
      <div class="key-box nsec-box">
        <label>Privater Schlüssel (Nsec) – GEHEIM HALTEN:</label>
        <code id="nsec-display" class="blurred">${escapeHtml(nsec)}</code>
        <div class="btn-group">
          <button onclick="toggleVisibility('nsec-display')" class="btn-secondary">Anzeigen</button>
          <button onclick="copyToClipboard('nsec-display')" class="btn-secondary">Kopieren</button>
        </div>
      </div>
      
      <div class="actions">
        <button id="download" class="btn-primary">
          💾 Schlüssel als Datei speichern
        </button>
        <label class="checkbox-label">
          <input type="checkbox" id="confirm-saved" />
          Ich habe meinen privaten Schlüssel sicher gespeichert
        </label>
        <button id="close" class="btn-primary" disabled>🔒 Weiter</button>
      </div>
      
      <p class="hint">Ohne den privaten Schlüssel kannst du dein Konto
      nicht wiederherstellen. Es gibt keinen "Passwort vergessen"-Mechanismus.</p>
    </div>
  `;

  // Weiter-Button erst nach Checkbox aktiv
  document.getElementById('confirm-saved').onchange = (e) => {
    document.getElementById('close').disabled = !e.target.checked;
  };
  
  document.getElementById('download').onclick = () => {
    const blob = new Blob(
      [`Nostr Schlüssel-Backup\n==================\n\nNpub: ${npub}\nNsec: ${nsec}\n\n⚠️ NIEMALS TEILEN!\n`],
      { type: 'text/plain' }
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `nostr-backup-${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };
  
  document.getElementById('close').onclick = () => window.close();
}

function showPasswordDialog(mode) {
  const app = document.getElementById('app');
  const isCreate = mode === 'create';
  app.innerHTML = `
    <div class="dialog password">
      <h2>${isCreate ? '🔑 Passwort festlegen' : '🔓 Extension entsperren'}</h2>
      <p>${isCreate
        ? 'Dieses Passwort schützt deinen privaten Schlüssel. Mindestens 8 Zeichen.'
        : 'Gib dein Passwort ein, um fortzufahren.'}</p>
      
      <div class="input-group">
        <input type="password" id="password" placeholder="Passwort" autofocus />
      </div>
      
      ${isCreate ? `
        <div class="input-group">
          <input type="password" id="password-confirm" placeholder="Passwort wiederholen" />
        </div>
      ` : ''}
      
      <p id="error" class="error" hidden></p>
      
      <div class="actions">
        <button id="submit" class="btn-primary">${isCreate ? 'Festlegen' : 'Entsperren'}</button>
        <button id="cancel" class="btn-secondary">Abbrechen</button>
      </div>
    </div>
  `;

  document.getElementById('submit').onclick = async () => {
    const pw = document.getElementById('password').value;
    const errorEl = document.getElementById('error');
    
    if (isCreate) {
      const pw2 = document.getElementById('password-confirm').value;
      if (pw !== pw2) {
        errorEl.textContent = '❌ Passwörter stimmen nicht überein';
        errorEl.hidden = false;
        return;
      }
      if (pw.length < 8) {
        errorEl.textContent = '❌ Mindestens 8 Zeichen erforderlich';
        errorEl.hidden = false;
        return;
      }
    }
    
    if (!pw) {
      errorEl.textContent = '❌ Passwort erforderlich';
      errorEl.hidden = false;
      return;
    }
    
    await chrome.storage.session.set({ passwordResult: pw });
    window.close();
  };
  
  document.getElementById('cancel').onclick = () => {
    chrome.storage.session.set({ passwordResult: null });
    window.close();
  };
  
  // Enter-Taste unterstützt
  document.getElementById('password').onkeypress = (e) => {
    if (e.key === 'Enter') document.getElementById('submit').click();
  };
  if (isCreate) {
    document.getElementById('password-confirm').onkeypress = (e) => {
      if (e.key === 'Enter') document.getElementById('submit').click();
    };
  }
}

function showDomainApprovalDialog(domain) {
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="dialog domain">
      <h2>🌐 Neue Domain</h2>
      <p>Die Webseite <strong>${escapeHtml(domain)}</strong> möchte auf deine Nostr-Identität zugreifen.</p>
      <p>Möchtest du dieser Domain vertrauen?</p>
      
      <div class="actions">
        <button id="allow" class="btn-primary">✓ Erlauben</button>
        <button id="deny" class="btn-secondary">✗ Ablehnen</button>
        <label class="checkbox-label">
          <input type="checkbox" id="remember" checked />
          Entscheidung für diese Domain merken
        </label>
      </div>
    </div>
  `;

  const respond = async (allowed) => {
    const remember = document.getElementById('remember').checked;
    
    if (remember) {
      const storageKey = allowed ? 'allowedDomains' : 'blockedDomains';
      const { [storageKey]: list = [] } = await chrome.storage.local.get(storageKey);
      if (!list.includes(domain)) {
        list.push(domain);
        await chrome.storage.local.set({ [storageKey]: list });
      }
    }
    
    await chrome.storage.local.set({
      domainApprovalResult: { domain, allowed }
    });
    window.close();
  };

  document.getElementById('allow').onclick = () => respond(true);
  document.getElementById('deny').onclick = () => respond(false);
}

function showConfirmDialog(domain, kind) {
  const kindNames = { 
    0: 'Profil-Metadaten', 
    1: 'Text-Notiz',
    3: 'Kontaktliste', 
    4: 'Verschlüsselte Nachricht',
    5: 'Verschlüsselter Event (NIP-17)',
    6: 'Repost',
    7: 'Reaction',
    9735: 'Zap Request'
  };
  const kindName = kindNames[kind] || `Unbekannt (Kind ${kind})`;
  
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="dialog confirm">
      <h2>✍️ Signatur-Anfrage</h2>
      <p><strong>${escapeHtml(domain)}</strong> möchte ein Event signieren:</p>
      <div class="event-info">
        <span class="kind">${kindName}</span>
      </div>
      <p class="warning">⚠️ Dies ist ein sensitiver Event-Typ. Bitte prüfe sorgfältig, ob du dieser Domain vertraust.</p>
      
      <div class="actions">
        <button id="confirm" class="btn-primary">Signieren</button>
        <button id="reject" class="btn-secondary">Ablehnen</button>
      </div>
    </div>
  `;

  document.getElementById('confirm').onclick = async () => {
    await chrome.storage.local.set({ signConfirmResult: true });
    window.close();
  };
  
  document.getElementById('reject').onclick = async () => {
    await chrome.storage.local.set({ signConfirmResult: false });
    window.close();
  };
}

// --- Hilfsfunktionen ---
window.copyToClipboard = function(elementId) {
  const text = document.getElementById(elementId).textContent;
  navigator.clipboard.writeText(text).then(() => {
    // Visuelles Feedback
    const btn = event.target;
    const originalText = btn.textContent;
    btn.textContent = '✓ Kopiert!';
    setTimeout(() => btn.textContent = originalText, 1500);
  });
};

window.toggleVisibility = function(elementId) {
  const el = document.getElementById(elementId);
  el.classList.toggle('blurred');
  const btn = event.target;
  btn.textContent = el.classList.contains('blurred') ? 'Anzeigen' : 'Verbergen';
};

function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}