# TASK-20: Chat-UI – Kontaktliste, Nachrichten-Ansicht & Suchfunktion

## Iststand (2026-02)

Diese Task-Datei enthält Plan-/Designanteile. Für den aktuellen Background-Vertrag gelten im Chat-Kontext:

- `NOSTR_GET_DMS` mit Payload: `{ relayUrl, contactPubkey, since?, limit? }`
- `NOSTR_SEND_DM` mit Payload: `{ recipientPubkey, content, relayUrl }`
- `NOSTR_SUBSCRIBE_DMS` mit Payload: `{ relayUrl }`

`scope` wird für DM-Operationen nicht mehr benötigt (Key-Suche erfolgt scope-agnostisch im Background).

## Ziel

Die Home-View der neuen App-Shell (TASK-16) wird zur vollständigen Chat-Oberfläche ausgebaut. Sie zeigt die Kontaktliste mit letzten Nachrichten, eine Suchfunktion und eine Konversations-Ansicht für 1:1 DMs.

## Abhängigkeiten

- TASK-16 (App-Shell & View-Router)
- TASK-18 (Kontaktliste & Profil-Auflösung)
- TASK-19 (NIP-17 DM Backend)
- TASK-13 (CSS Design-System)

## Design-Spezifikation

### Home-View: Kontaktliste

```text
┌──────────────────────────────┐
│  CONTACTS (Kind 3)           │
├──────────────────────────────┤
│  🔍 Kontakte durchsuchen...  │
├──────────────────────────────┤
│  ┌────┬──────────────┬────┐ │
│  │ 🟢 │ Bob Builder   │ 2m │ │
│  │ Av │ Hey, did you  │ ② │ │
│  │    │ sign that...  │    │ │
│  └────┴──────────────┴────┘ │
│  ┌────┬──────────────┬────┐ │
│  │    │ Carol Crypto  │ 1h │ │
│  │ Av │ Sent you the  │    │ │
│  │    │ sats!         │    │ │
│  └────┴──────────────┴────┘ │
│  ┌────┬──────────────┬────┐ │
│  │    │ Dave Developer│ 3h │ │
│  │ Av │ Can we check  │    │ │
│  │    │ the NIP-44... │    │ │
│  └────┴──────────────┴────┘ │
│  ┌────┬──────────────┬────┐ │
│  │    │ Eve Encrypted │ 1d │ │
│  │ Av │ Secrets are   │    │ │
│  │    │ safe.         │    │ │
│  └────┴──────────────┴────┘ │
└──────────────────────────────┘
```

### Konversations-Ansicht (Drill-Down)

```text
┌──────────────────────────────┐
│  ← Bob Builder          ···  │
├──────────────────────────────┤
│                              │
│  ┌────────────────────┐      │
│  │ Bob: Hey, did you  │ 14:02│
│  │ sign that event?   │      │
│  └────────────────────┘      │
│                              │
│      ┌────────────────────┐  │
│ 14:05│ Yes, already done! │  │
│      └────────────────────┘  │
│                              │
│  ┌────────────────────┐      │
│  │ Bob: Great, thanks!│ 14:06│
│  └────────────────────┘      │
│                              │
├──────────────────────────────┤
│  ┌──────────────────┬──────┐│
│  │ Nachricht...      │ Senden││
│  └──────────────────┴──────┘│
└──────────────────────────────┘
```

## HTML-Struktur

### Home-View (Kontaktliste)

```html
<div class="view active" id="view-home">
  <div class="contacts-header">
    <h2>CONTACTS <span class="contacts-badge">Kind 3</span></h2>
  </div>
  
  <div class="search-bar">
    <input type="text" id="contact-search" placeholder="Kontakte durchsuchen..." />
  </div>
  
  <div class="contact-list" id="contact-list">
    <!-- Wird dynamisch befüllt -->
    <p class="empty" id="contacts-empty">Kontakte werden geladen...</p>
  </div>
</div>
```

### Konversations-View (Dialog-Overlay oder Sub-View)

```html
<div class="view" id="view-conversation">
  <div class="conversation-header">
    <button class="btn-back" id="conversation-back">←</button>
    <img class="conversation-avatar" id="conversation-avatar" src="" alt="" />
    <span class="conversation-name" id="conversation-name"></span>
  </div>
  
  <div class="message-list" id="message-list">
    <!-- Wird dynamisch befüllt -->
  </div>
  
  <div class="message-input-bar">
    <input type="text" id="message-input" placeholder="Nachricht..." />
    <button class="btn-primary btn-send" id="send-message">Senden</button>
  </div>
</div>
```

## CSS-Spezifikation

### Kontaktliste

```css
.search-bar {
  padding: 8px 14px;
}

.search-bar input {
  width: 100%;
  border-radius: 999px;
  padding: 8px 14px;
  font-size: 12px;
  border: 1px solid var(--border);
  background: var(--surface-2);
}

.contact-list {
  display: flex;
  flex-direction: column;
  gap: 2px;
  overflow-y: auto;
}

.contact-item {
  display: grid;
  grid-template-columns: 44px 1fr auto;
  gap: 10px;
  align-items: center;
  padding: 10px 14px;
  cursor: pointer;
  transition: background 0.12s;
  border-bottom: 1px solid color-mix(in srgb, var(--border) 40%, transparent);
}

.contact-item:hover {
  background: var(--accent-soft);
}

.contact-avatar {
  width: 44px;
  height: 44px;
  border-radius: 999px;
  object-fit: cover;
  background: var(--surface-2);
  border: 1px solid var(--border);
}

.contact-online-dot {
  position: absolute;
  bottom: 2px;
  left: 32px;
  width: 10px;
  height: 10px;
  background: var(--success);
  border-radius: 50%;
  border: 2px solid var(--surface);
}

.contact-info {
  min-width: 0;
}

.contact-name {
  font-size: 13px;
  font-weight: 700;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.contact-preview {
  font-size: 11px;
  color: var(--muted);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  margin-top: 2px;
}

.contact-meta {
  text-align: right;
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 4px;
}

.contact-time {
  font-size: 10px;
  color: var(--muted);
}

.unread-badge {
  background: var(--accent);
  color: #fff;
  font-size: 10px;
  font-weight: 700;
  border-radius: 999px;
  min-width: 18px;
  height: 18px;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0 5px;
}
```

### Konversations-Ansicht

```css
.conversation-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  border-bottom: 1px solid var(--border);
  background: var(--surface);
  position: sticky;
  top: 0;
  z-index: 10;
}

.conversation-avatar {
  width: 32px;
  height: 32px;
  border-radius: 999px;
}

.conversation-name {
  font-size: 14px;
  font-weight: 700;
}

.message-list {
  flex: 1;
  overflow-y: auto;
  padding: 12px 14px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.message-bubble {
  max-width: 78%;
  padding: 8px 12px;
  border-radius: 14px;
  font-size: 12px;
  line-height: 1.4;
  word-break: break-word;
}

.message-in {
  align-self: flex-start;
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-bottom-left-radius: 4px;
}

.message-out {
  align-self: flex-end;
  background: linear-gradient(160deg, var(--accent), var(--accent-strong));
  color: #fff;
  border-bottom-right-radius: 4px;
}

.message-time {
  font-size: 9px;
  color: var(--muted);
  margin-top: 3px;
}

.message-out .message-time {
  color: rgba(255, 255, 255, 0.7);
}

.message-input-bar {
  display: flex;
  gap: 8px;
  padding: 8px 14px;
  border-top: 1px solid var(--border);
  background: var(--surface);
}

.message-input-bar input {
  flex: 1;
  border-radius: 999px;
}

.btn-send {
  border-radius: 999px;
  padding: 6px 16px;
  white-space: nowrap;
}
```

## JavaScript-Implementierung

### Kontaktliste rendern

```javascript
function renderContactList(contacts, messages) {
  const listNode = document.getElementById('contact-list');
  const emptyNode = document.getElementById('contacts-empty');
  
  if (!contacts.length) {
    emptyNode.textContent = 'Keine Kontakte gefunden.';
    emptyNode.style.display = 'block';
    listNode.innerHTML = '';
    listNode.appendChild(emptyNode);
    return;
  }
  
  emptyNode.style.display = 'none';
  
  // Für jeden Kontakt: letzte Nachricht finden
  const contactsWithPreview = contacts.map(c => {
    const lastMsg = getLastMessageForContact(messages, c.pubkey);
    return { ...c, lastMsg };
  });
  
  // Sortieren: Kontakte mit neuesten Nachrichten zuerst
  contactsWithPreview.sort((a, b) => {
    const aTime = a.lastMsg?.createdAt || 0;
    const bTime = b.lastMsg?.createdAt || 0;
    return bTime - aTime;
  });
  
  listNode.innerHTML = contactsWithPreview.map(c => `
    <div class="contact-item" data-pubkey="${escapeHtml(c.pubkey)}">
      <div style="position: relative">
        <img class="contact-avatar" 
             src="${escapeHtml(c.picture || '')}" 
             alt=""
             onerror="this.src='data:image/svg+xml,...'" />
      </div>
      <div class="contact-info">
        <div class="contact-name">${escapeHtml(c.displayName || c.name || formatShortHex(c.pubkey))}</div>
        <div class="contact-preview">${escapeHtml(c.lastMsg?.content || c.nip05 || '')}</div>
      </div>
      <div class="contact-meta">
        ${c.lastMsg ? `<span class="contact-time">${formatRelativeTime(c.lastMsg.createdAt)}</span>` : ''}
        ${c.unreadCount ? `<span class="unread-badge">${c.unreadCount}</span>` : ''}
      </div>
    </div>
  `).join('');
}
```

### Suche

```javascript
function setupContactSearch() {
  const searchInput = document.getElementById('contact-search');
  let searchTimeout = null;
  
  searchInput.addEventListener('input', () => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      const query = searchInput.value.trim().toLowerCase();
      filterContacts(query);
    }, 200); // Debounce 200ms
  });
}

function filterContacts(query) {
  const items = document.querySelectorAll('.contact-item');
  items.forEach(item => {
    const name = item.querySelector('.contact-name')?.textContent?.toLowerCase() || '';
    const preview = item.querySelector('.contact-preview')?.textContent?.toLowerCase() || '';
    const visible = !query || name.includes(query) || preview.includes(query);
    item.style.display = visible ? '' : 'none';
  });
}
```

### Konversation öffnen

```javascript
function openConversation(contactPubkey) {
  const contact = currentContacts.find(c => c.pubkey === contactPubkey);
  if (!contact) return;
  
  // Header setzen
  document.getElementById('conversation-name').textContent = 
    contact.displayName || contact.name || formatShortHex(contactPubkey);
  document.getElementById('conversation-avatar').src = contact.picture || '';
  
  // Aktive Konversation merken
  activeConversationPubkey = contactPubkey;
  
  // Nachrichten laden
  loadConversationMessages(contactPubkey);
  
  // View wechseln
  showConversationView();
}

async function loadConversationMessages(contactPubkey) {
  const messageList = document.getElementById('message-list');
  messageList.innerHTML = '<p class="empty">Nachrichten werden geladen...</p>';
  
  try {
    const response = await chrome.runtime.sendMessage({
      type: 'NOSTR_GET_DMS',
      payload: {
        relayUrl: activeDmRelay,
        contactPubkey
      }
    });
    
    const messages = response?.result?.messages || [];
    renderMessages(messages, contactPubkey);
    
    // Scroll to bottom
    messageList.scrollTop = messageList.scrollHeight;
  } catch (error) {
    messageList.innerHTML = `<p class="empty error">Fehler: ${escapeHtml(error.message)}</p>`;
  }
}
```

### Nachrichten rendern

```javascript
function renderMessages(messages, contactPubkey) {
  const messageList = document.getElementById('message-list');
  
  if (!messages.length) {
    messageList.innerHTML = '<p class="empty">Noch keine Nachrichten. Schreibe die erste!</p>';
    return;
  }
  
  messageList.innerHTML = messages.map(msg => {
    const isOutgoing = msg.direction === 'out';
    const timeStr = formatMessageTime(msg.createdAt);
    
    return `
      <div class="message-bubble ${isOutgoing ? 'message-out' : 'message-in'}">
        <div class="message-content">${renderMinimalMarkdown(msg.content)}</div>
        <div class="message-time">${timeStr}</div>
      </div>
    `;
  }).join('');
}
```

### Minimal-Markdown-Rendering

Für Chat-Nachrichten wird ein sicheres, minimales Markdown unterstützt:

**Unterstützte Formate:**
- `**bold**` → **bold**
- `*italic*` → *italic*
- `` `code` `` → `code`
- `- list item` → • list item
- `[text](url)` → Link mit `rel="nofollow noopener noreferrer"`

```javascript
/**
 * Minimaler Markdown-Renderer für Chat-Nachrichten.
 * Unterstützt: bold, italic, code, list items, links.
 * Alle Links erhalten nofollow/noopener/noreferrer.
 * 
 * @param {string} text - Roher Nachrichtentext
 * @returns {string} - HTML-String (sicher gerendert)
 */
function renderMinimalMarkdown(text) {
  // 1. Erst HTML escapen (Sicherheit)
  let escaped = escapeHtml(text);
  
  // 2. Inline-Code: `code` → <code>code</code>
  escaped = escaped.replace(/`([^`]+)`/g, '<code>$1</code>');
  
  // 3. Bold: **text** → <strong>text</strong>
  escaped = escaped.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  
  // 4. Italic: *text* → <em>text</em> (nicht innerhalb von code/strong)
  escaped = escaped.replace(/(?<![<code>])\*([^*]+)\*(?![<])/g, '<em>$1</em>');
  
  // 5. Links: [text](url) → <a href="url" rel="nofollow noopener noreferrer" target="_blank">text</a>
  escaped = escaped.replace(
    /\[([^\]]+)\]\(([^)]+)\)/g,
    '<a href="$2" rel="nofollow noopener noreferrer" target="_blank">$1</a>'
  );
  
  // 6. List items: - text → • text (am Zeilenanfang)
  escaped = escaped.replace(/^- (.+)$/gm, '• $1');
  
  // 7. Zeilenumbrüche: \n → <br>
  escaped = escaped.replace(/\n/g, '<br>');
  
  return escaped;
}
```

**Sicherheitsmerkmale:**
- HTML wird zuerst escaped (`<` → `&lt;`, etc.)
- Links erhalten `rel="nofollow noopener noreferrer"` um Phishing/Tracking zu verhindern
- Keine Unterstützung für Bilder (`![]()`), Script-Tags oder andere gefährliche Elemente
- `target="_blank"` öffnet Links in neuem Tab

### Nachricht senden

```javascript
async function sendMessage() {
  const input = document.getElementById('message-input');
  const content = input.value.trim();
  if (!content || !activeConversationPubkey) return;
  
  const sendButton = document.getElementById('send-message');
  sendButton.disabled = true;
  input.disabled = true;
  
  try {
    const response = await chrome.runtime.sendMessage({
      type: 'NOSTR_SEND_DM',
      payload: {
        recipientPubkey: activeConversationPubkey,
        content,
        relayUrl: activeDmRelay
      }
    });
    
    if (response?.result?.success) {
      input.value = '';
      // Nachricht sofort in der UI anzeigen (optimistic update)
      appendOptimisticMessage(content);
    } else {
      showStatus(`Fehler: ${response?.error || 'Unbekannt'}`, true);
    }
  } catch (error) {
    showStatus(`Sendefehler: ${error.message}`, true);
  } finally {
    sendButton.disabled = false;
    input.disabled = false;
    input.focus();
  }
}
```

### Hilfsfunktionen

```javascript
function formatRelativeTime(unixTimestamp) {
  const diff = Math.floor(Date.now() / 1000) - unixTimestamp;
  if (diff < 60) return 'jetzt';
  if (diff < 3600) return `${Math.floor(diff / 60)}m`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h`;
  if (diff < 604800) return `${Math.floor(diff / 86400)}d`;
  return new Date(unixTimestamp * 1000).toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit' });
}

function formatMessageTime(unixTimestamp) {
  return new Date(unixTimestamp * 1000).toLocaleTimeString('de-DE', { 
    hour: '2-digit', 
    minute: '2-digit' 
  });
}

function getLastMessageForContact(messages, contactPubkey) {
  return messages
    .filter(m => m.senderPubkey === contactPubkey || m.recipientPubkey === contactPubkey)
    .sort((a, b) => b.createdAt - a.createdAt)[0] || null;
}

function getUnreadCount(messages, contactPubkey, lastReadTimestamp) {
  return messages.filter(m => 
    m.senderPubkey === contactPubkey && 
    m.direction === 'in' &&
    m.createdAt > (lastReadTimestamp || 0)
  ).length;
}
```

## Akzeptanzkriterien

### Kontaktliste
- [ ] Home-View zeigt Kontaktliste mit Avatar, Name, letzte Nachricht, Zeitstempel
- [ ] Ungelesene Nachrichten werden als Badge-Zahl angezeigt
- [ ] Suchfeld filtert Kontakte in Echtzeit (Debounce 200ms)
- [ ] Klick auf Kontakt öffnet Konversations-Ansicht
- [ ] Relative Zeitangaben (2m, 1h, 3h, 1d)
- [ ] Nachrichten-Vorschau in Kontaktliste wird bei langen Texten abgeschnitten

### Konversations-Ansicht
- [ ] Konversation zeigt Chat-Bubbles (eingehend links, ausgehend rechts)
- [ ] Eingabefeld + Senden-Button zum Verfassen von Nachrichten
- [ ] Optimistic Update: Gesendete Nachricht erscheint sofort in der UI
- [ ] Zurück-Button kehrt zur Kontaktliste zurück
- [ ] Leerer Zustand: Sinnvolle Hinweise wenn keine Kontakte / keine Nachrichten
- [ ] Auto-Scroll zum neuesten Nachricht bei Konversations-Öffnung
- [ ] Enter-Taste sendet Nachricht
- [ ] Konversation scrollbar bei vielen Nachrichten
- [ ] Fehlerbehandlung: Sende-Fehler wird angezeigt, UI bleibt bedienbar

### Minimal-Markdown
- [ ] **bold** wird korrekt gerendert (`**text**`)
- [ ] *italic* wird korrekt gerendert (`*text*`)
- [ ] `code` wird korrekt gerendert (`` `code` ``)
- [ ] List items werden mit Bullet-Point gerendert (`- item`)
- [ ] Links werden gerendert mit `rel="nofollow noopener noreferrer"`
- [ ] Links öffnen in neuem Tab (`target="_blank"`)
- [ ] HTML in Nachrichten wird escaped (kein XSS möglich)
- [ ] Zeilenumbrüche werden als `<br>` gerendert

### Styling
- [ ] Dark/Light Mode korrekt (CSS Custom Properties)

## Performance-Hinweise

- Kontakte und Profile werden aus dem Cache geladen (TASK-18)
- Nachrichten werden aus dem lokalen Cache geladen, Relay-Fetch nur bei Force-Refresh
- Liste wird einmalig gerendert, Suche filtert via `display: none` (kein Re-Render)
- Avatar-Bilder laden lazy (`loading="lazy"`)
- Maximal 100 Kontakte initial anzeigen (Paginierung bei Bedarf)

## Nicht-Ziele (für spätere Tasks)

- Gruppen-DMs (NIP-17 mit mehreren p-Tags)
- Nachrichtensuche innerhalb von Konversationen
- Dateianhänge (Kind 15)
- Emoji-Reaktionen
- Push-Benachrichtigungen (erfordert Service Worker Notification API)
- Message-Status (zugestellt/gelesen)
