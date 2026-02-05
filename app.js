// pwa/app.js
// Hybrid model:
// - Python API is source of truth (vault.dat encrypted with Fernet)
// - PWA stores an *extra* encrypted snapshot locally for offline/instant use
// - Offline edits queue as ops; next online: push ops, then pull latest snapshot

// ---------------- UI helpers ----------------
const $ = (id) => document.getElementById(id);
const loginCard = $("loginCard");
const vaultCard = $("vaultCard");
const loginMsg = $("loginMsg");
const statusPill = $("statusPill");
const rowsEl = $("rows");
const metaEl = $("meta");
const modal = $("modal");
const modalMsg = $("modalMsg");

let API_BASE = "";
let token = null;

let masterPassword = "";        // kept in memory only
let cacheKeyCrypto = null;      // derived CryptoKey in memory only

let stateEntries = [];          // decrypted in-memory entries
let editingKey = null;          // {service, username} for existing row, or null for new

// ---------------- IndexedDB ----------------
const DB_NAME = "vault_pwa_db";
const DB_VER = 1;

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VER);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains("kv")) db.createObjectStore("kv");
      if (!db.objectStoreNames.contains("ops")) db.createObjectStore("ops", { keyPath: "opId" });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function kvSet(key, val) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("kv", "readwrite");
    tx.objectStore("kv").put(val, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
async function kvGet(key) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("kv", "readonly");
    const r = tx.objectStore("kv").get(key);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

async function opsAdd(op) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("ops", "readwrite");
    tx.objectStore("ops").put(op);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
async function opsAll() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("ops", "readonly");
    const r = tx.objectStore("ops").getAll();
    r.onsuccess = () => resolve(r.result || []);
    r.onerror = () => reject(r.error);
  });
}
async function opsClearMany(opIds) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("ops", "readwrite");
    const store = tx.objectStore("ops");
    for (const id of opIds) store.delete(id);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ---------------- Crypto: PBKDF2 + AES-GCM ----------------
function bufToB64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
function b64ToBuf(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

async function deriveCacheKeyFromPassword(password, saltB64) {
  const salt = saltB64 ? b64ToBuf(saltB64) : crypto.getRandomValues(new Uint8Array(16)).buffer;

  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 200_000,
      hash: "SHA-256"
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );

  return { key, saltB64: bufToB64(salt) };
}

async function encryptSnapshot(entries) {
  // returns {saltB64, ivB64, ctB64}
  const { key, saltB64 } = await deriveCacheKeyFromPassword(masterPassword, await kvGet("cacheSaltB64"));
  cacheKeyCrypto = key;

  // persist salt so the same master password can decrypt later
  await kvSet("cacheSaltB64", saltB64);

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(entries));

  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    cacheKeyCrypto,
    plaintext
  );

  return { saltB64, ivB64: bufToB64(iv.buffer), ctB64: bufToB64(ct) };
}

async function decryptSnapshot(blob) {
  // blob: {saltB64, ivB64, ctB64}
  const { key } = await deriveCacheKeyFromPassword(masterPassword, blob.saltB64);
  cacheKeyCrypto = key;

  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(b64ToBuf(blob.ivB64)) },
    cacheKeyCrypto,
    b64ToBuf(blob.ctB64)
  );

  return JSON.parse(new TextDecoder().decode(pt));
}

// ---------------- Data normalization ----------------
function parseTags(tagsStr) {
  return (tagsStr || "")
    .split(",")
    .map(t => t.trim())
    .filter(Boolean);
}

function entryKey(e) {
  return `${(e.service||"").toLowerCase()}::${(e.username||"").toLowerCase()}`;
}

function normalizeEntry(e) {
  return {
    service: (e.service || "").trim(),
    username: (e.username || "").trim(),
    email: (e.email || "").trim(),
    phone: (e.phone || "").trim(),
    tags: Array.isArray(e.tags) ? e.tags : parseTags(e.tags || ""),
    password: (e.password || ""),
    note: (e.note || "").trim(),
    custom1: (e.custom1 || "").trim(),
    custom2: (e.custom2 || "").trim(),
  };
}

// ---------------- API calls ----------------
async function api(path, opts = {}) {
  const url = `${API_BASE}${path}`;
  const headers = opts.headers || {};
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (!headers["Content-Type"] && opts.body) headers["Content-Type"] = "application/json";

  const res = await fetch(url, { ...opts, headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

async function apiLogin(pw) {
  return api("/api/login", { method: "POST", body: JSON.stringify({ master_password: pw }) });
}
async function apiSnapshot() {
  return api("/api/snapshot", { method: "GET" });
}
async function apiApplyOps(ops) {
  return api("/api/apply-ops", { method: "POST", body: JSON.stringify({ ops }) });
}
async function apiMetadata() {
  return api("/api/metadata", { method: "GET" });
}

// ---------------- Rendering ----------------
function render(entries) {
  const q = ($("q").value || "").toLowerCase().trim();
  const filtered = !q ? entries : entries.filter(e => {
    const tags = (e.tags || []).join(",").toLowerCase();
    return (
      (e.service || "").toLowerCase().includes(q) ||
      (e.username || "").toLowerCase().includes(q) ||
      (e.email || "").toLowerCase().includes(q) ||
      tags.includes(q)
    );
  });

  rowsEl.innerHTML = "";
  for (const e of filtered) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(e.service)}</td>
      <td>${escapeHtml(e.username)}</td>
      <td>${escapeHtml(e.email)}</td>
      <td>${escapeHtml((e.tags||[]).join(", "))}</td>
      <td class="right">
        <div class="actionsCell">
          <button class="btn" data-act="view">View</button>
          <button class="btn secondary" data-act="copy">Copy PW</button>
        </div>
      </td>
    `;

    tr.querySelector('[data-act="view"]').onclick = () => openModal(e);
    tr.querySelector('[data-act="copy"]').onclick = async () => {
      try {
        await navigator.clipboard.writeText(e.password || "");
        status(`Copied password for ${e.service}`, false);
      } catch {
        status("Clipboard blocked by browser settings.", true);
      }
    };

    rowsEl.appendChild(tr);
  }
}

function escapeHtml(s) {
  return (s ?? "").toString()
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function status(text, isErr=false) {
  statusPill.textContent = text;
  statusPill.style.color = isErr ? "#fecaca" : "#9ca3af";
  statusPill.style.borderColor = isErr ? "rgba(239,68,68,.5)" : "var(--line)";
}

// ---------------- Modal ----------------
function openModal(entryOrNull) {
  modal.classList.remove("hidden");
  modalMsg.textContent = "";

  if (!entryOrNull) {
    $("modalTitle").textContent = "Add Entry";
    $("btnDelete").style.display = "none";
    editingKey = null;

    fillForm({
      service: "", username: "", email: "", phone: "",
      tags: [], password: "", note: "", custom1: "", custom2: ""
    });
    return;
  }

  $("modalTitle").textContent = "Edit Entry";
  $("btnDelete").style.display = "inline-block";
  editingKey = entryKey(entryOrNull);

  fillForm(entryOrNull);
}

function fillForm(e) {
  $("fService").value = e.service || "";
  $("fUsername").value = e.username || "";
  $("fEmail").value = e.email || "";
  $("fPhone").value = e.phone || "";
  $("fTags").value = (e.tags || []).join(", ");
  $("fPassword").value = e.password || "";
  $("fNote").value = e.note || "";
  $("fCustom1").value = e.custom1 || "";
  $("fCustom2").value = e.custom2 || "";
}

function readForm() {
  return normalizeEntry({
    service: $("fService").value,
    username: $("fUsername").value,
    email: $("fEmail").value,
    phone: $("fPhone").value,
    tags: parseTags($("fTags").value),
    password: $("fPassword").value,
    note: $("fNote").value,
    custom1: $("fCustom1").value,
    custom2: $("fCustom2").value
  });
}

function closeModal() {
  modal.classList.add("hidden");
  modalMsg.textContent = "";
}

// ---------------- Offline cache + sync ----------------
async function loadFromCacheIfPossible() {
  const blob = await kvGet("encryptedSnapshot");
  if (!blob) return false;

  try {
    const entries = await decryptSnapshot(blob);
    stateEntries = entries;
    render(stateEntries);
    return true;
  } catch {
    return false;
  }
}

async function saveCache(entries) {
  const blob = await encryptSnapshot(entries);
  await kvSet("encryptedSnapshot", blob);
}

async function queueOp(type, payload) {
  const op = {
    opId: crypto.randomUUID(),
    type,
    payload,
    t: Date.now()
  };
  await opsAdd(op);
}

async function syncNow() {
  const online = navigator.onLine;
  if (!online) {
    status("offline (queued)", true);
    return;
  }
  if (!token) {
    status("not logged in", true);
    return;
  }

  status("syncing...", false);

  // 1) push ops
  const pending = await opsAll();
  if (pending.length) {
    const res = await apiApplyOps(pending.map(o => ({ type: o.type, payload: o.payload })));
    await opsClearMany(pending.map(o => o.opId));
    await kvSet("lastVersion", res.version);
  }

  // 2) pull if needed
  const meta = await apiMetadata();
  const localV = (await kvGet("lastVersion")) || 0;

  if (meta.version > localV) {
    const snap = await apiSnapshot();
    stateEntries = (snap.entries || []).map(normalizeEntry);
    await kvSet("lastVersion", snap.version);
    await saveCache(stateEntries);
    render(stateEntries);
  } else {
    // even if no server change, ensure cache is saved for current state
    await saveCache(stateEntries);
  }

  metaEl.textContent = `version: ${(await kvGet("lastVersion")) || "?"} • pending ops: ${(await opsAll()).length}`;
  status("synced", false);
}

// ---------------- Locking ----------------
async function lock() {
  token = null;
  masterPassword = "";
  cacheKeyCrypto = null;
  stateEntries = [];
  rowsEl.innerHTML = "";
  metaEl.textContent = "";
  $("masterPw").value = "";
  $("btnDelete").style.display = "inline-block";

  vaultCard.classList.add("hidden");
  loginCard.classList.remove("hidden");
  status("locked", false);
}

// ---------------- Events ----------------
$("btnLogin").onclick = async () => {
  loginMsg.textContent = "";
  API_BASE = ($("serverUrl").value || "").trim().replace(/\/+$/, "");
  masterPassword = $("masterPw").value || "";

  if (!API_BASE) {
    loginMsg.textContent = "Enter a server base URL (https://...).";
    return;
  }
  if (!masterPassword) {
    loginMsg.textContent = "Enter your master password.";
    return;
  }

  // save server URL for convenience
  await kvSet("serverUrl", API_BASE);

  // Try load cached snapshot immediately (instant open), even before login.
  const cacheOk = await loadFromCacheIfPossible();
  if (cacheOk) {
    status("opened from cache", false);
  } else {
    status("no cache yet", true);
  }

  // Attempt online login; if it fails but we have cache, still allow offline use
  try {
    const res = await apiLogin(masterPassword);
    token = res.token;

    // after login, do a real sync
    loginCard.classList.add("hidden");
    vaultCard.classList.remove("hidden");
    await syncNow();

    loginMsg.textContent = "";
  } catch (e) {
    if (cacheOk) {
      // Offline mode or server unreachable -> still allow local view/edit queue
      token = null;
      loginCard.classList.add("hidden");
      vaultCard.classList.remove("hidden");
      metaEl.textContent = `offline mode • pending ops: ${(await opsAll()).length}`;
      status("offline mode", true);
    } else {
      loginMsg.textContent = `Login failed: ${e.message}`;
    }
  }
};

$("btnSync").onclick = () => syncNow();
$("btnLock").onclick = () => lock();

$("q").oninput = () => render(stateEntries);

$("btnAdd").onclick = () => openModal(null);
$("btnClose").onclick = () => closeModal();

$("btnSave").onclick = async () => {
  modalMsg.textContent = "";

  const entry = readForm();
  if (!entry.service || !entry.username) {
    modalMsg.textContent = "Service and Username are required.";
    return;
  }

  // Upsert locally
  const k = entryKey(entry);
  const idx = stateEntries.findIndex(e => entryKey(e) === (editingKey || k));
  if (idx >= 0) stateEntries[idx] = entry;
  else stateEntries.push(entry);

  // queue op
  await queueOp("upsert", entry);

  // save cache immediately so offline is always current
  await saveCache(stateEntries);
  render(stateEntries);

  metaEl.textContent = `version: ${(await kvGet("lastVersion")) || "?"} • pending ops: ${(await opsAll()).length}`;
  status("saved (queued)", false);

  closeModal();
};

$("btnDelete").onclick = async () => {
  if (!editingKey) {
    closeModal();
    return;
  }

  const entry = readForm();
  const k = entryKey(entry);

  // delete locally
  stateEntries = stateEntries.filter(e => entryKey(e) !== editingKey);

  // queue delete (payload needs service+username at minimum)
  await queueOp("delete", { service: entry.service, username: entry.username });

  await saveCache(stateEntries);
  render(stateEntries);

  metaEl.textContent = `version: ${(await kvGet("lastVersion")) || "?"} • pending ops: ${(await opsAll()).length}`;
  status("deleted (queued)", true);

  closeModal();
};

window.addEventListener("online", () => status("online", false));
window.addEventListener("offline", () => status("offline", true));

// Load saved server URL into box
(async function init() {
  const savedUrl = await kvGet("serverUrl");
  if (savedUrl) $("serverUrl").value = savedUrl;

  // If user opens app and wants to unlock offline, they just type master password.
  status(navigator.onLine ? "online" : "offline", !navigator.onLine);
})();