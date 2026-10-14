/**
 * app.js -- Demo Orchestration & UI
 *
 * This is the application glue layer. It imports the two integration
 * modules (ishield.js and umfa.js) and wires them to the UI.
 *
 * A partner integrating iShield + Passkeys+ into their own app would
 * primarily study ishield.js and umfa.js. This file is demo-specific
 * and handles screens, flash messages, popups, and event listeners.
 *
 * FLOW:
 *   1. Enter Game    -- on a bound device authenticate() with Passkeys+, no
 *                       key and no dialog; on an unbound device (an attendee
 *                       arriving from the registration QR) a dialog naming
 *                       the four steps, the USB key touch, whose User ID must
 *                       match the box, a second dialog handing over to the
 *                       passkey, enroll() with Passkeys+, then the simulated
 *                       SNA number check (sna.js) and its four indicators:
 *                       USB Key, Phone# Verified, Device Bound, Passkey
 *   2. Actions       -- step-up authenticate() per protected action
 *   2b. P2P Exchange -- after the step-up, a QR code another attendee scans;
 *                       they confirm, verify with their passkey, and both
 *                       phones then show the other's contact (api/exchange.js)
 *   3. Suspend       -- flag device as suspended, require the USB key to
 *                       reactivate
 *
 * There is no New or Passkeys toggle (removed 2026-10-14): the device's own
 * state picks the ceremony, Passkeys+ is always part of it, and the User ID
 * can be changed until the login completes.
 *
 * NOTE: state.js is loaded as a classic script (non-module) so that the
 * State class is available as a global. The stateChange custom events it
 * dispatches are available but unused in this demo.
 */

import {
  hasLocalEnrollmentMarker,
  ENROLLMENT_MARKER_PREFIX,
  isSuspended,
  setSuspended,
  webauthnAuthenticate
} from './ishield.js';

import {
  initializeZSMClient,
  checkAllEnrollment,
  enroll,
  authenticate,
  resetClient
} from './umfa.js';

import {
  verifyNumber,
  isNumberVerified,
  getNumberVerification,
  setNumberVerified,
  SNA_STEPS,
  SNA_SCENARIOS
} from './sna.js';

// ---------------------------------------------------------------------------
// Shared UI helpers
// ---------------------------------------------------------------------------

function showFlash(elementId, message, state, duration = 3000) {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.textContent = message;
  el.className = 'flash ' + state;
  setTimeout(() => { el.textContent = ''; el.className = 'flash'; }, duration);
}

function getUsername() {
  return document.getElementById('username')?.value?.trim().toLowerCase() || '';
}

/**
 * Digits of a phone-shaped User ID, with the US trunk prefix dropped, so
 * "1 (913) 555-1235" and "9135551235" read as the same number. This is the
 * same rule normalizePhone in register.js applies before putting the number on
 * the key, which is what makes the two comparable.
 */
function phoneDigits(value) {
  const digits = value.replace(/\D/g, '');
  return digits.length === 11 && digits.startsWith('1') ? digits.slice(1) : digits;
}

/**
 * Reconciles the User ID on screen with the identity the key just proved.
 * The key is the authority: it hands back the user handle stored in the
 * credential, and the screen has to agree with it.
 *
 * Returns null when they are different people, or when the key returned no
 * handle at all (then nothing vouches for the typed value); the caller stops
 * either way, and keyMismatchMessage says which it was. Otherwise it returns
 * the key's own spelling and writes it into the field, so after a successful
 * touch the User ID on screen IS the credential on the key.
 */
function reconcileUserId(typed, fromKey) {
  if (!fromKey) return null;
  if (typed !== fromKey && (!phoneDigits(typed) || phoneDigits(typed) !== phoneDigits(fromKey))) {
    return null;
  }
  document.getElementById('username').value = fromKey;
  localStorage.setItem('username', fromKey);
  return fromKey;
}

/** The flash for a reconcileUserId that returned null. */
function keyMismatchMessage(typed, fromKey) {
  return fromKey
    ? `This key belongs to "${fromKey}", but the User ID box says "${typed}". Enter the ID that matches the key, or use that person's key.`
    : 'This key carries no User ID. Enroll it on the registration page first.';
}

// ---------------------------------------------------------------------------
// Confirmation Popup helpers
// ---------------------------------------------------------------------------
let popupResolve = null;
let popupPreviousFocus = null;

function showPopup(message) {
  return new Promise((resolve) => {
    popupPreviousFocus = document.activeElement;
    document.getElementById('popup-message').textContent = message;
    const popup = document.getElementById('confirm-popup');
    popup.style.display = 'flex';
    popupResolve = resolve;
    document.getElementById('popup-continue').focus();
    document.addEventListener('keydown', popupKeyHandler);
  });
}

function popupKeyHandler(e) {
  if (e.key === 'Escape') {
    hidePopup('cancel');
    return;
  }
  if (e.key === 'Tab') {
    const cancelBtn = document.getElementById('popup-cancel');
    const continueBtn = document.getElementById('popup-continue');
    if (e.shiftKey && document.activeElement === cancelBtn) {
      e.preventDefault();
      continueBtn.focus();
    } else if (!e.shiftKey && document.activeElement === continueBtn) {
      e.preventDefault();
      cancelBtn.focus();
    }
  }
}

function hidePopup(action) {
  document.removeEventListener('keydown', popupKeyHandler);
  document.getElementById('confirm-popup').style.display = 'none';
  if (popupPreviousFocus) {
    popupPreviousFocus.focus();
    popupPreviousFocus = null;
  }
  if (popupResolve) {
    popupResolve(action);
    popupResolve = null;
  }
}

// ---------------------------------------------------------------------------
// Guide dialog -- the one-button dialog in front of a ceremony: what Enter
// Game is about to do on a phone that is not bound yet, and the handoff from
// the USB key to the passkey. The tap on its button is also the user gesture
// the WebAuthn prompt that follows needs. Resolves 'ok' for the button and
// 'cancel' for Escape; there is no cancel button (the owner's wording,
// 2026-10-14).
// ---------------------------------------------------------------------------

/** The dialog in front of a first Enter Game: the four steps, then Start. */
const ONBOARDING_GUIDE = {
  title: "Let's get your phone ready.",
  lead: 'We are going to do 4 things',
  steps: [
    'Verify your FIDO USB Key',
    'Create a mobile device Passkey',
    'Cryptographically bind device with ZSM',
    'Verify phone number with carrier API'
  ],
  note: 'Start with the USB FIDO Key',
  button: 'Start'
};

/** The handoff once the key has answered: the passkey is next. */
const PASSKEY_GUIDE = {
  title: "Now let's get your mobile device Passkey enrolled",
  button: 'Continue'
};

let guideResolve = null;
let guidePreviousFocus = null;

function showGuide({ title, lead = '', steps = [], note = '', button = 'Continue' }) {
  return new Promise((resolve) => {
    const $ = (id) => document.getElementById(id);
    guidePreviousFocus = document.activeElement;
    $('guide-title').textContent = title;
    $('guide-lead').textContent = lead;
    $('guide-lead').hidden = !lead;
    const list = $('guide-steps');
    list.replaceChildren(...steps.map((text) => {
      const item = document.createElement('li');
      item.textContent = text;
      return item;
    }));
    list.hidden = steps.length === 0;
    $('guide-note').textContent = note;
    $('guide-note').hidden = !note;
    $('guide-start').textContent = button;
    $('guide-popup').style.display = 'flex';
    guideResolve = resolve;
    $('guide-start').focus();
    document.addEventListener('keydown', guideKeyHandler);
  });
}

function guideKeyHandler(e) {
  if (e.key === 'Escape') {
    hideGuide('cancel');
  } else if (e.key === 'Tab') {
    // One button: focus stays on it
    e.preventDefault();
    document.getElementById('guide-start').focus();
  }
}

function hideGuide(action) {
  document.removeEventListener('keydown', guideKeyHandler);
  document.getElementById('guide-popup').style.display = 'none';
  if (guidePreviousFocus) {
    guidePreviousFocus.focus();
    guidePreviousFocus = null;
  }
  const resolve = guideResolve;
  guideResolve = null;
  if (resolve) resolve(action);
}

// ---------------------------------------------------------------------------
// Challenge display helpers (UI-only -- not called from ishield.js or umfa.js)
// ---------------------------------------------------------------------------

function updateChallengeDisplay(challenge, signedChallenge) {
  const PREVIEW_LEN = 15;
  const isReset = challenge === '--';
  const container = document.getElementById('passkeys-challenge-display');
  const prev = document.getElementById('challenge-preview');
  const full = document.getElementById('challenge-full');
  const sPrev = document.getElementById('signed-challenge-preview');
  const sFull = document.getElementById('signed-challenge-full');
  if (prev && full) {
    prev.textContent = challenge.substring(0, PREVIEW_LEN) + (challenge.length > PREVIEW_LEN ? '...' : '');
    full.textContent = challenge;
  }
  if (sPrev && sFull) {
    sPrev.textContent = signedChallenge.substring(0, PREVIEW_LEN) + (signedChallenge.length > PREVIEW_LEN ? '...' : '');
    sFull.textContent = signedChallenge;
  }
  if (container) container.hidden = isReset;
  document.getElementById('challenge-details')?.removeAttribute('open');
  document.getElementById('signed-challenge-details')?.removeAttribute('open');
}

function updateIShieldChallengeDisplay(challenge, signedChallenge) {
  const PREVIEW_LEN = 15;
  const container = document.getElementById('ishield-challenge-display');
  const prev = document.getElementById('ishield-challenge-preview');
  const full = document.getElementById('ishield-challenge-full');
  const sPrev = document.getElementById('ishield-signed-challenge-preview');
  const sFull = document.getElementById('ishield-signed-challenge-full');
  if (prev && full) {
    prev.textContent = challenge.substring(0, PREVIEW_LEN) + (challenge.length > PREVIEW_LEN ? '...' : '');
    full.textContent = challenge;
  }
  if (sPrev && sFull) {
    sPrev.textContent = signedChallenge.substring(0, PREVIEW_LEN) + (signedChallenge.length > PREVIEW_LEN ? '...' : '');
    sFull.textContent = signedChallenge;
  }
  if (container) container.hidden = false;
  document.getElementById('ishield-challenge-details')?.removeAttribute('open');
  document.getElementById('ishield-signed-challenge-details')?.removeAttribute('open');
}

function updateAuthIcons({ ishield = false, zsm = false, passkeys = false } = {}) {
  document.getElementById('icon-ishield').hidden = !ishield;
  document.getElementById('icon-zsm').hidden = !zsm;
  document.getElementById('icon-passkeys').hidden = !passkeys;
  const ishieldDisplay = document.getElementById('ishield-challenge-display');
  if (ishieldDisplay) ishieldDisplay.hidden = !ishield;
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const STATE = new State({
  loginID: null
});

// ---------------------------------------------------------------------------
// Action labels for protected actions
// ---------------------------------------------------------------------------
const PROTECTED_ACTION_LABELS = {
  'authenticate': 'Authenticate',
  'p2p-contact-exchange': 'P2P Contact Exchange',
  'view-point-standings': 'View Point Standings',
  'add-beneficiary': 'Add Beneficiary'
};

// ---------------------------------------------------------------------------
// User database -- the account behind the User ID
//
// The Ideem user API (docs/user-api.md) holds one record per attendee, keyed
// by the bare-digit phone number that is also the credential on the key. Its
// balance is points, the same number the partner booths credit. The actions
// with a cost debit that record through its balance endpoint once the step-up
// has succeeded. The other actions only step up.
//
// The API is reached through the site's own /db proxy (dev-server.mjs
// locally, api/db.js on Vercel) because it sends no CORS headers.
// ---------------------------------------------------------------------------
const DB_BASE = './db';

/**
 * What each action costs, in points. The registration form never asks for an
 * amount, so the demo charges a fixed one per action. Actions missing from
 * this table step up and stop; they touch no balance. P2P Contact Exchange
 * branches to its own screen before this table is consulted, so its entry is
 * unused until it is decided whether an exchange should cost anything.
 */
const ACTION_AMOUNTS = {
  'authenticate': 25,
  'p2p-contact-exchange': 100
};

const pointsFormat = new Intl.NumberFormat('en-US', { maximumFractionDigits: 2 });

/** "1,030 pts", "12.5 pts": the balance and every charge on this page, as on the partner page. */
function formatPoints(n) {
  return `${pointsFormat.format(n)} pts`;
}

/** The record for the logged-in user, or null when none is on file. */
let account = null;
/** Which User ID `account` was loaded for, so a stale record is never reused. */
let accountFor = null;

/**
 * Looks the logged-in user up by phone number. The API matches the stored
 * string exactly and answers an array, so this sends bare digits and takes
 * the first match. A User ID that is not phone-shaped has no record to find.
 *
 * @returns {Promise<{userId: number, balance: number}|null>}
 */
async function findAccount(user) {
  const digits = phoneDigits(user);
  if (!digits) return null;
  const res = await fetch(`${DB_BASE}/users/phone/${encodeURIComponent(digits)}`, { cache: 'no-store' });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`lookup returned ${res.status}`);
  const body = await res.json();
  const record = Array.isArray(body) ? body[0] ?? null : body;
  return record ? { userId: record.userId, balance: Number(record.balance) } : null;
}

/**
 * Re-reads the account from the database and redraws the balance line. A
 * database that is down or has no record leaves the demo usable: the actions
 * still step up, they just have nothing to charge.
 */
async function refreshAccount(user) {
  accountFor = user;
  try {
    account = await findAccount(user);
  } catch (err) {
    console.warn('[account] lookup failed:', err.message);
    account = null;
  }
  renderBalance();
}

function renderBalance() {
  const line = document.getElementById('balance-display');
  const value = document.getElementById('balance-value');
  if (!line || !value) return;
  line.hidden = !account;
  value.textContent = account ? formatPoints(account.balance) : '--';
}

/**
 * Moves the balance by `amount` through PATCH /users/:id/balance. The API
 * ADDS the amount it is sent (a charge is a negative number), rounds to two
 * decimals, and will take the balance below zero without complaint, so the
 * overdraft check lives in the caller, not here. It is also not idempotent:
 * a timed-out request may have applied, so the caller must never retry.
 *
 * @returns {Promise<number>} The balance the server now holds.
 */
async function adjustBalance(userId, amount) {
  const res = await fetch(`${DB_BASE}/users/${encodeURIComponent(userId)}/balance`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ amount })
  });
  if (!res.ok) throw new Error(`balance update returned ${res.status}`);
  const body = await res.json();
  return Number(body.user?.balance ?? body.balance);
}

/**
 * Charges an action's points to the logged-in user's account after the step-up
 * has been authorized. The balance is re-read first so the overdraft check
 * is against what the server holds now, not what this page last saw.
 *
 * @returns {Promise<{state: string, message: string}>} What to flash.
 */
async function settleAction(user, actionLabel, amount) {
  await refreshAccount(user);
  if (!account) {
    return { state: 'success', message: `${actionLabel} Authorized (no account on file)` };
  }
  if (account.balance < amount) {
    return {
      state: 'failure',
      message: `${actionLabel} Declined: ${formatPoints(amount)} exceeds balance of ${formatPoints(account.balance)}`
    };
  }
  try {
    account.balance = await adjustBalance(account.userId, -amount);
    renderBalance();
    return { state: 'success', message: `${actionLabel} Authorized: ${formatPoints(amount)} charged` };
  } catch (err) {
    // The charge may or may not have landed. Re-read rather than retry, so a
    // slow server never charges twice.
    console.error('[account] charge failed:', err.message);
    await refreshAccount(user);
    return { state: 'failure', message: `${actionLabel} Authorized, but the charge did not go through` };
  }
}

// ---------------------------------------------------------------------------
// P2P Contact Exchange
//
// Two logged-in attendees swap name and phone. The initiator taps the action,
// passes the step-up, and gets a code from api/exchange.js that this page
// shows as a QR. The responder scans it, lands here with ?exchange=<code>,
// logs in the usual way, and that login is what authorizes sending their
// User ID against the code. The server fills in both contacts from the user
// database, the initiator's poll sees it, and both screens show the other
// person. The ZSM token never leaves umfa.js: its validation window is a few
// seconds, so the server trusts the User ID and looks the contact up itself.
// ---------------------------------------------------------------------------

/** The matchmaker, relative like DB_BASE: dev-server.mjs and Vercel both mount it here. */
const EXCHANGE_API = './api/exchange';
/** How often the initiator's page asks whether someone has scanned. */
const EXCHANGE_POLL_MS = 2000;
/** sessionStorage key holding a scanned code until this phone has logged in. */
const PENDING_EXCHANGE_KEY = 'pendingExchange';

/**
 * The exchange this page is part of, if any. `role` is 'initiator' (this
 * phone showed the QR) or 'responder' (this phone scanned it). `record` is
 * the server's copy, refreshed by polling or by the completion response.
 * `confirmed` is the responder's tap on "Confirm sharing contact info";
 * until then the screen only asks.
 */
const exchange = { active: false, role: null, code: null, record: null, pollTimer: null, confirmed: false };

function getPendingExchange() {
  try { return sessionStorage.getItem(PENDING_EXCHANGE_KEY) || ''; } catch (_) { return ''; }
}

function setPendingExchange(code) {
  try {
    if (code) sessionStorage.setItem(PENDING_EXCHANGE_KEY, code);
    else sessionStorage.removeItem(PENDING_EXCHANGE_KEY);
  } catch (_) { /* private mode: the code simply is not remembered */ }
}

/** The URL the QR carries: this origin, since the code lives on the deployment that issued it. */
function exchangeUrl(code) {
  return `${location.origin}/?exchange=${encodeURIComponent(code)}`;
}

/**
 * One call to the matchmaker. Never throws: a network failure comes back as
 * status 0 so every caller branches on the status alone.
 */
async function exchangeFetch(query, body) {
  try {
    const res = await fetch(EXCHANGE_API + query, {
      method: body ? 'POST' : 'GET',
      cache: 'no-store',
      headers: body ? { 'Content-Type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined
    });
    let data = null;
    try { data = await res.json(); } catch (_) { /* no body */ }
    return { status: res.status, ok: res.ok, data: data ?? {} };
  } catch (err) {
    return { status: 0, ok: false, data: { error: err.message } };
  }
}

/**
 * Initiator side, after the step-up: ask for a code, show it as a QR, and
 * poll until the other person has logged in or the code expires.
 */
async function startExchange(user) {
  const { ok, data } = await exchangeFetch('', { userId: user });
  if (!ok) {
    showFlash('action-status', `P2P Contact Exchange unavailable: ${data.error || 'no response'}`, 'failure', 4000);
    return;
  }
  Object.assign(exchange, { active: true, role: 'initiator', code: data.code, record: data });
  showScreen('EXCHANGE');
  renderExchange();
  await renderExchangeQr(exchangeUrl(data.code));
  exchange.pollTimer = setTimeout(pollExchange, EXCHANGE_POLL_MS);
}

/** Re-reads the record; stops on completion, on expiry, or once the screen is left. */
async function pollExchange() {
  exchange.pollTimer = null;
  if (!exchange.active || exchange.role !== 'initiator') return;
  const { status, ok, data } = await exchangeFetch(`?code=${encodeURIComponent(exchange.code)}`);
  if (!exchange.active) return;   // Done was tapped while the request was in flight
  if (status === 404) {
    renderExchange({ expired: true });
    return;
  }
  if (ok) {
    exchange.record = data;
    if (data.responder) {
      renderExchange();
      return;
    }
  }
  exchange.pollTimer = setTimeout(pollExchange, EXCHANGE_POLL_MS);
}

/**
 * Responder side, once the passkey verification has set STATE.loginID: send
 * this User ID against the scanned code. The record the invite read is kept
 * so the screen keeps naming the other person while it sends.
 */
async function completeExchange(user, code) {
  setPendingExchange('');
  const record = exchange.code === code ? exchange.record : null;
  Object.assign(exchange, { active: true, role: 'responder', code, record, confirmed: true });
  showScreen('EXCHANGE');
  renderExchange();
  const { status, ok, data } = await exchangeFetch(`?code=${encodeURIComponent(code)}`, { userId: user });
  if (!exchange.active) return;
  if (status === 404) return renderExchange({ expired: true });
  if (status === 409) return renderExchange({ used: true });
  if (!ok) return renderExchange({ error: data.error || 'no response' });
  exchange.record = data;
  renderExchange();
}

/**
 * Responder side, the moment the QR's URL opens: show who is asking and a
 * "Confirm sharing contact info" button, before any credential is touched.
 * The code stays in sessionStorage so a reload lands back on this screen.
 * A code the server no longer holds, or one already used, is said so here
 * and forgotten, so nobody digs out a key for nothing.
 */
async function openExchangeInvite(code) {
  setPendingExchange(code);
  Object.assign(exchange, { active: true, role: 'responder', code, record: null, confirmed: false });
  showScreen('EXCHANGE');
  renderExchange();
  const { status, ok, data } = await exchangeFetch(`?code=${encodeURIComponent(code)}`);
  if (!exchange.active || exchange.code !== code) return;   // Cancel was tapped meanwhile
  if (status === 404) {
    setPendingExchange('');
    return renderExchange({ expired: true });
  }
  if (!ok) return renderExchange({ error: data.error || 'no response' });
  if (data.responder) {
    setPendingExchange('');
    return renderExchange({ used: true });
  }
  exchange.record = data;
  renderExchange();
}

/**
 * The confirm tap. The passkey verification is the demo's own login: on a
 * phone that is not bound yet that is the iShield touch plus ZSM enrollment,
 * on a bound phone the ZSM authenticate. login() ends in updateUI, which sees
 * the pending code and calls completeExchange. Should the page already be
 * logged in, the ZSM step-up alone is the verification, as for the actions.
 */
async function confirmExchange() {
  const btn = document.getElementById('exchange-confirm');
  if (!getUsername()) {
    showFlash('flash-status', 'Enter your User ID first.', 'failure', 4000);
    document.getElementById('username').focus();
    return;
  }
  if (!STATE.loginID) {
    await login(btn);
    return;
  }
  btn.classList.add('loading');
  btn.setAttribute('aria-busy', 'true');
  try {
    const authResult = await authenticate(STATE.loginID, true);
    if (!authResult.success) {
      showFlash('flash-status', 'Passkey verification failed', 'failure', 4000);
      return;
    }
    if (authResult.challengeData) {
      updateChallengeDisplay(authResult.challengeData.challenge, authResult.challengeData.signedChallenge);
    }
    updateAuthIcons({ zsm: true, passkeys: true });
    await completeExchange(STATE.loginID, exchange.code);
  } finally {
    btn.classList.remove('loading');
    btn.removeAttribute('aria-busy');
  }
}

/** Leaves the exchange: stops polling and forgets the record and any pending code. */
function endExchange() {
  if (exchange.pollTimer) clearTimeout(exchange.pollTimer);
  Object.assign(exchange, { active: false, role: null, code: null, record: null, pollTimer: null, confirmed: false });
  setPendingExchange('');
  document.getElementById('exchange-qr')?.replaceChildren();
}

/** Draws the QR with the vendored generator, the same way register.js does. */
async function renderExchangeQr(url) {
  const box = document.getElementById('exchange-qr');
  try {
    const { qrcode } = await import('./vendor/qrcode-generator/dist/qrcode.mjs');
    const qr = qrcode(0, 'M');    // 0: smallest version the data fits in
    qr.addData(url);
    qr.make();
    // scalable drops the pixel size so the stylesheet decides how big it
    // prints; the margin is the four-module quiet zone a camera needs.
    box.innerHTML = qr.createSvgTag({ cellSize: 8, margin: 8 * 4, scalable: true });
  } catch (err) {
    console.error('[exchange] QR failed:', err);
    box.textContent = url;
  }
}

/**
 * Puts the exchange on screen. The card shows the OTHER party once the record
 * has both sides; until then the status line says what is being waited on.
 */
function renderExchange({ expired = false, used = false, error = '' } = {}) {
  const $ = (id) => document.getElementById(id);
  const record = exchange.record;
  const initiator = exchange.role === 'initiator';
  const complete = !!(record && record.responder);
  const other = complete ? (initiator ? record.responder : record.initiator) : null;
  const over = complete || expired || used || !!error;
  const awaitingConfirm = !initiator && !exchange.confirmed;

  let title = 'P2P Contact Exchange';
  let status;
  let state;
  if (expired) {
    status = initiator
      ? 'This code expired before anyone scanned it.'
      : 'This QR code has expired. Ask them to tap P2P Contact Exchange again.';
    state = 'failure';
  } else if (used) {
    status = 'This code was already used by someone else.';
    state = 'failure';
  } else if (error) {
    status = `Exchange failed: ${error}`;
    state = 'failure';
  } else if (complete) {
    title = 'Contact received';
    status = initiator
      ? 'Exchange complete. They have your contact too.'
      : `Exchange complete. ${displayName(record.initiator)} has your contact too.`;
    state = 'success';
  } else if (awaitingConfirm) {
    title = 'Confirm sharing contact info';
    status = record
      ? `${displayName(record.initiator)} wants to exchange contact info with you. You will verify with your passkey, then you both see each other's name and phone.`
      : 'Checking this code…';
    state = 'info';
  } else {
    title = initiator ? 'Have them scan this code' : 'Exchanging contacts…';
    status = initiator ? 'Waiting for the other person to confirm…' : 'Sending your contact…';
    state = 'info';
  }

  $('exchange-title').textContent = title;
  $('exchange-status').textContent = status;
  $('exchange-status').className = 'flash ' + state;
  $('exchange-qr-section').hidden = !(initiator && !over);
  // The confirm button appears once the invite knows who is asking; Cancel
  // steps down to secondary beside it and is the only button otherwise.
  const confirmBtn = $('exchange-confirm');
  confirmBtn.hidden = !(awaitingConfirm && !over && !!record);
  $('exchange-done').textContent = over ? 'Done' : 'Cancel';
  $('exchange-done').className = 'btn ' + (confirmBtn.hidden ? 'btn-primary' : 'btn-secondary');

  const card = $('exchange-card');
  card.hidden = !other;
  if (other) {
    $('exchange-name').textContent = other.found ? displayName(other) : 'No contact record';
    $('exchange-phone').textContent = other.found ? formatPhone(other.phone) : '';
    $('exchange-phone').hidden = !other.found;
    $('exchange-userid').textContent = `User ID: ${other.userId}`;
    const photo = $('exchange-photo');
    const hasPhoto = typeof other.photo === 'string' && /^(https?:|data:image\/)/.test(other.photo);
    photo.hidden = !hasPhoto;
    if (hasPhoto) photo.src = other.photo;
    else photo.removeAttribute('src');
  }

  // Off localhost, a Map-backed store means Redis is not wired up yet: the
  // exchange may work on a warm instance and then not, so say so rather
  // than let it look like a bug in the pages.
  const note = $('exchange-note');
  const memoryOffLocalhost = record?.store === 'memory'
    && !['localhost', '127.0.0.1', '[::1]'].includes(location.hostname);
  note.hidden = !memoryOffLocalhost;
  note.textContent = memoryOffLocalhost
    ? 'This deployment has no Redis store, so an exchange can be lost between function instances. Add Upstash Redis to the Vercel project.'
    : '';
}

function displayName(contact) {
  if (!contact) return '';
  const name = `${contact.firstName || ''} ${contact.lastName || ''}`.trim();
  return name || contact.userId || '';
}

/** (913) 555-1235 for a ten-digit number; anything else as stored. */
function formatPhone(value) {
  const text = String(value || '');
  const digits = phoneDigits(text);
  return digits.length === 10 ? `(${digits.slice(0, 3)}) ${digits.slice(3, 6)}-${digits.slice(6)}` : text;
}

// ---------------------------------------------------------------------------
// SNA — simulated Silent Network Authentication (sna.js)
//
// Runs once per device for a User ID: after the ZSM enrollment on an unbound
// device, or on the first login of a device bound before this existed, and
// always before the first ACTIONS screen. An attendee binding a phone sees
// the iShield touch, the passkey enrollment, the number check, then the four
// indicators. The marker sna.js leaves is what later logins check, so a
// cancelled check is asked for again next time and nothing else is lost.
// ---------------------------------------------------------------------------
const SNA_SCENARIO_KEY = 'snaScenario';

/** What the screen says when a scenario fails, by the reason sna.js gives. */
const SNA_FAILURE_MESSAGES = {
  no_match: 'Your network says this number is not on this device.',
  network_unsupported: 'Your network could not verify the number silently. Turn on cellular data and try again.'
};

/**
 * The indicator rows, in order, with what each reads when lit and when not:
 * true/false, as the status pills, except that a missing key marker is
 * 'unknown' (the marker is per device, so its absence proves nothing).
 */
const SNA_INDICATORS = [
  { id: 'ishield', on: 'true', off: 'unknown' },
  { id: 'number', on: 'true', off: 'false' },
  { id: 'device', on: 'true', off: 'false' },
  { id: 'passkey', on: 'true', off: 'false' }
];

let snaResolve = null;     // settles the ensureNumberVerified() promise
let snaAbort = null;       // cancels a check in progress
let snaStepRows = [];      // { row, detail } per SNA_STEPS entry, for the step list
let snaShownCheckId = null;

/** Presenter-only: the ?sna= scenario, consumed by the one run that reads it. */
function takeSnaScenario() {
  const scenario = sessionStorage.getItem(SNA_SCENARIO_KEY);
  sessionStorage.removeItem(SNA_SCENARIO_KEY);
  return SNA_SCENARIOS.includes(scenario) ? scenario : 'success';
}

/**
 * The gate every login path passes before STATE.loginID is set. Resolves
 * true at once when this device already verified the user's number;
 * otherwise puts the SNA screen up and resolves true after a successful
 * check and Continue, false on Cancel.
 */
function ensureNumberVerified(user) {
  if (isNumberVerified(user)) return Promise.resolve(true);
  return new Promise((resolve) => {
    snaResolve = resolve;
    renderSna({ user, phase: 'ready' });
    showScreen('SNA');
    refreshPills(user);  // the enroll has just run; the pills under the card should say so
  });
}

function finishSna(verified) {
  if (snaAbort) {
    snaAbort.abort();
    snaAbort = null;
  }
  const resolve = snaResolve;
  snaResolve = null;
  if (resolve) resolve(verified);
}

/** "Verify my number": plays the simulation and records a match. */
async function runSnaCheck() {
  const user = getUsername();
  if (!user || !snaResolve || snaAbort) return;
  renderSna({ user, phase: 'running' });
  snaAbort = new AbortController();
  try {
    const result = await verifyNumber(user, {
      scenario: takeSnaScenario(),
      signal: snaAbort.signal,
      onStep: renderSnaStep
    });
    if (result.match) {
      setNumberVerified(user, result);
      await refreshPills(user);  // Phone# Verified turns true under the card as well
      await renderSna({ user, phase: 'verified' });
    } else {
      renderSna({ user, phase: 'failed', message: SNA_FAILURE_MESSAGES[result.reason] || 'Number not verified.' });
    }
  } catch (err) {
    if (err.name === 'AbortError') return;
    console.error('[sna] check failed:', err);
    renderSna({ user, phase: 'failed', message: 'Verification failed. Try again.' });
  } finally {
    snaAbort = null;
  }
}

/**
 * Draws the SNA screen for a phase: 'ready' (the invitation), 'running'
 * (the steps playing), 'verified' (steps done, indicators in, Continue) or
 * 'failed' (the failed step stays red, Try again).
 */
async function renderSna({ user, phase, message = '' }) {
  const $ = (id) => document.getElementById(id);
  const verified = phase === 'verified';
  const failed = phase === 'failed';

  $('sna-number').textContent = formatPhone(user);
  $('sna-title').textContent = verified ? 'Number verified' : 'Verify phone number with telco carrier';
  $('sna-subtitle').textContent =
    verified ? 'Your mobile number was verified silently over your network.' :
    phase === 'running' ? 'This takes a few seconds and needs nothing from you.' :
    'Cryptographically guarantee this phone number is operating on this device.';

  if (phase === 'ready' || phase === 'running') buildSnaSteps();
  $('sna-steps').hidden = phase === 'ready';

  const status = $('sna-status');
  status.textContent = verified ? `${formatPhone(user)} Verified` : message;
  status.className = 'flash' + (verified ? ' success' : failed ? ' failure' : '');

  const verify = $('sna-verify');
  verify.hidden = !(phase === 'ready' || failed);
  verify.textContent = failed ? 'Try again' : 'Verify my number';
  $('sna-continue').hidden = !verified;
  $('sna-cancel').hidden = verified;

  $('sna-indicators').hidden = !verified;
  if (verified) {
    renderSnaIndicators(await snaIndicatorStates(user));
    $('sna-continue').focus();
  }
}

/** One pending row per SNA_STEPS entry. */
function buildSnaSteps() {
  snaStepRows = SNA_STEPS.map((step) => {
    const row = document.createElement('li');
    row.className = 'sna-step';
    const mark = document.createElement('span');
    mark.className = 'sna-step-mark';
    const label = document.createElement('span');
    label.className = 'sna-step-label';
    label.textContent = step.label;
    const detail = document.createElement('span');
    detail.className = 'sna-step-detail';
    detail.textContent = step.detail;
    label.appendChild(detail);
    row.append(mark, label);
    return { row, detail };
  });
  document.getElementById('sna-steps').replaceChildren(...snaStepRows.map((entry) => entry.row));
}

/** verifyNumber's onStep: colours the row as the step starts and ends. */
function renderSnaStep(index, step, status) {
  const entry = snaStepRows[index];
  if (!entry) return;
  entry.row.className = `sna-step ${status}`;
  if (status === 'failed' && step.failDetail) entry.detail.textContent = step.failDetail;
}

/** What the four indicators read for this user on this device. */
async function snaIndicatorStates(user) {
  let device = false;
  let passkey = false;
  try {
    await initializeZSMClient(user);
    const status = await checkAllEnrollment(user);
    if (status && !(status instanceof Error)) {
      device = status.hasZSMCred === true || !!status.zsmCredID;
      passkey = status.hasRemotePasskey === true;
    }
  } catch (_) {}
  return { ishield: hasLocalEnrollmentMarker(user), number: isNumberVerified(user), device, passkey };
}

function renderSnaIndicators(states) {
  for (const { id, on, off } of SNA_INDICATORS) {
    const lit = states[id] === true;
    document.getElementById(`sna-ind-${id}`).className = 'sna-indicator ' + (lit ? 'on' : 'off');
    document.getElementById(`sna-ind-${id}-state`).textContent = lit ? on : off;
  }
}

/**
 * The Silent Network Auth block on ACTIONS: the check this device verified
 * the number with, or hidden when there is none. Left alone while the same
 * check is already up, so updateUI does not fold the details every time.
 */
function updateSnaDisplay(record) {
  const PREVIEW_LEN = 15;
  const container = document.getElementById('sna-challenge-display');
  if (!container) return;
  const checkId = record?.checkId || '';
  if (checkId === (snaShownCheckId || '')) {
    container.hidden = !checkId;
    return;
  }
  snaShownCheckId = checkId || null;
  const code = record?.code || '';
  const preview = (value) => value.substring(0, PREVIEW_LEN) + (value.length > PREVIEW_LEN ? '...' : '');
  document.getElementById('sna-check-preview').textContent = checkId ? preview(checkId) : '--';
  document.getElementById('sna-check-full').textContent = checkId;
  document.getElementById('sna-code-preview').textContent = code ? preview(code) : '--';
  document.getElementById('sna-code-full').textContent = code;
  container.hidden = !checkId;
  document.getElementById('sna-check-details')?.removeAttribute('open');
  document.getElementById('sna-code-details')?.removeAttribute('open');
}

// ---------------------------------------------------------------------------
// showScreen — simple screen switcher
// ---------------------------------------------------------------------------
const SCREEN_ANNOUNCEMENTS = {
  'LOGIN': 'Login screen. Enter your user ID and tap Enter Game.',
  'SNA': 'Phone number verification screen. Tap Verify my number.',
  'ACTIONS': 'Actions screen. You are logged in.',
  'EXCHANGE': 'P2P Contact Exchange screen.'
};

function showScreen(screenId) {
  document.querySelectorAll('.screen').forEach(s => {
    s.classList.remove('active');
    s.setAttribute('aria-hidden', 'true');
  });
  const target = document.getElementById(screenId);
  if (target) {
    target.classList.add('active');
    target.setAttribute('aria-hidden', 'false');
  }

  // The User ID can always be changed before logging in. It is read-only
  // once logged in (ACTIONS, or EXCHANGE after the responder has verified)
  // and on SNA (the number being verified is the one on screen). A
  // responder who has only scanned so far can still correct it.
  const loggedInScreen = screenId === 'ACTIONS' || (screenId === 'EXCHANGE' && !!STATE.loginID);
  document.getElementById('username').readOnly = loggedInScreen || screenId === 'SNA';

  // Announce screen change to screen readers
  const announcer = document.getElementById('screen-announcer');
  if (announcer) announcer.textContent = SCREEN_ANNOUNCEMENTS[screenId] || '';
}

// ---------------------------------------------------------------------------
// refreshPills — the five status pills under the card, from what this device
// and the SDK hold for `user`. updateUI draws them on every screen change;
// the SNA screen draws them too, since the enroll has just run when it comes
// up and the number check changes the second pill while it stays up.
// ---------------------------------------------------------------------------
async function refreshPills(user) {
  // The key marker (localStorage — may be absent on Device B)
  const hasIShield = user ? hasLocalEnrollmentMarker(user) : false;

  // ZSM & Passkey status (SDK)
  let hasZSM = false;
  let hasPasskey = false;
  if (user) {
    try {
      await initializeZSMClient(user);
      const status = await checkAllEnrollment(user);
      if (status && !(status instanceof Error)) {
        hasZSM = status.hasZSMCred === true || !!status.zsmCredID;
        hasPasskey = status.hasRemotePasskey === true;
      }
    } catch (_) {}
  }

  function setPill(el, value) {
    el.textContent = value;
    const pill = el.closest('.pill');
    pill.classList.remove('pill-success', 'pill-danger', 'pill-neutral', 'pill-unknown');
    if (value === 'true' || value === 'Active') pill.classList.add('pill-success');
    else if (value === 'false' || value === 'Suspended') pill.classList.add('pill-danger');
    else if (value === 'unknown') pill.classList.add('pill-unknown');
    else pill.classList.add('pill-neutral');
  }

  // The four indicators the enrollment ends on: USB Key (local marker),
  // Phone# Verified (the SNA marker), Device Bound (the ZSM credential),
  // Passkey (the Passkeys+ credential).
  setPill(document.getElementById('ishield-status'), !user ? '--' : (hasIShield ? 'true' : 'unknown'));
  setPill(document.getElementById('number-status'), !user ? '--' : (isNumberVerified(user) ? 'true' : 'false'));
  setPill(document.getElementById('zsm-status'), !user ? '--' : (hasZSM ? 'true' : 'false'));
  setPill(document.getElementById('passkey-status'), !user ? '--' : (hasPasskey ? 'true' : 'false'));

  // Passkeys+ pill — the key is no longer required (credential lives on the key)
  const fullyEnrolled = hasZSM && hasPasskey;
  const suspended = isSuspended(user);
  const ppStatus = !user || !fullyEnrolled ? 'Not Enrolled' : (suspended ? 'Suspended' : 'Active');
  setPill(document.getElementById('passkeys-plus-status'), ppStatus);

  return { hasIShield, hasZSM, hasPasskey, fullyEnrolled, suspended };
}

// ---------------------------------------------------------------------------
// updateUI — detect state and show correct screen + pills
// ---------------------------------------------------------------------------
async function updateUI() {
  const user = getUsername();
  const { fullyEnrolled, suspended } = await refreshPills(user);

  // Suspend button — enabled only when fully enrolled and not already suspended
  document.getElementById('suspend-device').disabled = !(fullyEnrolled && !suspended);

  // Enter Game needs a User ID; its label says when the device is suspended
  const loginBtn = document.getElementById('login-btn');
  loginBtn.disabled = !user;
  loginBtn.textContent = suspended ? 'Reactivate & Enter Game' : 'Enter Game';

  // The Silent Network Auth block on ACTIONS follows the stored check
  updateSnaDisplay(STATE.loginID ? getNumberVerification(STATE.loginID) : null);

  // Determine which screen to show
  if (STATE.loginID) {
    const pendingCode = getPendingExchange();
    if (pendingCode) {
      // The passkey verification that just set loginID is what the scanned
      // exchange was waiting for, so it completes right away.
      completeExchange(STATE.loginID, pendingCode)
        .catch(err => console.error('[exchange] completion failed:', err));
    } else if (exchange.active) {
      showScreen('EXCHANGE');
    } else {
      showScreen('ACTIONS');
    }
    // Load the account once per login; the actions with a cost re-read it themselves.
    if (accountFor !== STATE.loginID) await refreshAccount(STATE.loginID);
  } else if (snaResolve) {
    // A number check is waiting for its Verify or Continue: nothing else
    // moves the screen until it settles.
    showScreen('SNA');
  } else if (exchange.active) {
    // Scanned a P2P QR and not verified yet: the confirm screen stays up
    showScreen('EXCHANGE');
  } else {
    showScreen('LOGIN');
  }
}

// ---------------------------------------------------------------------------
// bindDevice — the steps after the key has vouched for `user` and the guide
// has handed over to the passkey: the ZSM + Passkeys+ enroll (steps 2 and 3
// of the guide, one SDK call), the local key marker, the number check (step
// 4), then the actions screen.
// ---------------------------------------------------------------------------
async function bindDevice(user) {
  showFlash('flash-status', 'Creating your passkey and binding this device...', 'success');
  await initializeZSMClient(user);
  const enrollResult = await enroll(user, true);
  if (!enrollResult || enrollResult === false || enrollResult instanceof Error) {
    showFlash('flash-status', 'Device binding failed', 'failure');
    return false;
  }

  // The local enrollment marker, so the USB Key pill shows 'true'
  localStorage.setItem(ENROLLMENT_MARKER_PREFIX + user, JSON.stringify({
    boundFromRemote: true,
    createdAt: new Date().toISOString()
  }));

  // The simulated SNA number check, ending on the four indicators
  if (!(await ensureNumberVerified(user))) {
    showFlash('flash-status', 'Number not verified. Tap Enter Game to try again.', 'failure', 4000);
    await updateUI();
    return false;
  }

  STATE.loginID = user;
  updateAuthIcons({ ishield: true, zsm: true, passkeys: true });
  showFlash('flash-status', 'Device bound successfully', 'success');
  await updateUI();
  return true;
}

// ---------------------------------------------------------------------------
// login — Enter Game. The passkey alone on a bound device; the USB key only
// the first time (binding) and after a suspension (reactivation). `btn` is
// whichever button started it: Enter Game, or the exchange screen's Confirm.
//
// The device's own state picks the ceremony. A device that holds a ZSM
// credential for the typed User ID and is not suspended goes straight to the
// Passkeys+ authenticate: no key, no dialog. A device with no credential for
// it is walked through the four steps: the guide dialog names them and its
// Start runs the open get (the tap is the user gesture the prompt needs); the
// User ID the key hands back has to be the one in the box (reconcileUserId: a
// different person stops the flow, a different spelling of the same number is
// adopted); a second dialog hands over to the passkey; and bindDevice does
// the ZSM + Passkeys+ enroll and the number check. A suspended device asks
// the key, then reactivates with the passkey, with no dialog.
// ---------------------------------------------------------------------------
async function login(btn = document.getElementById('login-btn')) {
  let user = getUsername();  // replaced by the key's own spelling when the key is asked
  if (!user) return;

  btn.classList.add('loading');
  btn.setAttribute('aria-busy', 'true');
  btn.setAttribute('aria-disabled', 'true');

  try {
    // Step 1: what this device already holds for that user
    await initializeZSMClient(user);
    let hasLocalZSM = false;
    let hasPasskey = false;
    try {
      const status = await checkAllEnrollment(user);
      if (status && !(status instanceof Error)) {
        hasLocalZSM = status.hasZSMCred === true || !!status.zsmCredID;
        hasPasskey = status.hasRemotePasskey === true;
      }
    } catch (_) {}
    const suspended = isSuspended(user);

    // A bound, active device: the passkey alone
    if (hasLocalZSM && !suspended) {
      // Bound without a passkey (a binding from before the passkey was
      // always part of it): enroll one first, behind the same handoff dialog
      if (!hasPasskey) {
        if (await showGuide(PASSKEY_GUIDE) !== 'ok') return;
        showFlash('flash-status', 'Enrolling Passkeys+...', 'success');
        const enrollResult = await enroll(user, true);
        if (!enrollResult || enrollResult === false || enrollResult instanceof Error) {
          showFlash('flash-status', 'Passkeys+ enrollment failed', 'failure');
          return;
        }
        // A device bound before the number check existed gets it here
        if (!(await ensureNumberVerified(user))) {
          await updateUI();
          return;
        }
        STATE.loginID = user;
        updateAuthIcons({ zsm: true, passkeys: true });
        showFlash('flash-status', 'Passkeys+ enrolled successfully', 'success');
        await updateUI();
        return;
      }

      const authResult = await authenticate(user, true);
      if (!authResult.success) {
        showFlash('flash-status', 'Login failed', 'failure');
        return;
      }
      if (authResult.challengeData) {
        updateChallengeDisplay(authResult.challengeData.challenge, authResult.challengeData.signedChallenge);
      }

      // A device bound before the number check existed gets it here; one
      // that has it answers at once.
      if (!(await ensureNumberVerified(user))) {
        await updateUI();
        return;
      }

      STATE.loginID = user;
      updateAuthIcons({ zsm: true, passkeys: true });
      await updateUI();
      return;
    }

    // Step 2: a device with nothing for this User ID sees the guide first:
    // the four steps, and Start, whose tap is what the key prompt needs.
    if (!hasLocalZSM) {
      if (await showGuide(ONBOARDING_GUIDE) !== 'ok') return;
    }

    // Step 3: the key. A discoverable get, so whichever key is present
    // answers with the identity it holds.
    showFlash('flash-status',
      suspended ? 'Device suspended. Touch your USB key to reactivate...' : 'Touch your USB key...',
      'success', 60000);
    const ishieldResult = await webauthnAuthenticate(user);
    if (!ishieldResult.success) {
      showFlash('flash-status',
        ishieldResult.error?.name === 'NotAllowedError'
          ? 'Cancelled, timed out, or nothing on this key for this site yet. Enroll the key on the registration page first.'
          : ishieldResult.error?.message || 'USB key authentication failed',
        'failure', 6000);
      return;
    }
    if (ishieldResult.clientDataHash) {
      updateIShieldChallengeDisplay(ishieldResult.clientDataHash, ishieldResult.signatureHex);
    }

    // Step 4: the User ID on screen has to be the credential the key holds.
    // A different identity stops here; a different spelling of the same
    // number is adopted, so what is on screen is literally what is on the key.
    const confirmed = reconcileUserId(user, ishieldResult.authenticatedUser);
    if (!confirmed) {
      showFlash('flash-status', keyMismatchMessage(user, ishieldResult.authenticatedUser), 'failure', 8000);
      return;
    }
    user = confirmed;
    showFlash('flash-status', 'USB key verified', 'success');

    // An unbound device: hand over to the passkey, then bind (ZSM + Passkeys+)
    if (!hasLocalZSM) {
      if (await showGuide(PASSKEY_GUIDE) !== 'ok') return;
      await bindDevice(user);
      return;
    }

    // A suspended device: the key touch above plus a Passkeys+ authenticate clear it
    showFlash('flash-status', 'Authenticating to complete reactivation...', 'success');
    await initializeZSMClient(user);
    const reactivateResult = await authenticate(user, true);
    if (!reactivateResult.success) {
      showFlash('flash-status', 'Reactivation failed', 'failure');
      return;
    }
    if (reactivateResult.challengeData) {
      updateChallengeDisplay(reactivateResult.challengeData.challenge, reactivateResult.challengeData.signedChallenge);
    }
    setSuspended(user, false);
    STATE.loginID = user;
    updateAuthIcons({ ishield: true, zsm: true, passkeys: true });
    await updateUI();
    showFlash('flash-status', 'Device reactivated', 'success');
  } catch (err) {
    console.error('[login] Error:', err);
    showFlash('flash-status', 'Login failed', 'failure');
  } finally {
    btn.classList.remove('loading');
    btn.removeAttribute('aria-busy');
    btn.removeAttribute('aria-disabled');
  }
}

// ---------------------------------------------------------------------------
// handleProtectedAction
// ---------------------------------------------------------------------------
async function handleProtectedAction(actionKey) {
  const actionLabel = PROTECTED_ACTION_LABELS[actionKey] ?? 'Protected Action';

  if (!STATE.loginID) {
    showFlash('action-status', `${actionLabel} Failed`, 'failure', 2000);
    return;
  }

  const authResult = await authenticate(STATE.loginID, true);

  if (!authResult.success) {
    showFlash('action-status', `${actionLabel} Failed`, 'failure', 2000);
    return;
  }

  if (authResult.challengeData) {
    updateChallengeDisplay(authResult.challengeData.challenge, authResult.challengeData.signedChallenge);
  }
  updateAuthIcons({ zsm: true, passkeys: true });

  // P2P Contact Exchange has its own screen: the step-up above is what
  // authorizes issuing a code, and the exchange takes it from there.
  if (actionKey === 'p2p-contact-exchange') {
    await startExchange(STATE.loginID);
    return;
  }

  // The step-up is what the action protects; an action with a cost then
  // settles against the user database. The other actions are done at this point.
  const amount = ACTION_AMOUNTS[actionKey];
  if (amount === undefined) {
    showFlash('action-status', `${actionLabel} Authorized`, 'success', 2000);
    return;
  }
  showFlash('action-status', `${actionLabel} Authorized, charging ${formatPoints(amount)}...`, 'success', 10000);
  const outcome = await settleAction(STATE.loginID, actionLabel, amount);
  showFlash('action-status', outcome.message, outcome.state, 4000);
}

// ---------------------------------------------------------------------------
// logOut
// ---------------------------------------------------------------------------
async function logOut() {
  endExchange();
  resetClient();
  STATE.reset();
  account = null;
  accountFor = null;
  renderBalance();
  updateChallengeDisplay('--', '--');
  updateAuthIcons();
  await updateUI();
}

// ---------------------------------------------------------------------------
// purgeStorage — Reset Device: everything this device holds goes, except the
// User ID, and the page reloads on its bare path so a ?userid= from the
// registration QR is not read again. It comes back on LOGIN with the User
// ID editable, as it always is before a login.
// ---------------------------------------------------------------------------
function purgeStorage() {
  const username = getUsername();
  localStorage.clear();
  sessionStorage.clear();
  if (username) localStorage.setItem('username', username);
  try { indexedDB.deleteDatabase('ideem'); } catch (_) { /* ignore */ }
  window.location.replace(window.location.pathname);
}

// ---------------------------------------------------------------------------
// suspendDevice — suspend Passkeys+ login, require iShield re-auth
// ---------------------------------------------------------------------------
async function suspendDevice() {
  const user = getUsername();
  if (!user) return;

  if (isSuspended(user)) return;

  const action = await showPopup('Suspend Passkeys+ login? You will need your USB key to reactivate.');
  if (action === 'cancel') return;

  setSuspended(user, true);
  logOut();
  await updateUI();
}

// ---------------------------------------------------------------------------
// DOMContentLoaded — wire up event listeners
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  // Enter Game
  document.getElementById('login-btn').addEventListener('click', () => login());

  // Protected action buttons
  document.querySelectorAll('.btn-action').forEach((btn) => {
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      btn.classList.add('loading');
      btn.setAttribute('aria-busy', 'true');
      btn.setAttribute('aria-disabled', 'true');
      try {
        await handleProtectedAction(btn.dataset.action);
      } finally {
        btn.classList.remove('loading');
        btn.removeAttribute('aria-busy');
        btn.removeAttribute('aria-disabled');
      }
    });
  });

  // Log Out
  document.getElementById('logout-btn').addEventListener('click', () => logOut());

  // Confirm on the exchange screen: the responder's passkey verification
  document.getElementById('exchange-confirm').addEventListener('click', () => confirmExchange());

  // The SNA screen: Verify plays the simulated check, Continue and Cancel
  // settle the gate the login path is waiting on
  document.getElementById('sna-verify').addEventListener('click', () => runSnaCheck());
  document.getElementById('sna-continue').addEventListener('click', () => finishSna(true));
  document.getElementById('sna-cancel').addEventListener('click', () => finishSna(false));

  // Done / Cancel on the exchange screen: back to the actions when logged
  // in, otherwise to the login screen
  document.getElementById('exchange-done').addEventListener('click', async () => {
    endExchange();
    await updateUI();
  });

  // Suspend Device
  document.getElementById('suspend-device').addEventListener('click', () => suspendDevice());

  // Reset Device
  document.getElementById('reset-device').addEventListener('click', () => purgeStorage());

  // Confirmation Popup buttons
  document.getElementById('popup-continue').addEventListener('click', () => hidePopup('continue'));
  document.getElementById('popup-cancel').addEventListener('click', () => hidePopup('cancel'));

  // The guide dialog's one button
  document.getElementById('guide-start').addEventListener('click', () => hideGuide('ok'));

  // Restore username from localStorage
  const savedUsername = localStorage.getItem('username');
  if (savedUsername) {
    document.getElementById('username').value = savedUsername;
  }

  // Auto-populate from URL parameters. ?userid= is what the registration
  // page's QR code carries: the attendee scans it and arrives with their
  // number already in the field, having typed nothing. Enter Game then reads
  // the key, which holds that number, and binds this phone to it.
  const urlParams = new URLSearchParams(window.location.search);
  const urlUserId = urlParams.get('userid');
  if (urlUserId) {
    document.getElementById('username').value = urlUserId;
    localStorage.setItem('username', urlUserId);
  }

  // ?exchange= is what another attendee's P2P QR carries. The code goes to
  // sessionStorage and comes off the address bar, so a reload lands on the
  // same confirm screen while a used code cannot be replayed from history.
  const urlExchange = urlParams.get('exchange');
  if (urlExchange) {
    setPendingExchange(urlExchange.trim().toUpperCase());
    urlParams.delete('exchange');
  }

  // ?sna= is for the presenter: nomatch or unsupported plays that IDlayr
  // outcome on the next number check, once, and the default success returns.
  const urlSna = urlParams.get('sna');
  if (urlSna) {
    sessionStorage.setItem(SNA_SCENARIO_KEY, urlSna.trim().toLowerCase());
    urlParams.delete('sna');
  }

  if (urlExchange || urlSna) {
    const query = urlParams.toString();
    history.replaceState(null, '', location.pathname + (query ? `?${query}` : ''));
  }
  const pendingExchange = getPendingExchange();
  if (pendingExchange) openExchangeInvite(pendingExchange);

  // ?msg= — show flash message from redirect
  const urlMsg = urlParams.get('msg');
  if (urlMsg) {
    showFlash('flash-status', urlMsg, 'success', 6000);
  }

  // Show hint when clicking the read-only username field: the session owns
  // the identity once logged in, and the number check owns it while it runs.
  document.getElementById('username').addEventListener('click', (e) => {
    if (!e.target.readOnly) return;
    showFlash('flash-status',
      STATE.loginID ? 'Log Out to change the User ID' : 'Cancel the number check to change the User ID',
      'failure', 3000);
  });

  // Persist username on input, update button state, and recheck enrollment status
  let usernameTimer = null;
  document.getElementById('username').addEventListener('input', (e) => {
    const user = getUsername();
    localStorage.setItem('username', user);
    document.getElementById('login-btn').disabled = !user;

    if (usernameTimer) clearTimeout(usernameTimer);
    usernameTimer = setTimeout(() => updateUI(), 800);
  });

  // Copy button handlers
  document.querySelectorAll('.btn-copy').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      e.stopPropagation();
      const summary = btn.closest('summary');
      const details = summary?.closest('details');
      const pre = details?.querySelector('.challenge-full');
      const text = pre?.textContent;
      if (text) {
        try {
          await navigator.clipboard.writeText(text);
          const originalHTML = btn.innerHTML;
          btn.textContent = '✓';
          btn.style.opacity = '1';
          btn.style.color = 'var(--color-terminal-value)';
          setTimeout(() => {
            btn.innerHTML = originalHTML;
            btn.style.opacity = '';
            btn.style.color = '';
          }, 1500);
        } catch (err) {
          console.error('Copy failed:', err);
        }
      }
    });
  });

  // Detect existing credentials and show correct screen
  updateUI();
});
