/**
 * partner.js -- A partner booth: unlock with the shared password, pick the
 * partner, identify an attendee by their FIDO key, then move points on
 * their account
 *
 * The page opens locked. The one password every booth shares (PARTNER_PASSWORD,
 * in plain text below: this is a demo, not a secret) sets a flag in
 * localStorage so the booth's device stays unlocked across reloads; Lock in
 * the footer clears it. A strip of partner tiles sits at the top of the card;
 * the chosen one is highlighted, remembered in localStorage, and can be preset
 * with ?partner=<id> so each booth gets its own link. Nothing about the
 * partner is sent anywhere: the user API has no field for it, so the choice
 * only decides which preset buttons appear and how the flash names the move.
 * Once a tile is tapped the strip hides and the chosen partner's icon and
 * name stand in for it, with a Change link that brings the strip back.
 *
 * The three refreshment booths (selfService in PARTNERS: Ice Cream, Popcorn,
 * Oxygen) are self-service: one button, Identify and Award Points, runs the
 * same get and lookup, shows the attendee's first name, last name and phone
 * number with a QR code of the demo site (LEADERBOARD_QR_URL) and the line
 * "View the leaderboard on your phone", and credits the partner's single
 * preset.
 *
 * Identify runs the demo's open get (webauthnIdentify in ishield.js: empty
 * allowCredentials, userVerification discouraged, the security-key hint), so
 * whatever discoverable credential the key holds for this site answers and
 * hands back its user handle: the phone number register.html wrote there, as
 * bare digits. The page looks that number up in the user database and shows
 * the account, in points, with the partner's preset buttons (PARTNERS: +10,
 * +30, +70 for the three sponsors, +50 for Ice Cream, Popcorn and Oxygen)
 * and the two Custom buttons that take whatever is typed in the box:
 *
 *   Add Custom Credit / Cash Out   + Custom   the amount typed in the box
 *   Deduct Custom Credit / Buy In  - Custom   the same amount, negative
 *
 * Each press is one PATCH /users/:id/balance (docs/user-api.md section 3a).
 * The API ADDS what it is sent and rounds to cents, so a deduction is a
 * negative amount. It also allows an overdraft, so this page refuses a
 * deduction the balance cannot cover, the rule app.js applies to a charge.
 * A PATCH that fails is never retried (there is no idempotency key, and a
 * slow one may have landed): the record is re-read and the balance shown is
 * whatever the server now holds. The record is read by bare-digit phone and
 * the PATCH goes by userId, never by phone, since duplicate numbers are
 * possible. The balance is points on this page and on the demo page (app.js),
 * which charges its actions from the same field.
 *
 * BROWSERS: the open get is what phones do (iOS in any browser, Android
 * Chrome 128+) and Safari on a Mac. Desktop Chrome refuses it for a PIN-less
 * key, so the page says so up front, as register.html does for the create.
 *
 * The helpers (checkPassword, findPartner, partnerFromSearch, formatPoints,
 * formatBalance, presetLabel, userIdFromHandle, describeGetError, parseAmount,
 * findUserByPhone, adjustBalance, fullName, formatPhone) are pure or take a
 * fetch, so a
 * Node harness can cover them; the module's top level only registers a
 * DOMContentLoaded listener.
 */

import { webauthnIdentify } from './ishield.js';
import { detectBrowser } from './key-enroll.js';

const DB_BASE = './db';

/** The password every booth shares. Hard-coded on purpose: the demo needs a gate, not security. */
export const PARTNER_PASSWORD = 'Passkeys2026';

/** localStorage keys: the unlocked flag, and the id of the chosen partner. */
export const UNLOCKED_KEY = 'partner_unlocked';
export const PARTNER_KEY = 'partner_booth';

/**
 * The partners, in strip order. `presets` are the fixed buttons, in points,
 * signed: positive adds, negative would deduct (none does today; a negative
 * entry draws red and goes through the overdraft check). A tile whose icon
 * file is missing shows the name alone.
 */
export const PARTNERS = [
  { id: 'rsa',      name: 'RSA',       icon: './partners/rsa.png',       presets: [10, 30, 70] },
  { id: 'swissbit', name: 'Swissbit',  icon: './partners/swissbit.png',  presets: [10, 30, 70] },
  { id: 'hid',      name: 'HID',       icon: './partners/hid.png',       presets: [10, 30, 70] },
  { id: 'icecream', name: 'Ice Cream', icon: './partners/ice-cream.svg', presets: [50], selfService: true },
  { id: 'popcorn',  name: 'Popcorn',   icon: './partners/popcorn.svg',   presets: [50], selfService: true },
  { id: 'oxygen',   name: 'Oxygen',    icon: './partners/oxygen.svg',    presets: [50], selfService: true }
];

/** What the QR code on a self-service booth opens: the demo site, where View Leaderboard lives. */
export const LEADERBOARD_QR_URL = 'https://authenticate26.vercel.app';

/** The most a Custom button will send in one press, in points. */
export const MAX_AMOUNT = 1000000;

const pointsFormat = new Intl.NumberFormat('en-US', { maximumFractionDigits: 2 });

/** "12.5 pts", "50 pts": every amount on this page. */
export function formatPoints(n) {
  return `${pointsFormat.format(n)} pts`;
}

const wholePointsFormat = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });

/**
 * "1,030 pts": the balance, whole points only (the owner's rule, 2026-10-14),
 * rounded down so the screen never shows a point the record does not hold.
 */
export function formatBalance(n) {
  return `${wholePointsFormat.format(Math.floor(n))} pts`;
}

/** The face of a preset button: "+30", "-50". */
export function presetLabel(amount) {
  return `${amount < 0 ? '-' : '+'}${pointsFormat.format(Math.abs(amount))}`;
}

/** True for the partner password, exactly as typed (no trimming: a stray space is a wrong password). */
export function checkPassword(text) {
  return String(text ?? '') === PARTNER_PASSWORD;
}

/** The partner with this id, case-insensitively, or null. */
export function findPartner(id) {
  const key = String(id ?? '').trim().toLowerCase();
  return PARTNERS.find(p => p.id === key) ?? null;
}

/** The partner a ?partner=<id> query names, or null when there is none or it is unknown. */
export function partnerFromSearch(search) {
  return findPartner(new URLSearchParams(search).get('partner'));
}

/** What a failed get usually means, by DOMException name. */
export const GET_ERROR_HINTS = {
  NotAllowedError: 'Cancelled, timed out, no key inserted, or the browser refused the open query. Desktop Chrome does that for a PIN-less key: use a phone, or Safari on a Mac.',
  SecurityError: 'The RP ID is not valid for this origin. Open the page over HTTPS or http://localhost, not an IP address.',
  NotSupportedError: 'This browser cannot run a get without a credential list.',
  AbortError: 'The operation was aborted.'
};

/** E.164 allows 15 digits; 7 is the shortest number worth treating as one (as register.js). */
const MIN_DIGITS = 7;
const MAX_DIGITS = 15;

/**
 * The User ID a key's user handle stands for. register.html writes bare
 * digits, and a handle that reads as a phone number comes back in that form
 * whatever its spelling (the rule phoneDigits in app.js applies: strip
 * non-digits, drop a leading US 1 from 11). Any other non-empty handle is
 * passed through trimmed, since that is what the key vouches for; an empty
 * or missing handle gives null.
 */
export function userIdFromHandle(handle) {
  const text = String(handle ?? '').trim();
  if (!text) return null;
  const stripped = text.replace(/\D/g, '');
  const digits = stripped.length === 11 && stripped.startsWith('1') ? stripped.slice(1) : stripped;
  const phoneLike = /^[\d\s().+-]+$/.test(text) && digits.length >= MIN_DIGITS && digits.length <= MAX_DIGITS;
  return phoneLike ? digits : text;
}

/** One line for a failed get: the DOMException name and what it usually means. */
export function describeGetError(err) {
  const name = err?.name || 'Error';
  const hint = GET_ERROR_HINTS[name];
  if (hint) return `${name}. ${hint}`;
  return err?.message || 'The key could not be read.';
}

/**
 * A typed amount as a positive number of points rounded to two decimals, or
 * null when it is not one: blank, zero, negative, more than two decimals, not
 * a number, or above MAX_AMOUNT. A leading $ and thousands separators in the
 * right places ("1,250.50") are tolerated; a comma anywhere else is not.
 */
export function parseAmount(text) {
  const cleaned = String(text ?? '').trim().replace(/^\$/, '');
  if (!/^((\d{1,3}(,\d{3})+|\d+)(\.\d{0,2})?|\.\d{1,2})$/.test(cleaned)) return null;
  const value = Math.round(Number(cleaned.replace(/,/g, '')) * 100) / 100;
  return value > 0 && value <= MAX_AMOUNT ? value : null;
}

/**
 * Looks a user up by phone number. The API matches the stored string exactly
 * and answers with an array, so bare digits in, first element out. The same
 * function as in register.js.
 *
 * @returns {Promise<object|null>} The record, or null when there is none.
 */
export async function findUserByPhone(phone, fetchImpl = fetch) {
  const res = await fetchImpl(`${DB_BASE}/users/phone/${encodeURIComponent(phone)}`, { cache: 'no-store' });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`lookup returned ${res.status}`);
  const body = await res.json();
  return Array.isArray(body) ? body[0] ?? null : body;
}

/**
 * Moves the balance by `amount` through PATCH /users/:id/balance. The API
 * ADDS the amount it is sent (a deduction is a negative number), rounds to
 * cents, and will take the balance below zero without complaint, so the
 * overdraft check lives in the caller, not here. It is also not idempotent:
 * a timed-out request may have applied, so the caller must never retry.
 * The same function as in app.js.
 *
 * @returns {Promise<number>} The balance the server now holds.
 */
export async function adjustBalance(userId, amount, fetchImpl = fetch) {
  const res = await fetchImpl(`${DB_BASE}/users/${encodeURIComponent(userId)}/balance`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ amount })
  });
  if (!res.ok) throw new Error(`balance update returned ${res.status}`);
  const body = await res.json();
  return Number(body.user?.balance ?? body.balance);
}

/** "Ada Lovelace", or a note when the record has no name. */
export function fullName(record) {
  const name = [record?.firstName, record?.lastName].map(s => String(s || '').trim()).filter(Boolean).join(' ');
  return name || 'name not on record';
}

/** (913) 555-1235 for a ten-digit number; anything else as given. The rule register.js and app.js apply. */
export function formatPhone(value) {
  const text = String(value || '');
  const digits = userIdFromHandle(text) ?? '';
  return /^\d{10}$/.test(digits) ? `(${digits.slice(0, 3)}) ${digits.slice(3, 6)}-${digits.slice(6)}` : text;
}

// ---------------------------------------------------------------------------
// Page glue
// ---------------------------------------------------------------------------

const $ = id => document.getElementById(id);
let flashTimer = null;

/** The identified account: { phone, userId, balance }, or null before a key has answered. */
let account = null;

/** The chosen partner (one of PARTNERS), or null until a tile is tapped. */
let partner = null;

/** The preset buttons drawn for `partner`, so a balance move can disable them. */
let presetButtons = [];

/** True while a PATCH is in flight: every balance button is disabled, including ones drawn meanwhile. */
let busy = false;

/** localStorage, tolerated absent (private mode, blocked storage): the page then forgets on reload. */
function stored(key) {
  try { return localStorage.getItem(key); } catch { return null; }
}

function store(key, value) {
  try {
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch { /* nothing to do: the choice lasts for this page only */ }
}

function showFlash(message, state, duration = 6000) {
  const el = $('flash-status');
  clearTimeout(flashTimer);
  el.textContent = message;
  el.className = 'flash ' + state;
  if (duration) {
    flashTimer = setTimeout(() => { el.textContent = ''; el.className = 'flash'; }, duration);
  }
}

function setBusy(on) {
  busy = on;
  for (const btn of [...presetButtons, $('add-custom-btn'), $('deduct-custom-btn')]) btn.disabled = on;
}

// ---- the gate ----

/** Locked shows the password form alone; unlocked shows the booth and the Lock link. */
function showGate(locked) {
  $('gate-section').hidden = !locked;
  $('booth').hidden = locked;
  $('lock-link').hidden = locked;
}

/** The password form's submit: the right password unlocks this device until Lock. */
function unlock(event) {
  event.preventDefault();
  const input = $('gate-password');
  if (!checkPassword(input.value)) {
    input.value = '';
    input.focus();
    showFlash('That is not the partner password.', 'failure');
    return;
  }
  input.value = '';
  store(UNLOCKED_KEY, '1');
  showGate(false);
  showFlash(partner ? `Unlocked. This is the ${partner.name} booth.` : 'Unlocked. Choose the partner.', 'success');
}

/** Lock: forget the flag, drop whatever account was on screen, back to the form. */
function lock() {
  store(UNLOCKED_KEY, null);
  account = null;
  $('account-section').hidden = true;
  $('award-result').hidden = true;
  $('custom-amount').value = '';
  showGate(true);
  $('gate-password').focus();
}

// ---- the partner strip ----

/** One tile per partner: icon over name, a radio in all but markup. */
function renderStrip() {
  const strip = $('partner-strip');
  const tiles = PARTNERS.map(p => {
    const tile = document.createElement('button');
    tile.type = 'button';
    tile.className = 'pt-tile';
    tile.dataset.partner = p.id;
    tile.setAttribute('role', 'radio');
    tile.setAttribute('aria-checked', 'false');
    const img = document.createElement('img');
    img.src = p.icon;
    img.alt = '';
    img.addEventListener('error', () => { img.hidden = true; });
    const name = document.createElement('span');
    name.className = 'pt-tile-name';
    name.textContent = p.name;
    tile.appendChild(img);
    tile.appendChild(name);
    tile.addEventListener('click', () => selectPartner(p.id));
    return tile;
  });
  strip.replaceChildren(...tiles);
}

/**
 * Makes `id` the current partner (none when it is null or unknown),
 * remembers it, drops whatever attendee was on screen and redraws the booth.
 */
function selectPartner(id) {
  partner = findPartner(id);
  store(PARTNER_KEY, partner ? partner.id : null);
  account = null;
  $('account-section').hidden = true;
  $('award-result').hidden = true;
  for (const tile of $('partner-strip').children) {
    const on = !!partner && tile.dataset.partner === partner.id;
    tile.classList.toggle('selected', on);
    tile.setAttribute('aria-checked', String(on));
  }
  renderBooth();
}

/**
 * The booth for the chosen partner. Until one is chosen only the strip
 * shows. Once chosen the strip hides, the partner's icon and name take its
 * place with a Change link, and either the sponsor flow (Identify, the
 * account, presets and custom moves) or the self-service flow (one button)
 * appears.
 */
function renderBooth() {
  const chosen = !!partner;
  $('partners-section').hidden = chosen;
  $('partner-chosen').hidden = !chosen;
  $('identify-section').hidden = !chosen || !!partner.selfService;
  $('self-section').hidden = !chosen || !partner.selfService;
  if (!chosen) return;
  $('chosen-icon').src = partner.icon;
  $('chosen-name').textContent = partner.name;
  $('presets-title').textContent = `${partner.name} points`;
  renderPresets();
}

/** The partner's fixed buttons: green adds, red deducts, each one PATCH of its amount. */
function renderPresets() {
  presetButtons = partner.presets.map(amount => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `btn pt-btn ${amount < 0 ? 'pt-btn-deduct' : 'pt-btn-credit'}`;
    btn.textContent = presetLabel(amount);
    btn.disabled = busy;
    btn.addEventListener('click', () => adjust(partner.name, amount));
    return btn;
  });
  $('presets').replaceChildren(...presetButtons);
}

// ---- the account ----

/** Draws the account block for `userId`; a null record means no account on file. */
function renderAccount(userId, record) {
  $('account-user').textContent = userId;
  $('account-name').textContent = record ? fullName(record) : '--';
  $('account-balance').textContent = record ? formatBalance(Number(record.balance)) : '--';
  $('moves').hidden = !record;
  $('account-note').textContent = record ? '' : 'No account has this number. Register it on the registration page first.';
  $('account-note').hidden = !!record;
  $('account-section').hidden = false;
}

/**
 * Identify: the open get, the User ID off the handle, the record behind it.
 * A failure of any kind stays on this page with the reason in the flash.
 */
async function identify() {
  const btn = $('identify-btn');
  account = null;
  $('account-section').hidden = true;
  btn.disabled = true;
  btn.classList.add('loading');
  showFlash('Insert the FIDO key and touch it when the browser asks...', 'info', 60000);
  try {
    const result = await webauthnIdentify();
    if (!result.success) {
      showFlash(describeGetError(result.error), 'failure', 12000);
      return;
    }
    const userId = userIdFromHandle(result.authenticatedUser);
    if (!userId) {
      showFlash('The key answered, but its credential carries no User ID. Enroll it on the registration page first.', 'failure', 12000);
      return;
    }

    showFlash(`Identified ${userId}. Looking the account up...`, 'info', 60000);
    let record;
    try {
      record = await findUserByPhone(userId);
    } catch (err) {
      showFlash(`Identified ${userId}, but the user database did not answer (${err.message}).`, 'failure', 12000);
      return;
    }
    if (record) account = { phone: userId, userId: record.userId, balance: Number(record.balance) };
    renderAccount(userId, record);
    $('custom-amount').value = '';
    btn.textContent = 'Identify another key';
    showFlash(record ? `${fullName(record)} identified` : `Identified ${userId}: no account on file`, record ? 'success' : 'failure');
    $('account-section').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } finally {
    btn.disabled = false;
    btn.classList.remove('loading');
  }
}

// ---- the self-service booths ----

/** Draws the QR code with the vendored generator, as the demo and registration pages do. */
async function renderQr(box, url) {
  try {
    const { qrcode } = await import('./vendor/qrcode-generator/dist/qrcode.mjs');
    const qr = qrcode(0, 'M');    // 0: the smallest version the data fits in
    qr.addData(url);
    qr.make();
    box.innerHTML = qr.createSvgTag({ cellSize: 8, margin: 8 * 4, scalable: true });
  } catch (err) {
    console.error('[partner] QR failed:', err);
    box.textContent = url;
  }
}

/** The attendee's card on a self-service booth: name and number, then the QR code and its line when there is a record. */
async function renderAward(userId, record) {
  $('award-first').textContent = String(record?.firstName || '').trim() || '--';
  $('award-last').textContent = String(record?.lastName || '').trim() || '--';
  $('award-phone').textContent = formatPhone(record?.phone || userId);
  $('award-note').textContent = record ? '' : 'No account has this number. Register it on the registration page first.';
  $('award-note').hidden = !!record;
  $('award-qr').hidden = !record;
  $('award-message').hidden = !record;
  $('award-result').hidden = false;
  if (record) await renderQr($('award-qr'), LEADERBOARD_QR_URL);
}

/**
 * Identify and Award Points: the same get and lookup as Identify, then the
 * attendee's card and the partner's single preset credited through adjust,
 * whose flash reports the new balance. Nothing stops a second press from
 * crediting again.
 */
async function identifyAndAward() {
  const btn = $('award-btn');
  account = null;
  $('award-result').hidden = true;
  btn.disabled = true;
  btn.classList.add('loading');
  showFlash('Insert your FIDO key and touch it when the browser asks...', 'info', 60000);
  try {
    const result = await webauthnIdentify();
    if (!result.success) {
      showFlash(describeGetError(result.error), 'failure', 12000);
      return;
    }
    const userId = userIdFromHandle(result.authenticatedUser);
    if (!userId) {
      showFlash('The key answered, but its credential carries no User ID. Enroll it on the registration page first.', 'failure', 12000);
      return;
    }

    showFlash(`Identified ${userId}. Looking the account up...`, 'info', 60000);
    let record;
    try {
      record = await findUserByPhone(userId);
    } catch (err) {
      showFlash(`Identified ${userId}, but the user database did not answer (${err.message}).`, 'failure', 12000);
      return;
    }
    await renderAward(userId, record);
    if (!record) {
      showFlash(`Identified ${userId}: no account on file`, 'failure', 8000);
      return;
    }
    account = { phone: userId, userId: record.userId, balance: Number(record.balance) };
    await adjust(partner.name, partner.presets[0]);
  } finally {
    btn.disabled = false;
    btn.classList.remove('loading');
  }
}

/** Re-reads the balance after a PATCH whose outcome is unknown. Never retries. */
async function rereadBalance() {
  try {
    const record = await findUserByPhone(account.phone);
    if (record) {
      account.balance = Number(record.balance);
      $('account-balance').textContent = formatBalance(account.balance);
    }
  } catch (err) {
    console.warn('[partner] re-read failed:', err.message);
  }
}

/**
 * One balance move for the identified account. `amount` is signed: positive
 * adds, negative deducts, and a deduction the balance cannot cover is refused
 * here because the API would not refuse it. `label` names the move in the
 * flash: the partner for a preset, "<partner> custom credit" for the box.
 */
async function adjust(label, amount) {
  if (!account || busy) return;
  const magnitude = Math.abs(amount);
  if (amount < 0 && account.balance < magnitude) {
    showFlash(`${label} declined: ${formatPoints(magnitude)} exceeds the balance of ${formatBalance(account.balance)}.`, 'failure', 8000);
    return;
  }
  setBusy(true);
  showFlash(`${label}: ${amount < 0 ? 'deducting' : 'adding'} ${formatPoints(magnitude)}...`, 'info', 60000);
  try {
    account.balance = await adjustBalance(account.userId, amount);
    $('account-balance').textContent = formatBalance(account.balance);
    showFlash(`${label}: ${formatPoints(magnitude)} ${amount < 0 ? 'deducted' : 'added'}. Balance is now ${formatBalance(account.balance)}.`, 'success', 8000);
  } catch (err) {
    // The PATCH may or may not have landed. Re-read rather than retry, so a
    // slow server never applies it twice.
    console.error('[partner] balance update failed:', err.message);
    await rereadBalance();
    showFlash(`${label} may not have gone through (${err.message}). The balance shown is what the server holds now.`, 'failure', 12000);
  } finally {
    setBusy(false);
  }
}

/** The Custom amount box as a number, or null after telling the user what is wrong with it. */
function customAmount(label) {
  const amount = parseAmount($('custom-amount').value);
  if (amount === null) {
    showFlash(`${label}: enter a positive amount, up to ${formatPoints(MAX_AMOUNT)}, in the Custom amount box first.`, 'failure', 8000);
    $('custom-amount').focus();
  }
  return amount;
}

/** Names the browser in the footer and warns in desktop Chrome, where the open get fails. */
async function showBrowserInfo() {
  const { label, chromium, desktop } = await detectBrowser();
  $('browser-info').textContent = `Browser: ${label}`;
  $('chrome-warning').hidden = !(chromium && desktop);
}

document.addEventListener('DOMContentLoaded', () => {
  $('gate-form').addEventListener('submit', unlock);
  $('lock-link').addEventListener('click', event => { event.preventDefault(); lock(); });

  // The strip, then the partner: ?partner=<id> wins, is remembered, and comes
  // off the address bar; otherwise the remembered one; otherwise the first.
  renderStrip();
  const fromUrl = partnerFromSearch(location.search);
  if (fromUrl) {
    store(PARTNER_KEY, fromUrl.id);
    const url = new URL(location.href);
    url.searchParams.delete('partner');
    history.replaceState(null, '', url);
  }
  selectPartner(stored(PARTNER_KEY));
  showGate(stored(UNLOCKED_KEY) !== '1');
  $('change-partner').addEventListener('click', event => { event.preventDefault(); selectPartner(null); });

  $('identify-btn').addEventListener('click', () => identify());
  $('award-btn').addEventListener('click', () => identifyAndAward());
  if (!window.PublicKeyCredential) {
    for (const btn of [$('identify-btn'), $('award-btn')]) {
      btn.disabled = true;
      btn.textContent = 'This browser has no WebAuthn support';
    }
  }

  $('add-custom-btn').addEventListener('click', () => {
    const label = `${partner.name} custom credit`;
    const amount = customAmount(label);
    if (amount !== null) adjust(label, amount);
  });
  $('deduct-custom-btn').addEventListener('click', () => {
    const label = `${partner.name} custom deduction`;
    const amount = customAmount(label);
    if (amount !== null) adjust(label, -amount);
  });

  showBrowserInfo();
});
