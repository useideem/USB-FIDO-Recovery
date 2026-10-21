/**
 * register.js -- Registration page: write a phone number onto a FIDO USB key
 *
 * One box and one button. The phone number, as bare digits, goes onto the
 * inserted key as a discoverable, PIN-protected credential (key-enroll.js),
 * and the page then shows a QR code and a link that open the main page with
 * that number already in the User ID box. The user's phone takes it from
 * there: the key touch, the number check, the passkey.
 *
 * This is also how a replacement key is made when one is lost: enroll the
 * new key with the same number here, and the main page's "Associate new
 * FIDO key" reads it. The new credential has its own key pair; only the
 * number is the same.
 *
 * There is no database and no SDK here. Nothing leaves the page except the
 * credential record the dev server keeps for the key tester (absent in
 * production).
 *
 * THE BROWSER MATTERS. The create requires user verification, so the browser
 * drives the key's PIN: entering it, or setting one on a key that has none.
 * Safari on a Mac is the measured browser for the create; desktop Chrome
 * insists on a PIN for a discoverable credential anyway, which is now what
 * is asked for, but its PIN setup on the iShield failed in the September
 * tests (docs/ishield-pinless-discoverable.md). Measure before relying on
 * it. The footer names the browser rendering the page.
 */

import { enrollKey, shareEnrollment, detectBrowser, ERROR_HINTS } from './key-enroll.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Where the QR code points when this page is served from localhost, which no
 * phone can reach. The deployment's own origin is used everywhere else, so
 * the code matches the origin the credential's RP ID is bound to. This is the
 * Vercel project's production URL, seen serving on 2026-10-21.
 */
export const PUBLIC_DEMO_ORIGIN = 'https://usb-fido-recovery.vercel.app';

const LOCAL_HOSTNAMES = ['localhost', '127.0.0.1', '[::1]'];

/** How many digits a phone number may have, bare. */
const MIN_DIGITS = 7;
const MAX_DIGITS = 15;

// ---------------------------------------------------------------------------
// Pure helpers (a Node harness can cover these)
// ---------------------------------------------------------------------------

/**
 * Bare digits, with a leading US trunk 1 dropped from an 11-digit number, so
 * "1 (913) 555-1235" and "9135551235" are the same User ID. The main page
 * applies the same rule (phoneDigits in app.js) before comparing the typed
 * number with the one the key hands back.
 */
export function normalizePhone(value) {
  const digits = String(value ?? '').replace(/\D/g, '');
  return digits.length === 11 && digits.startsWith('1') ? digits.slice(1) : digits;
}

/** (913) 555-1235 for a ten-digit number; anything else as stored. */
export function formatPhone(value) {
  const digits = normalizePhone(value);
  return digits.length === 10 ? `(${digits.slice(0, 3)}) ${digits.slice(3, 6)}-${digits.slice(6)}` : String(value ?? '');
}

/**
 * The phone number to enroll, or why it cannot be.
 *
 * @returns {{ok: true, phone: string}|{ok: false, error: string}}
 */
export function validatePhone(value) {
  const phone = normalizePhone(value);
  if (!phone) return { ok: false, error: 'Enter a phone number.' };
  if (phone.length < MIN_DIGITS || phone.length > MAX_DIGITS) {
    return { ok: false, error: `A phone number is ${MIN_DIGITS} to ${MAX_DIGITS} digits.` };
  }
  return { ok: true, phone };
}

/**
 * The URL the QR code carries: the main page with the number as ?userid=,
 * on this origin, or on the deployment when this page is on localhost.
 */
export function registerUrl(phone, origin, hostname) {
  const base = LOCAL_HOSTNAMES.includes(hostname) ? PUBLIC_DEMO_ORIGIN : origin;
  return `${base}/?userid=${encodeURIComponent(phone)}`;
}

/** The first characters of a credential id, enough to tell keys apart on screen. */
export function shortId(id) {
  const text = String(id ?? '');
  return text.length > 16 ? `${text.slice(0, 16)}…` : text;
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

const $ = (id) => document.getElementById(id);

let flashTimer = null;

function showFlash(message, state, duration = 6000) {
  const el = $('flash-status');
  el.textContent = message;
  el.className = 'flash ' + state;
  if (flashTimer) clearTimeout(flashTimer);
  if (duration > 0) {
    flashTimer = setTimeout(() => { el.textContent = ''; el.className = 'flash'; }, duration);
  }
}

/**
 * Enroll Key: the key-enroll.js create for the number in the box, then the
 * warnings the key earned, what it did, and the hand-off code.
 */
async function enrollInsertedKey() {
  const check = validatePhone($('phone').value);
  if (!check.ok) {
    showFlash(check.error, 'failure');
    $('phone').focus();
    return;
  }
  const { phone } = check;
  $('phone').value = phone;

  const btn = $('enroll-btn');
  btn.classList.add('loading');
  btn.disabled = true;
  $('enroll-warnings').replaceChildren();
  $('enroll-result').hidden = true;
  $('qr-section').hidden = true;
  showFlash('Insert the FIDO key. Enter its PIN and touch it when the browser asks...', 'info', 0);

  let result;
  try {
    result = await enrollKey({ phone, displayName: formatPhone(phone) });
  } catch (err) {
    const hint = ERROR_HINTS[err.name] ? ` ${ERROR_HINTS[err.name]}` : '';
    showFlash(`${err.name}: ${err.message}${hint}`, 'failure', 12000);
    return;
  } finally {
    btn.classList.remove('loading');
    btn.disabled = false;
  }

  shareEnrollment(result.entry, result.rpId);
  $('enroll-warnings').replaceChildren(...result.warnings.map(text => {
    const p = document.createElement('p');
    p.className = 'en-warning';
    p.textContent = text;
    return p;
  }));
  renderResult(result.entry);
  btn.textContent = 'Enroll another key';
  showFlash(result.ok ? `FIDO key enrolled for ${formatPhone(phone)}` : 'Key enrolled, but check the warnings', result.ok ? 'success' : 'failure');
  await showQr(phone);
}

/** What the key did: the credential it made and whether the PIN was used. */
function renderResult(entry) {
  $('result-phone').textContent = `${formatPhone(entry.phone)} (${entry.phone})`;
  $('result-credential').textContent = shortId(entry.id);
  $('result-credential').title = entry.id;
  $('result-uv').textContent = entry.uvAtCreate === true ? 'yes' : entry.uvAtCreate === false ? 'no' : 'unknown';
  $('result-when').textContent = new Date(entry.createdAt).toLocaleString();
  $('enroll-result').hidden = false;
}

/**
 * Draws the scan-to-open code. The generator is vendored and loaded on
 * demand, so if it is missing the link is still shown.
 */
async function showQr(phone) {
  const url = registerUrl(phone, location.origin, location.hostname);
  $('qr-link').textContent = url;
  $('qr-link').href = url;

  // A credential is bound to the RP ID it was created under, so a key enrolled
  // on localhost is useless to the deployment the QR opens. Say so here rather
  // than let it surface as a key that mysteriously will not work.
  const sameOrigin = url.startsWith(location.origin + '/');
  $('qr-note').textContent = sameOrigin ? '' :
    `This page is running on ${location.origin}, so the credential just written belongs to ${location.hostname}. `
    + 'The QR opens the deployment instead, where that credential does not exist. Enroll from the deployment itself for a key the scanned page can use.';
  $('qr-note').hidden = sameOrigin;

  try {
    const { qrcode } = await import('./vendor/qrcode-generator/dist/qrcode.mjs');
    const qr = qrcode(0, 'M');    // 0: smallest version the data fits in
    qr.addData(url);
    qr.make();
    // Geometry only; nothing from the number reaches the markup.
    $('qr-code').innerHTML = qr.createSvgTag({ cellSize: 8, margin: 8 * 4, scalable: true });
    $('qr-code').hidden = false;
  } catch (err) {
    console.error('[register] QR generator failed:', err);
    $('qr-code').replaceChildren();
    $('qr-code').hidden = true;
  }

  $('qr-section').hidden = false;
  $('qr-section').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/** Names the browser in the footer, with a word for desktop Chrome. */
async function showBrowserInfo() {
  const { label, chromium, desktop } = await detectBrowser();
  $('browser-info').textContent = `Browser: ${label}` + (chromium && desktop
    ? '. Desktop Chrome sets the key\'s PIN itself when the key has none; if that fails, enroll in Safari.'
    : '');
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', () => {
  $('enroll-form').addEventListener('submit', (e) => {
    e.preventDefault();
    enrollInsertedKey();
  });

  if (!navigator.credentials?.create) {
    $('enroll-btn').disabled = true;
    showFlash('This browser has no WebAuthn support, so it cannot write a key.', 'failure', 0);
  }

  showBrowserInfo();
});
