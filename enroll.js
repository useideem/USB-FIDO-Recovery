/**
 * enroll.js -- Booth enrollment: put an attendee's phone number on an iShield Key
 *
 * Takes a first name, last name and phone number, then writes a DISCOVERABLE
 * credential to the inserted Swissbit iShield Key 2 Pro with the phone number
 * as user.id. Later, on any other device, a get with an empty
 * allowCredentials list makes the key hand that phone number back after a
 * touch -- no PIN, no account picker, nothing typed.
 *
 * WHY THESE OPTIONS (all measured on the key, see
 * docs/ishield-pinless-discoverable.md):
 *   - residentKey: 'required'            the key must store the credential and
 *                                        the user handle, or an empty-list get
 *                                        can never find it
 *   - userVerification: 'discouraged'    touch only; the retrieval devices are
 *                                        strangers' phones, so no PIN entry
 *   - credentialProtectionPolicy:        level 1, sent WITHOUT
 *     'userVerificationOptional'         enforceCredentialProtectionPolicy --
 *                                        Chrome rejects that combination as
 *                                        inconsistent (NotSupportedError).
 *                                        Without it the browser picks a level
 *                                        that hides the credential from a
 *                                        PIN-less empty-list get.
 *   - hints: ['security-key']            WebAuthn L3: skip the platform passkey
 *                                        UI and go straight to the USB key.
 *                                        Advisory, and needs Chrome 128+.
 *   - authenticatorAttachment:           roaming key, never Touch ID
 *     'cross-platform'
 *   - attestation: 'none'                nothing here checks a metadata
 *                                        statement, so don't ask for one
 *
 * RUN THIS IN SAFARI ON A MAC. Desktop Chrome refuses to create a
 * discoverable credential until the key has a PIN, and once the key has a
 * PIN every retrieval device demands it -- which kills the demo.
 *
 * WHAT THE KEY CARRIES AWAY: only the phone number (user.id) and the name
 * shown in a picker (user.name / user.displayName). A get only ever returns
 * the user handle, so the name lives in the user database instead, keyed by
 * that same phone number -- which is how the retrieval device turns a touch
 * into "Toby Rush, $1,250.50".
 *
 * PHONE NUMBERS ARE BARE DIGITS everywhere: on the key, in the database, and
 * in the lookup. The API matches the stored string exactly, so one canonical
 * form is the only thing that works. Format it for display if you like.
 *
 * ONCE THE KEY AND THE DATABASE BOTH AGREE, the page shows a QR code pointing
 * at the demo with ?userid=<digits>. app.js reads that parameter into the User
 * ID field on load, so the attendee's own phone opens the demo knowing which
 * account it is looking at, with nothing typed.
 *
 * STORAGE:
 *   localStorage 'ishield_enrollments' -- one record per credential created
 *   here. Clearing it removes nothing from the key.
 */

import { bufferToBase64url, base64urlToBuffer } from './ishield.js';
import {
  CRED_PROTECT_LEVELS,
  parseAuthenticatorData,
  checkCeremony
} from './webauthn-util.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** localStorage key holding the array of enrollment records. */
const STORAGE_KEY = 'ishield_enrollments';

/** How long the browser waits for a key touch before failing. */
const TIMEOUT_MS = 120000;

const RP_NAME = 'Demo Swissbit';

/** COSE algorithm identifiers offered at create time, in preference order. */
const COSE_ALGORITHMS = { [-7]: 'ES256', [-8]: 'EdDSA', [-257]: 'RS256' };
const PUB_KEY_CRED_PARAMS = [-7, -8, -257].map(alg => ({ type: 'public-key', alg }));

/** E.164 allows 15 digits; 7 is the shortest number worth accepting. */
const MIN_DIGITS = 7;
const MAX_DIGITS = 15;

/** Friendlier explanations for the DOMException names WebAuthn throws. */
const ERROR_HINTS = {
  NotAllowedError: 'Cancelled, timed out, or the key refused. In desktop Chrome this is also what a discoverable credential without a PIN looks like.',
  InvalidStateError: 'This key already holds a credential for that phone number. It is already enrolled.',
  SecurityError: 'The RP ID is not valid for this origin. Open the page over HTTPS or http://localhost, not an IP address.',
  NotSupportedError: 'The key supports none of the requested algorithms or options.',
  ConstraintError: 'The key cannot store a discoverable credential under these settings.',
  AbortError: 'The operation was aborted.'
};

let flashTimer;

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

function loadEnrollments() {
  try {
    const list = JSON.parse(localStorage.getItem(STORAGE_KEY));
    return Array.isArray(list) ? list : [];
  } catch (_) {
    return [];
  }
}

function saveEnrollments(list) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
}

// ---------------------------------------------------------------------------
// Phone numbers
// ---------------------------------------------------------------------------

/**
 * Reduces whatever was typed to the digits that become user.id. A leading
 * country code is kept; the US trunk prefix on an 11-digit number is not, so
 * "1 (913) 555-1234" and "913-555-1234" enroll as the same number.
 */
function normalizePhone(raw) {
  const digits = raw.replace(/\D/g, '');
  return digits.length === 11 && digits.startsWith('1') ? digits.slice(1) : digits;
}

// ---------------------------------------------------------------------------
// User database
// ---------------------------------------------------------------------------

/**
 * The Ideem user API, reached through the proxy this site runs at /db.
 * The API itself sends no CORS headers, so the browser cannot call it
 * directly; dev-server.mjs and api/db.js both forward to it.
 */
const DB_BASE = './db';

/** A plausible balance for a demo account, since the booth form doesn't ask. */
function demoBalance() {
  return Math.round((500 + Math.random() * 9000) * 100) / 100;
}

/**
 * Looks a user up by phone number. The API matches the stored string exactly,
 * which is why everything here uses bare digits end to end.
 *
 * @returns {Promise<object|null>} The record, or null when there is none.
 */
export async function findUserByPhone(phone) {
  const res = await fetch(`${DB_BASE}/users/phone/${encodeURIComponent(phone)}`, { cache: 'no-store' });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`lookup returned ${res.status}`);
  const body = await res.json();
  return Array.isArray(body) ? body[0] ?? null : body;  // by-phone answers with an array
}

/**
 * Writes the attendee to the user database: a new record, or an update when
 * that number is already there. An existing balance and photo are kept, so
 * re-enrolling somebody does not wipe what the demo shows for them.
 */
export async function saveUser({ firstName, lastName, phone }) {
  const existing = await findUserByPhone(phone);
  const record = {
    firstName,
    lastName,
    phone,
    balance: existing?.balance ?? demoBalance(),
    photo: existing?.photo ?? null,
    customAttrib: `Enrolled at the Swissbit booth ${new Date().toISOString().slice(0, 10)}`
  };

  const res = await fetch(existing ? `${DB_BASE}/users/${existing.userId}` : `${DB_BASE}/users`, {
    method: existing ? 'PUT' : 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(record)
  });
  if (!res.ok) throw new Error(`${existing ? 'update' : 'create'} returned ${res.status}`);

  const text = await res.text();
  let returned = null;
  try { returned = text ? JSON.parse(text) : null; } catch (_) { /* not JSON; the status is what matters */ }
  return { updated: !!existing, userId: existing?.userId ?? returned?.userId ?? null, record, returned };
}

// ---------------------------------------------------------------------------
// Hand-off to the demo
// ---------------------------------------------------------------------------

/**
 * Where the QR code sends the attendee's phone. app.js reads ?userid= into the
 * User ID field on load (app.js:640-651), so the number the key now carries
 * arrives typed in.
 *
 * A phone cannot reach the booth Mac's localhost, so a page served from there
 * points at the deployment instead. Anywhere else -- Vercel, a tunnel -- the
 * QR keeps the origin the enrollment was done on, which is also the origin the
 * credential's RP ID is bound to.
 */
const PUBLIC_DEMO_ORIGIN = 'https://authenticate26.vercel.app';
const LOCAL_HOSTNAMES = ['localhost', '127.0.0.1', '[::1]', '::1'];

function demoUrl(phone) {
  const base = LOCAL_HOSTNAMES.includes(location.hostname) ? PUBLIC_DEMO_ORIGIN : location.origin;
  return `${base}/?userid=${encodeURIComponent(phone)}`;
}

/**
 * Draws the scan-to-open code for a number that is now on a key and in the
 * database. The generator is vendored and loaded on demand, so if it is
 * missing the link is still shown and the enrollment still stands.
 */
async function showQr(phone) {
  const url = demoUrl(phone);
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
    // Geometry only -- nothing from the form reaches the markup. scalable
    // drops the pixel size so the stylesheet decides how big it prints, and
    // the margin is the four-module quiet zone a camera needs to find the code.
    $('qr-code').innerHTML = qr.createSvgTag({ cellSize: 8, margin: 8 * 4, scalable: true });
    $('qr-code').hidden = false;
  } catch (err) {
    $('qr-code').replaceChildren();
    $('qr-code').hidden = true;
    sendLog({ event: 'qr-error', phone, error: { name: err.name, message: err.message } });
  }

  // Shown after the result, so this is the scroll that wins: the code is what
  // the attendee is here for.
  $('qr-section').hidden = false;
  $('qr-section').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function hideQr() {
  $('qr-section').hidden = true;
  $('qr-code').replaceChildren();
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

/**
 * Records the outcome on the dev server so booth results can be read from one
 * file. Absent in production (Vercel serves static files only), so failures
 * are ignored.
 */
function sendLog(event) {
  const body = JSON.stringify({
    at: new Date().toISOString(),
    origin: location.origin,
    userAgent: navigator.userAgent,
    ...event
  });
  fetch('./log', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body, keepalive: true })
    .catch(() => {});
}

// ---------------------------------------------------------------------------
// UI helpers
// ---------------------------------------------------------------------------

const $ = id => document.getElementById(id);

function showFlash(message, state, duration = 6000) {
  const el = $('flash-status');
  clearTimeout(flashTimer);
  el.textContent = message;
  el.className = 'flash ' + state;
  if (duration) {
    flashTimer = setTimeout(() => { el.textContent = ''; el.className = 'flash'; }, duration);
  }
}

function pill(label, value, state) {
  const el = document.createElement('span');
  el.className = `pill pill-${state}`;
  const b = document.createElement('b');
  b.textContent = value;
  el.append(`${label}: `, b);
  return el;
}

/**
 * Puts the outcome on screen. The warnings sit above the envelope, in the
 * open: they are the reason to look at this page at all when something is
 * wrong. Everything else goes inside the envelope, collapsed, because what the
 * booth needs on screen is the code the attendee is about to scan.
 */
function showResult({ title, pills, warnings, summary }) {
  $('result-title').textContent = title;
  $('result-pills').replaceChildren(...pills.map(p => pill(...p)));
  $('result-warnings').replaceChildren(...warnings.map(text => {
    const p = document.createElement('p');
    p.className = 'en-warning';
    p.textContent = text;
    return p;
  }));
  $('result-summary').textContent = JSON.stringify(summary, null, 2);
  $('result-block').hidden = false;
  $('envelope').hidden = false;
  $('envelope').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/** Renders the list of people enrolled from this browser. */
function renderEnrollments() {
  const list = loadEnrollments();
  $('enrolled-count').textContent = list.length ? `${list.length} enrolled from this browser` : 'Nothing enrolled from this browser yet';
  $('enrolled-section').hidden = !list.length;
  // The table lives inside the envelope, so earlier enrollments need the
  // envelope itself on screen (still collapsed) to be reachable at all.
  if (list.length) $('envelope').hidden = false;

  $('enrolled-body').replaceChildren(...list.map(entry => {
    const tr = document.createElement('tr');
    const cells = [
      `${entry.firstName} ${entry.lastName}`.trim(),
      entry.phone,
      new Date(entry.createdAt).toLocaleString(),
      entry.id.slice(0, 12) + '…'
    ];
    for (const text of cells) {
      const td = document.createElement('td');
      td.textContent = text;
      tr.append(td);
    }
    const td = document.createElement('td');
    const btn = document.createElement('button');
    btn.className = 'btn-danger-small';
    btn.textContent = 'Forget';
    btn.title = 'Removes this record from the browser only. The credential stays on the key.';
    btn.addEventListener('click', () => {
      saveEnrollments(loadEnrollments().filter(c => c.id !== entry.id));
      renderEnrollments();
    });
    td.append(btn);
    tr.append(td);
    return tr;
  }));
}

/**
 * Names the browser actually rendering this page and says whether it can do a
 * PIN-less discoverable create. Desktop Chrome cannot: it upgrades the
 * ceremony to user verification required and makes the attendee set a PIN on
 * the key, which then blocks every touch-only retrieval.
 */
async function showBrowserInfo() {
  const ua = navigator.userAgent;
  let label = null;
  let chromium = false;

  try {
    const data = await (navigator.userAgentData?.getHighEntropyValues(['fullVersionList']) ?? null);
    const brand = data?.fullVersionList?.find(b => !/not.a.brand/i.test(b.brand));
    if (brand) {
      label = `${brand.brand} ${brand.version}`;
      chromium = true;
    }
  } catch (_) { /* unsupported, or the user agent declined */ }

  if (!label) {                    // WebKit and Gecko do not implement UA Client Hints
    const named = ua.match(/(CriOS|Chrome|Firefox|Version)\/(\d+)/);
    const names = { Version: 'Safari', CriOS: 'Chrome for iOS' };
    label = named ? `${names[named[1]] || named[1]} ${named[2]}` : 'unknown browser';
    chromium = named?.[1] === 'Chrome';
  }

  const desktop = !/Android|iPhone|iPad|iPod/.test(ua);
  $('browser-info').textContent = `Browser: ${label}`;
  $('chrome-warning').hidden = !(chromium && desktop);
}

// ---------------------------------------------------------------------------
// Enrollment
// ---------------------------------------------------------------------------

/**
 * Writes a discoverable credential holding the attendee's phone number, then
 * reports what the key actually did: whether the credential is really
 * discoverable, which credProtect level it applied, and whether it stayed
 * PIN-less.
 */
async function enroll() {
  const firstName = $('first-name').value.trim();
  const lastName = $('last-name').value.trim();
  const phone = normalizePhone($('phone').value);

  if (!firstName || !lastName) return showFlash('Enter both a first and last name', 'failure');
  if (phone.length < MIN_DIGITS || phone.length > MAX_DIGITS) {
    return showFlash(`That phone number has ${phone.length} digits; it needs ${MIN_DIGITS} to ${MAX_DIGITS}`, 'failure');
  }

  // user.id is the phone number as UTF-8, so a get on any other device reads
  // it straight back out of the user handle. A production RP would use random
  // opaque bytes here: the spec says user.id must not contain personal
  // information. Carrying the number IS the demo.
  const userId = new TextEncoder().encode(phone);
  const displayName = `${firstName} ${lastName}`;
  const rpId = location.hostname;
  const challenge = crypto.getRandomValues(new Uint8Array(32));

  // Refuse a second credential for the same number on the same key. Transports
  // are left off so the browser tries every way it can reach the key.
  const excludeCredentials = loadEnrollments()
    .filter(c => c.phone === phone)
    .map(c => ({ type: 'public-key', id: base64urlToBuffer(c.id) }));

  const publicKey = {
    rp: { id: rpId, name: RP_NAME },
    user: { id: userId, name: phone, displayName },
    challenge,
    pubKeyCredParams: PUB_KEY_CRED_PARAMS,
    timeout: TIMEOUT_MS,
    excludeCredentials,
    authenticatorSelection: {
      authenticatorAttachment: 'cross-platform',  // roaming USB key, not Touch ID
      residentKey: 'required',                    // discoverable: the key stores the phone number
      requireResidentKey: true,                   // Level 1 compat; ignored where residentKey is understood
      userVerification: 'discouraged'             // touch only, no PIN
    },
    attestation: 'none',
    hints: ['security-key'],                      // Level 3: go straight to the security key UI
    extensions: {
      credProps: true,                            // report whether the credential is really discoverable
      // Level 1, and deliberately not enforced: Chrome rejects
      // enforceCredentialProtectionPolicy alongside userVerificationOptional
      // as inconsistent. The result below shows the level the key applied.
      credentialProtectionPolicy: 'userVerificationOptional'
    }
  };

  hideQr();               // the previous attendee's code must not linger
  $('envelope').open = false;  // and their detail should not be left hanging open

  const btn = $('enroll-btn');
  btn.classList.add('loading');
  btn.disabled = true;
  showFlash('Insert the iShield Key and touch it...', 'success', 0);

  try {
    const cred = await navigator.credentials.create({ publicKey });
    const r = cred.response;
    const authData = parseAuthenticatorData(r.getAuthenticatorData());
    const checks = await checkCeremony({
      clientDataJSON: r.clientDataJSON, authData, expectedType: 'webauthn.create', challenge, rpId
    });
    const alg = r.getPublicKeyAlgorithm();
    const spki = r.getPublicKey?.();  // null when the browser doesn't understand the algorithm
    const rk = cred.getClientExtensionResults().credProps?.rk;
    const cpLevel = authData.extensions?.credProtect;
    const ceremonyOk = checks.type && checks.challenge && checks.origin && checks.rpIdHash;

    const entry = {
      id: cred.id,
      phone,
      firstName,
      lastName,
      displayName,
      rk: rk ?? null,
      credProtect: cpLevel ?? null,
      alg,
      publicKey: spki ? bufferToBase64url(spki) : null,
      transports: r.getTransports?.() ?? [],
      aaguid: authData.aaguid ?? null,
      uvAtCreate: authData.flags.UV,
      signCount: authData.signCount,
      createdAt: new Date().toISOString()
    };
    saveEnrollments([entry, ...loadEnrollments().filter(c => c.id !== entry.id)]);
    renderEnrollments();

    // Share the credential with the other demo devices through the dev server.
    // Absent in production, so a failure is not worth reporting.
    fetch('./credentials', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...entry, rpId, userName: phone })
    }).catch(() => {});

    // Write the attendee to the user database. This runs after the key work,
    // so a cancelled or failed ceremony never leaves a record behind for
    // somebody who is not actually enrolled.
    let db = null;
    let dbError = null;
    try {
      db = await saveUser({ firstName, lastName, phone });
    } catch (err) {
      dbError = err.message;
    }

    // Anything that would break the retrieval flow is called out here, while
    // the attendee and the key are still at the booth.
    const warnings = [];
    if (dbError) {
      warnings.push(`The key is enrolled, but the user database was not updated (${dbError}). The retrieval device will find the phone number and no name behind it.`);
    }
    if (rk === false) {
      warnings.push('The key did not make this credential discoverable, so another device will not find it. Enroll again in Safari on a Mac.');
    }
    if (authData.flags.UV) {
      warnings.push('This key verified the user, which means it has a PIN set. Every retrieval device will ask for that PIN. Reset the key to make it PIN-less.');
    }
    if (cpLevel && cpLevel !== 1) {
      warnings.push(`The key applied credProtect level ${cpLevel} (${CRED_PROTECT_LEVELS[cpLevel] || 'unknown'}). Level 1 is what lets a touch-only lookup see the credential.`);
    }
    if (!ceremonyOk) {
      warnings.push('The challenge, origin or RP ID check did not match. Treat this enrollment as suspect.');
    }

    const ok = rk !== false && !authData.flags.UV && ceremonyOk && !dbError;
    showResult({
      title: ok ? `${displayName} is on the key` : `${displayName} enrolled, with warnings`,
      pills: [
        ['Phone on key', phone, 'success'],
        ['Database', dbError ? 'failed' : db.updated ? `updated #${db.userId}` : `created${db.userId ? ' #' + db.userId : ''}`, dbError ? 'danger' : 'success'],
        ['Discoverable', rk === undefined ? 'not reported' : String(rk), rk ? 'success' : rk === false ? 'danger' : 'unknown'],
        ['credProtect', cpLevel ? `${cpLevel} (${CRED_PROTECT_LEVELS[cpLevel] || 'unknown'})` : 'not reported', cpLevel === 1 ? 'success' : 'unknown'],
        ['PIN used', authData.flags.UV ? 'yes' : 'no', authData.flags.UV ? 'danger' : 'success'],
        ['Checks', ceremonyOk ? 'ok' : 'MISMATCH', ceremonyOk ? 'success' : 'danger']
      ],
      warnings,
      summary: {
        name: displayName,
        userHandleOnKey: phone,
        credentialId: cred.id,
        discoverable: rk ?? 'not reported (browser did not return credProps)',
        credProtect: cpLevel ? `${cpLevel} (${CRED_PROTECT_LEVELS[cpLevel] || 'unknown'})` : 'not reported',
        algorithm: COSE_ALGORITHMS[alg] ? `${COSE_ALGORITHMS[alg]} (${alg})` : String(alg),
        publicKeySaved: !!spki,
        aaguid: authData.aaguid ?? null,
        transports: entry.transports,
        flags: authData.flags,
        signCount: authData.signCount,
        rpId,
        checks: { type: checks.type, challenge: checks.challenge, origin: checks.origin, rpIdHash: checks.rpIdHash },
        database: dbError ? { error: dbError } : { action: db.updated ? 'updated' : 'created', userId: db.userId, record: db.record }
      }
    });

    // The hand-off code stands for a number that is genuinely on a key AND in
    // the database; without the record the demo would open on an empty account.
    if (!dbError) await showQr(phone);

    showFlash(ok ? `Passkey created for ${displayName}` : 'Passkey created, but check the warnings', ok ? 'success' : 'failure');
    sendLog({
      event: 'enroll', ok, phone, displayName, credentialId: cred.id, rk, credProtect: cpLevel, uv: authData.flags.UV,
      database: dbError ? { error: dbError } : { action: db.updated ? 'updated' : 'created', userId: db.userId }
    });

    $('first-name').value = '';
    $('last-name').value = '';
    $('phone').value = '';
    $('first-name').focus();
  } catch (err) {
    const hint = ERROR_HINTS[err.name] ? ` ${ERROR_HINTS[err.name]}` : '';
    showFlash(`${err.name}: ${err.message}${hint}`, 'failure', 12000);
    sendLog({ event: 'enroll-error', phone, error: { name: err.name, message: err.message } });
  } finally {
    btn.classList.remove('loading');
    btn.disabled = false;
  }
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', () => {
  if (!window.PublicKeyCredential) {
    showFlash('This browser has no WebAuthn support', 'failure', 0);
    $('enroll-btn').disabled = true;
    return;
  }

  $('enroll-form').addEventListener('submit', event => {
    event.preventDefault();
    enroll();
  });

  $('clear-enrollments').addEventListener('click', () => {
    saveEnrollments([]);
    renderEnrollments();
    showFlash('Cleared this browser’s records. Nothing was removed from any key.', 'success');
  });

  // Show the number the way it will be stored: digits only
  $('phone').addEventListener('blur', () => {
    const digits = normalizePhone($('phone').value);
    if (digits) $('phone').value = digits;
  });

  renderEnrollments();
  showBrowserInfo();
  sendLog({ event: 'load', page: 'enroll' });
});
