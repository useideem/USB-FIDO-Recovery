/**
 * app.js -- Demo Orchestration & UI
 *
 * This is the application glue layer. It imports the integration modules
 * (ishield.js, umfa.js, sna.js, key-records.js) and wires them to the UI.
 *
 * A partner integrating a FIDO key + Passkeys+ into their own app would
 * primarily study ishield.js and umfa.js. This file is demo-specific and
 * handles screens, flash messages, dialogs, and event listeners.
 *
 * THE STORY (the customer's flow, 2026-10-31): a bank ships the user a blank
 * FIDO USB key. On their phone the user binds the number and the phone, then
 * encodes the key themselves, creating its PIN. When the key is lost they say
 * so in the app, the old key is refused, the bank ships another blank key,
 * and after the passkey the user encodes that one.
 *
 * FLOW:
 *   1. Continue       -- on a phone that holds a ZSM share for the number:
 *                        authenticate() with Passkeys+, nothing else. On a
 *                        phone that holds none: a dialog naming the three
 *                        steps, the simulated SNA number check (sna.js), a
 *                        dialog handing over to the passkey, enroll() with
 *                        Passkeys+ in the SDK's required mode (the same call
 *                        rebinds a browser from a passkey the server already
 *                        knows), then a dialog in front of the key: the
 *                        WebAuthn create (key-enroll.js) that writes the
 *                        verified number onto the blank key. The create
 *                        requires user verification, so the browser has the
 *                        user create the key's PIN, then touch it
 *   2. Home           -- the key this phone encoded and when, the four
 *                        factors (USB Key, Phone# Verified, Device Bound,
 *                        Passkey), and the challenge each factor's last
 *                        ceremony produced; Authenticate is a fresh passkey
 *                        step-up; Verify USB key is a get on the key, which
 *                        is how a lost key is shown to be refused
 *   3. I lost this key -- a dialog saying the bank would be notified and
 *                        would ship a blank replacement; the key is marked
 *                        lost and refused from then on
 *   4. Encode new FIDO key -- the recovery: the passkey again, then the
 *                        create on the blank replacement, with every key this
 *                        phone knows excluded so a lost key that turns up is
 *                        refused by the key itself; the new credential
 *                        becomes the associated key and the one before is
 *                        marked replaced
 *
 * Everything the app knows about a user's keys lives in this browser
 * (key-records.js): there is no backend. A second phone has its own list.
 *
 * NOTE: state.js is loaded as a classic script (non-module) so that the
 * State class is available as a global. The stateChange custom events it
 * dispatches are available but unused in this demo.
 */

import { webauthnAuthenticate } from './ishield.js';
import { enrollKey, ERROR_HINTS, COSE_ALGORITHMS } from './key-enroll.js';

import {
  initializeZSMClient,
  checkAllEnrollment,
  enroll,
  authenticate,
  resetClient,
  challengeDataFrom
} from './umfa.js';

import {
  verifyNumber,
  isNumberVerified,
  setNumberVerified,
  getNumberVerification,
  SNA_STEPS,
  SNA_SCENARIOS
} from './sna.js';

import {
  loadKeys,
  activeKey,
  recordVerification,
  associateKey,
  markLost,
  KEY_STATUS
} from './key-records.js';

// ---------------------------------------------------------------------------
// Shared UI helpers
// ---------------------------------------------------------------------------

const flashTimers = {};

function showFlash(elementId, message, state, duration = 3000) {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.textContent = message;
  el.className = 'flash ' + state;
  if (flashTimers[elementId]) clearTimeout(flashTimers[elementId]);
  if (duration > 0) {
    flashTimers[elementId] = setTimeout(() => { el.textContent = ''; el.className = 'flash'; }, duration);
  }
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
  const digits = String(value || '').replace(/\D/g, '');
  return digits.length === 11 && digits.startsWith('1') ? digits.slice(1) : digits;
}

/** (913) 555-1235 for a ten-digit number; anything else as stored. */
function formatPhone(value) {
  const text = String(value || '');
  const digits = phoneDigits(text);
  return digits.length === 10 ? `(${digits.slice(0, 3)}) ${digits.slice(3, 6)}-${digits.slice(6)}` : text;
}

/** Date and time, to the second, in the phone's own locale. */
function formatWhen(iso) {
  if (!iso) return '--';
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? '--' : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' });
}

/** The first characters of a credential id, enough to tell keys apart on screen. */
function shortId(id) {
  const text = String(id ?? '');
  return text.length > 16 ? `${text.slice(0, 16)}…` : text;
}

/** True when the key's user handle and the User ID name the same number. */
function sameUser(typed, fromKey) {
  if (!fromKey) return false;
  return typed === fromKey || (!!phoneDigits(typed) && phoneDigits(typed) === phoneDigits(fromKey));
}

/**
 * The flash when the key's user handle does not name the User ID on screen.
 * The key is the authority on identity: it hands back the handle stored in
 * the credential, and the signed-in User ID has to agree with it.
 */
function keyMismatchMessage(typed, fromKey) {
  return fromKey
    ? `This key belongs to "${fromKey}", but the User ID box says "${typed}". Enter the ID that matches the key, or use that person's key.`
    : 'This key carries no User ID for this site. A blank key is encoded from HOME.';
}

/** The flash for a key get that failed. */
function keyFailureMessage(error) {
  const name = error?.name || '';
  const message = error?.message || '';
  if (/platform passkey/.test(message)) {
    return 'A passkey answered instead of the key. A password manager may be stepping in front of the security-key prompt; use the USB key.';
  }
  if (name === 'NotAllowedError') {
    return 'Cancelled, timed out, the PIN was wrong, or this key holds nothing for this site. A blank key is encoded from HOME.';
  }
  return message || 'USB key verification failed';
}

/**
 * The flash for a key create that failed. InvalidStateError is the key
 * refusing an excluded credential: it already holds one for this number
 * that this phone knows, which after a loss means the lost key turned up.
 */
function encodeFailureMessage(error) {
  const name = error?.name || '';
  if (name === 'InvalidStateError') {
    return 'This key is already encoded for this number on this phone. A key reported lost or replaced stays refused; insert the blank replacement key.';
  }
  if (name === 'NotAllowedError') {
    return 'Cancelled, timed out, or the PIN was not created or entered. If the key refused the PIN, choose one that is not a run like 1234 and does not repeat a character four times. Insert the key and try again.';
  }
  return ERROR_HINTS[name] || error?.message || 'Encoding the key failed';
}

// ---------------------------------------------------------------------------
// Guide dialog -- the dialog in front of a ceremony. The tap on its button is
// also the user gesture the WebAuthn prompt that follows needs. Resolves 'ok'
// for the button, 'alt' for the optional second button, and 'cancel' for
// Escape.
// ---------------------------------------------------------------------------

/** In front of a first Continue on this phone: the three steps, then Start. */
const ONBOARDING_GUIDE = {
  title: "Let's get your phone ready.",
  lead: 'We are going to do 3 things',
  steps: [
    'Verify your phone number with the carrier',
    'Create a mobile device Passkey and bind this phone',
    'Encode the FIDO USB Key from your bank and create its PIN'
  ],
  note: 'Start with your phone number',
  button: 'Start'
};

/** After the number check: the passkey is next. */
const PASSKEY_GUIDE = {
  title: 'Your number is verified!',
  lead: "Now let's get your mobile device Passkey enrolled",
  button: 'Continue'
};

/**
 * After the passkey at setup: the blank key is next. The tap on its button
 * is the gesture the create needs, and the browser's own "create a PIN" step
 * follows it.
 */
const ENCODE_KEY_GUIDE = {
  title: 'Insert the FIDO USB Key from your bank',
  lead: 'The key arrives blank. Your phone will ask you to create a PIN for it, then to touch it. Choose a PIN that is not a run like 1234 and does not repeat a character four times; the key refuses those. The key is then encoded with your verified number.',
  button: 'Encode the key'
};

/** The lost-key report. Escape, or the second button, leaves the key as it is. */
const LOST_KEY_GUIDE = {
  title: 'Report this FIDO key lost',
  lead: 'In this scenario the bank would be notified and would send you a blank replacement key. Until a new key is encoded, this key is no longer accepted on this phone.',
  button: 'Report it lost',
  alt: 'Keep it'
};

/** In front of Encode new FIDO key: the two steps, then Start. */
const ENCODE_NEW_GUIDE = {
  title: 'Encode a new FIDO key',
  lead: 'We are going to do 2 things',
  steps: [
    'Confirm with your mobile device Passkey',
    'Encode the blank FIDO USB Key and create its PIN'
  ],
  note: 'Start with the Passkey',
  button: 'Start'
};

/** After the passkey in the recovery: the blank replacement is next. */
const NEW_KEY_GUIDE = {
  title: 'Insert the new FIDO USB Key',
  lead: 'It arrives blank. Your phone will ask you to create a PIN for it, then to touch it. Choose a PIN that is not a run like 1234 and does not repeat a character four times. The key you reported lost stays refused.',
  button: 'Encode the key'
};

let guideResolve = null;
let guidePreviousFocus = null;

function showGuide({ title, lead = '', steps = [], note = '', button = 'Continue', alt = '' }) {
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
    $('guide-alt').textContent = alt;
    $('guide-alt').hidden = !alt;
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
    // Focus stays inside the dialog: on the one button, or between the two
    e.preventDefault();
    const start = document.getElementById('guide-start');
    const alt = document.getElementById('guide-alt');
    (document.activeElement === start && !alt.hidden ? alt : start).focus();
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
// State
// ---------------------------------------------------------------------------
const STATE = new State({
  loginID: null
});

// ---------------------------------------------------------------------------
// Ceremony results -- what each factor's last ceremony produced, for the
// challenge blocks on HOME: the key's create or get, the passkey's enroll or
// authenticate, and the number check. Kept per User ID in sessionStorage so
// a reload within the tab keeps them; Log Out and Reset Device clear them.
// ---------------------------------------------------------------------------
const RESULTS_PREFIX = 'factor_results:';

function loadResults(user) {
  if (!user) return {};
  try {
    return JSON.parse(sessionStorage.getItem(RESULTS_PREFIX + user)) || {};
  } catch (_) {
    return {};
  }
}

function setResult(user, factor, data) {
  if (!user) return;
  const results = loadResults(user);
  results[factor] = data;
  try { sessionStorage.setItem(RESULTS_PREFIX + user, JSON.stringify(results)); } catch (_) { /* no storage: the blocks last this page */ }
}

function clearResults(user) {
  if (!user) return;
  try { sessionStorage.removeItem(RESULTS_PREFIX + user); } catch (_) { /* nothing to clear */ }
}

/** The key get (purpose 'verify'), as the USB Key block shows it. */
function keyResultFrom(result, purpose) {
  return {
    purpose,
    credentialId: result.credentialId,
    challenge: result.challenge,
    clientDataHash: result.clientDataHash ?? null,
    signatureHex: result.signatureHex ?? null,
    userVerified: result.userVerified ?? null,
    signCount: result.signCount ?? null,
    at: result.at
  };
}

/**
 * The key create (purpose 'encode' at setup, 'replace' in the recovery), as
 * the USB Key block shows it. A create with attestation 'none' signs nothing,
 * so the block shows the public key the phone now holds instead.
 */
function encodeResultFrom({ entry }, purpose) {
  return {
    purpose,
    credentialId: entry.id,
    challenge: entry.challenge,
    publicKey: entry.publicKey ?? null,
    alg: entry.alg ?? null,
    rk: entry.rk ?? null,
    userVerified: entry.uvAtCreate ?? null,
    signCount: entry.signCount ?? null,
    at: entry.createdAt
  };
}

/** The create's entry as key-records.js takes it. */
function keyFromEnrollment({ entry }) {
  return {
    credentialId: entry.id,
    authenticatedUser: entry.phone,
    userVerified: entry.uvAtCreate ?? null,
    signCount: entry.signCount ?? null,
    publicKey: entry.publicKey ?? null,
    alg: entry.alg ?? null,
    encoded: true
  };
}

/** The SDK ceremony, as the Passkey block shows it. */
async function passkeyResultFrom(credential, ceremony) {
  const data = await challengeDataFrom(credential);
  return {
    ceremony,
    challenge: data?.challenge ?? null,
    signedChallenge: data?.signedChallenge ?? null,
    at: new Date().toISOString()
  };
}

// ---------------------------------------------------------------------------
// SNA — simulated Silent Network Authentication (sna.js)
//
// Runs first at setup, before the passkey and the key (the customer's flow,
// 2026-10-31; the recovery runs the passkey alone). A sign-in on a phone
// that holds the marker never sees it.
// ---------------------------------------------------------------------------
const SNA_SCENARIO_KEY = 'snaScenario';

/** What the screen says when a scenario fails, by the reason sna.js gives. */
const SNA_FAILURE_MESSAGES = {
  no_match: 'Your network says this number is not on this device.',
  network_unsupported: 'Your network could not verify the number silently. Turn on cellular data and try again.'
};

/**
 * The indicator rows, in order, with what each reads when lit and when not.
 * The same four rows are drawn on the SNA screen (sna-ind-) and on HOME
 * (factor-).
 */
const FACTORS = [
  { id: 'ishield', on: 'true', off: 'false' },
  { id: 'number', on: 'true', off: 'false' },
  { id: 'device', on: 'true', off: 'false' },
  { id: 'passkey', on: 'true', off: 'false' }
];

let snaResolve = null;     // settles the ensureNumberVerified() promise
let snaAbort = null;       // cancels a check in progress
let snaStepRows = [];      // one row per SNA_STEPS entry, for the step list

/** Presenter-only: the ?sna= scenario, consumed by the one run that reads it. */
function takeSnaScenario() {
  const scenario = sessionStorage.getItem(SNA_SCENARIO_KEY);
  sessionStorage.removeItem(SNA_SCENARIO_KEY);
  return SNA_SCENARIOS.includes(scenario) ? scenario : 'success';
}

/**
 * The number check gate. Resolves true at once when this phone already
 * verified the user's number, unless `force` asks for a fresh check (setup
 * does); otherwise puts the SNA screen up and resolves true
 * after a successful check and Continue. Nothing resolves it false now that
 * the screen has no Cancel; the callers still handle false.
 */
function ensureNumberVerified(user, { force = false } = {}) {
  if (!force && isNumberVerified(user)) return Promise.resolve(true);
  return new Promise((resolve) => {
    snaResolve = resolve;
    renderSna({ user, phase: 'ready' });
    showScreen('SNA');
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
      setResult(user, 'sna', { checkId: result.checkId, code: result.code, phone: result.phone, verifiedAt: result.verifiedAt });
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
  const subtitle =
    verified ? 'Your mobile number was verified silently over your network.' :
    phase === 'running' ? 'This takes a few seconds and needs nothing from you.' : '';
  $('sna-subtitle').textContent = subtitle;
  $('sna-subtitle').hidden = !subtitle;

  if (phase === 'ready' || phase === 'running') buildSnaSteps();
  $('sna-steps').hidden = phase === 'ready';

  const status = $('sna-status');
  status.textContent = verified ? `${formatPhone(user)} Verified` : message;
  status.className = 'flash' + (verified ? ' success' : failed ? ' failure' : '');

  const verify = $('sna-verify');
  verify.hidden = !(phase === 'ready' || failed);
  verify.textContent = failed ? 'Try again' : 'Verify my number';
  $('sna-continue').hidden = !verified;

  $('sna-indicators').hidden = !verified;
  if (verified) {
    renderFactors('sna-ind', await factorStates(user));
    $('sna-continue').focus();
  }
}

/** One pending row per SNA_STEPS entry: the mark and the label. */
function buildSnaSteps() {
  snaStepRows = SNA_STEPS.map((step) => {
    const row = document.createElement('li');
    row.className = 'sna-step';
    const mark = document.createElement('span');
    mark.className = 'sna-step-mark';
    const label = document.createElement('span');
    label.className = 'sna-step-label';
    label.textContent = step.label;
    row.append(mark, label);
    return row;
  });
  document.getElementById('sna-steps').replaceChildren(...snaStepRows);
}

/** verifyNumber's onStep: colours the row as the step starts and ends. */
function renderSnaStep(index, step, status) {
  const row = snaStepRows[index];
  if (row) row.className = `sna-step ${status}`;
}

// ---------------------------------------------------------------------------
// Factors — what the four rows read for this user on this phone: the key
// (an active record in key-records.js), the number (the SNA marker), the
// device binding and the passkey (the SDK).
// ---------------------------------------------------------------------------
async function factorStates(user) {
  let device = false;
  let passkey = false;
  if (user) {
    try {
      await initializeZSMClient(user);
      const status = await checkAllEnrollment(user);
      if (status && !(status instanceof Error)) {
        device = status.hasZSMCred === true || !!status.zsmCredID;
        passkey = status.hasRemotePasskey === true || status.hasLocalPasskey === true;
      }
    } catch (_) {}
  }
  return {
    ishield: !!activeKey(user),
    number: isNumberVerified(user),
    device,
    passkey
  };
}

/** Lights the four rows under `prefix` (sna-ind or factor) from the states. */
function renderFactors(prefix, states) {
  for (const { id, on, off } of FACTORS) {
    const lit = states[id] === true;
    const row = document.getElementById(`${prefix}-${id}`);
    if (!row) continue;
    row.className = 'sna-indicator ' + (lit ? 'on' : 'off');
    document.getElementById(`${prefix}-${id}-state`).textContent = lit ? on : off;
  }
}

// ---------------------------------------------------------------------------
// HOME — the key card, the factors, and the challenge blocks
// ---------------------------------------------------------------------------

/** What a key record's status reads on the card. */
function keyStatusText(record) {
  switch (record.status) {
    case KEY_STATUS.LOST: return `Reported lost ${formatWhen(record.lostAt)}`;
    case KEY_STATUS.REPLACED: return `Replaced ${formatWhen(record.replacedAt)}`;
    default: return 'Active';
  }
}

function renderKeyCard(user) {
  const $ = (id) => document.getElementById(id);
  const keys = loadKeys(user);
  const current = keys[0] || null;
  $('key-current').hidden = !current;
  $('key-none').hidden = !!current;
  if (current) {
    $('key-id').textContent = shortId(current.id);
    $('key-id').title = current.id;
    $('key-associated-label').textContent = current.encodedAt ? 'Encoded' : 'Associated';
    $('key-associated').textContent = formatWhen(current.associatedAt);
    $('key-verified').textContent = formatWhen(current.lastVerifiedAt);
    $('key-status').textContent = keyStatusText(current);
    $('key-status').className = 'key-status-' + current.status;
  }
  const history = keys.slice(1);
  const list = $('key-history');
  list.replaceChildren(...history.map((record) => {
    const li = document.createElement('li');
    li.className = 'key-history-row';
    const id = document.createElement('span');
    id.className = 'key-mono';
    id.textContent = shortId(record.id);
    id.title = record.id;
    const detail = document.createElement('span');
    detail.className = 'key-history-detail';
    detail.textContent = `${record.encodedAt ? 'encoded' : 'associated'} ${formatWhen(record.associatedAt)} · ${keyStatusText(record)}`;
    li.append(id, detail);
    return li;
  }));
  list.hidden = history.length === 0;
  $('lost-key-btn').disabled = !activeKey(user);
}

/**
 * Fills a challenge block from rows of { label, value } and a meta line,
 * cloning the row template for each. Hidden when there is nothing to show.
 */
function renderChallengeBlock(id, rows, meta = '') {
  const block = document.getElementById(id);
  if (!block) return;
  const template = document.getElementById('challenge-row-template');
  const shown = rows.filter(({ value }) => value !== null && value !== undefined && value !== '');
  block.querySelector('.challenge-rows').replaceChildren(...shown.map(({ label, value }) => {
    const row = template.content.firstElementChild.cloneNode(true);
    const text = String(value);
    row.querySelector('.challenge-row-label').textContent = label;
    row.querySelector('.challenge-value').textContent = text.length > 15 ? `${text.substring(0, 15)}...` : text;
    row.querySelector('.challenge-full').textContent = text;
    return row;
  }));
  const metaLine = block.querySelector('.challenge-meta');
  metaLine.textContent = meta;
  metaLine.hidden = !meta;
  block.hidden = shown.length === 0;
}

function renderChallengeBlocks(user) {
  const results = loadResults(user);
  // The USB Key block: a create shows the challenge, the public key the
  // phone now holds and the credential; a get shows the signed challenge.
  const key = results.key;
  const encoded = !!key && (key.purpose === 'encode' || key.purpose === 'replace');
  renderChallengeBlock('key-challenge-display', !key ? [] : encoded ? [
    { label: 'Challenge', value: key.challenge },
    { label: 'Public key', value: key.publicKey },
    { label: 'Credential', value: key.credentialId }
  ] : [
    { label: 'Challenge', value: key.challenge },
    { label: 'Client data hash', value: key.clientDataHash },
    { label: 'Signed challenge', value: key.signatureHex },
    { label: 'Credential', value: key.credentialId }
  ], key ? [
    key.purpose === 'replace' ? 'Replacement key encoded' : key.purpose === 'encode' ? 'Key encoded' : 'Key verified',
    key.userVerified === true ? 'PIN verified' : key.userVerified === false ? 'PIN not verified' : null,
    encoded && COSE_ALGORITHMS[key.alg] ? COSE_ALGORITHMS[key.alg] : null,
    Number.isFinite(key.signCount) ? `sign count ${key.signCount}` : null,
    formatWhen(key.at)
  ].filter(Boolean).join(' · ') : '');

  const passkey = results.passkey;
  renderChallengeBlock('passkey-challenge-display', passkey ? [
    { label: 'Challenge', value: passkey.challenge },
    { label: 'Signed challenge', value: passkey.signedChallenge }
  ] : [], passkey ? `${passkey.ceremony === 'enrollment' ? 'Enrollment' : 'Authentication'} · ${formatWhen(passkey.at)}` : '');

  const sna = results.sna || snaResultFromMarker(user);
  renderChallengeBlock('sna-challenge-display', sna ? [
    { label: 'Check ID', value: sna.checkId },
    { label: 'Code', value: sna.code }
  ] : [], sna ? `${formatPhone(sna.phone || user)} verified · ${formatWhen(sna.verifiedAt)}` : '');
}

/** The number check this phone holds, when the tab has no result of its own. */
function snaResultFromMarker(user) {
  const marker = getNumberVerification(user);
  return marker?.checkId ? { checkId: marker.checkId, code: marker.code, phone: marker.phone, verifiedAt: marker.verifiedAt } : null;
}

async function renderHome(user) {
  renderKeyCard(user);
  renderChallengeBlocks(user);
  renderFactors('factor', await factorStates(user));
}

// ---------------------------------------------------------------------------
// showScreen — simple screen switcher
// ---------------------------------------------------------------------------
const SCREEN_ANNOUNCEMENTS = {
  'LOGIN': 'Login screen. Enter your phone number and tap Continue.',
  'SNA': 'Phone number verification screen. Tap Verify my number.',
  'HOME': 'Home screen. You are logged in.'
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

  // The User ID can be changed before logging in. It is read-only once
  // logged in and on SNA (the number being verified is the one on screen).
  document.getElementById('username').readOnly = screenId === 'HOME' || screenId === 'SNA';

  // Announce screen change to screen readers
  const announcer = document.getElementById('screen-announcer');
  if (announcer) announcer.textContent = SCREEN_ANNOUNCEMENTS[screenId] || '';
}

// ---------------------------------------------------------------------------
// updateUI — detect state and show the right screen
// ---------------------------------------------------------------------------
async function updateUI() {
  const user = getUsername();
  document.getElementById('login-btn').disabled = !user;

  if (snaResolve) {
    // A number check is waiting for its Verify or Continue: nothing else
    // moves the screen until it settles.
    showScreen('SNA');
  } else if (STATE.loginID) {
    showScreen('HOME');
    await renderHome(STATE.loginID);
  } else {
    showScreen('LOGIN');
    await renderLoginHint(user);
  }
}

/** Under Continue: whether this phone will be set up or just ask for the passkey. */
async function renderLoginHint(user) {
  const hint = document.getElementById('login-hint');
  if (!user) {
    hint.hidden = true;
    return;
  }
  const { device } = await factorStates(user);
  if (getUsername() !== user) return;   // typed over meanwhile
  hint.textContent = device
    ? 'This phone is set up: Continue signs you in with your passkey.'
    : 'First time on this phone: we verify your number, create your passkey, then encode the blank FIDO USB key from your bank.';
  hint.hidden = false;
}

// ---------------------------------------------------------------------------
// Ceremonies
// ---------------------------------------------------------------------------

/** The passkey: a fresh ZSM + Passkeys+ authenticate in the SDK's required mode. */
async function verifyPasskey(user, prompt) {
  showFlash('flash-status', prompt, 'success', 60000);
  await initializeZSMClient(user);
  const authResult = await authenticate(user, 'required');
  if (!authResult.success) {
    showFlash('flash-status', 'Passkey verification failed', 'failure', 5000);
    return null;
  }
  setResult(user, 'passkey', await passkeyResultFrom(authResult.credential, 'authentication'));
  showFlash('flash-status', 'Passkey verified', 'success', 2500);
  return authResult;
}

/**
 * Continue. The device's own state picks the ceremony: a phone that holds a
 * ZSM share for the typed User ID signs in on the passkey alone; one that
 * holds none is set up: the guide, the number check, the handoff dialog, the
 * ZSM + Passkeys+ enroll in required mode (which creates a passkey or, where
 * the server already knows one for this number, authenticates it and
 * rebuilds the share here), then, from HOME, the dialog in front of the
 * create that encodes the blank key. A phone whose key step is skipped or
 * fails is still bound: HOME offers Encode new FIDO key.
 */
async function login() {
  const btn = document.getElementById('login-btn');
  const user = getUsername();
  if (!user) return;

  btn.classList.add('loading');
  btn.setAttribute('aria-busy', 'true');
  btn.setAttribute('aria-disabled', 'true');

  try {
    await initializeZSMClient(user);
    let hasLocalZSM = false;
    try {
      const status = await checkAllEnrollment(user);
      if (status && !(status instanceof Error)) {
        hasLocalZSM = status.hasZSMCred === true || !!status.zsmCredID;
      }
    } catch (_) {}

    // A set-up phone: the passkey alone
    if (hasLocalZSM) {
      if (!(await verifyPasskey(user, 'Confirm with your passkey...'))) return;
      // A phone set up before the number check existed gets it here; one
      // that has it answers at once.
      if (!(await ensureNumberVerified(user))) {
        await updateUI();
        return;
      }
      STATE.loginID = user;
      showFlash('flash-status', 'Signed in with your passkey', 'success');
      await updateUI();
      return;
    }

    // Step 1: the guide names the three steps
    if (await showGuide(ONBOARDING_GUIDE) !== 'ok') return;

    // Step 2: the number check, always at setup
    if (!(await ensureNumberVerified(user, { force: true }))) {
      showFlash('flash-status', 'Number not verified. Tap Continue to try again.', 'failure', 4000);
      await updateUI();
      return;
    }

    // Step 3: the passkey, behind the handoff dialog (its tap is the gesture)
    if (await showGuide(PASSKEY_GUIDE) !== 'ok') {
      await updateUI();
      return;
    }
    showFlash('flash-status', 'Creating your passkey and binding this phone...', 'success', 60000);
    await initializeZSMClient(user);
    const enrollResult = await enroll(user, 'required');
    if (!enrollResult || enrollResult === false || enrollResult instanceof Error) {
      showFlash('flash-status', 'Passkey enrollment failed. Tap Continue to try again.', 'failure', 6000);
      await updateUI();
      return;
    }
    setResult(user, 'passkey', await passkeyResultFrom(enrollResult, 'enrollment'));

    // The phone is bound: HOME from here, with the key step on top of it
    STATE.loginID = user;
    await updateUI();

    // Step 4: the blank key, behind its dialog (its tap is the gesture the
    // create needs; the browser's "create a PIN" step follows)
    if (await showGuide(ENCODE_KEY_GUIDE) !== 'ok') {
      showFlash('flash-status', 'Phone bound: number and passkey. Encode your FIDO key from HOME when you are ready.', 'success', 6000);
      return;
    }
    await encodeKey(user, 'encode');
    await updateUI();
  } catch (err) {
    console.error('[login] Error:', err);
    showFlash('flash-status', 'Login failed', 'failure');
    await updateUI();
  } finally {
    btn.classList.remove('loading');
    btn.removeAttribute('aria-busy');
    btn.removeAttribute('aria-disabled');
  }
}

/** Authenticate on HOME: a fresh passkey step-up, drawn into the Passkey block. */
async function authenticateStepUp() {
  const user = STATE.loginID;
  if (!user) return;
  if (!(await verifyPasskey(user, 'Confirm with your passkey...'))) {
    showFlash('action-status', 'Authenticate failed', 'failure', 3000);
    return;
  }
  showFlash('action-status', 'Authenticate authorized', 'success', 3000);
  await renderHome(user);
}

/** I lost this key: the dialog, then the key is marked lost and refused. */
async function reportLost() {
  const user = STATE.loginID;
  if (!user) return;
  if (!activeKey(user)) {
    showFlash('action-status', 'No key is associated on this phone', 'failure', 3000);
    return;
  }
  if (await showGuide(LOST_KEY_GUIDE) !== 'ok') return;
  const lost = markLost(user);
  showFlash('action-status', lost ? `Key reported lost ${formatWhen(lost.lostAt)}. The bank would ship a blank replacement key.` : 'No key to report', lost ? 'success' : 'failure', 5000);
  await renderHome(user);
}

/**
 * The create that encodes the inserted blank key with this User ID. The
 * create requires user verification, so the browser has the user create the
 * key's PIN when the key has none, then touch it; the key decides what a PIN
 * may be. Every key this phone already knows (active, lost or replaced) is
 * excluded, so a lost key that turns up is refused by the key itself. The
 * new credential becomes the associated key and the one before is marked
 * replaced. Must run straight from a tap. Returns the record, or null after
 * flashing why it stopped.
 */
async function encodeKey(user, purpose) {
  showFlash('flash-status', 'Create a PIN for the key when your phone asks (not a run like 1234, no character four times), then touch the key...', 'success', 120000);
  let enrollment;
  try {
    enrollment = await enrollKey({
      phone: user,
      displayName: formatPhone(user),
      excludeIds: loadKeys(user).map(k => k.id)
    });
  } catch (err) {
    console.error('[encode] create failed:', err);
    showFlash('flash-status', encodeFailureMessage(err), 'failure', 8000);
    return null;
  }

  const { outcome, record, previous } = associateKey(user, keyFromEnrollment(enrollment));
  if (outcome === 'refused') {
    showFlash('flash-status', `That key was ${record.status === KEY_STATUS.LOST ? 'reported lost' : 'replaced'} ${formatWhen(record.lostAt || record.replacedAt)} and is no longer accepted.`, 'failure', 8000);
    return null;
  }
  setResult(user, 'key', encodeResultFrom(enrollment, purpose));
  if (outcome === 'same') {
    showFlash('flash-status', 'That is the key already associated with this phone.', 'success', 5000);
    return record;
  }
  const when = formatWhen(record.associatedAt);
  if (enrollment.warnings.length) {
    showFlash('flash-status', `Key encoded ${when}, with a warning: ${enrollment.warnings[0]}`, 'failure', 10000);
  } else if (previous) {
    showFlash('flash-status', `New key encoded ${when}. The previous key is no longer accepted.`, 'success', 6000);
  } else if (purpose === 'replace') {
    showFlash('flash-status', `New key encoded ${when}. The key you reported lost stays refused.`, 'success', 6000);
  } else {
    showFlash('flash-status', `Key encoded ${when}. Keep it safe.`, 'success', 6000);
  }
  return record;
}

/**
 * Verify USB key on HOME: the open get, drawn into the USB Key block. The
 * handle must name this User ID. The associated key moves its last-verified
 * time; a key reported lost or replaced is refused and the flash says when,
 * which is how the demo shows the old key disabled; a different key while
 * one is active is not swapped (Encode new FIDO key changes keys). With no
 * active key, the key read becomes the associated one, which is how a second
 * phone adopts a key it did not encode.
 *
 * The get names every key this phone has recorded in allowCredentials, so
 * the browser opens its security-key sheet rather than the passkey chooser
 * that puts the device biometric first; with no records it is the open get.
 */
async function verifyUsbKey() {
  const user = STATE.loginID;
  if (!user) return;
  showFlash('flash-status', 'Enter the PIN and touch your USB key...', 'success', 60000);
  // Lost and replaced keys are listed too, so a lost key still signs and the
  // refusal below is the app's, with its date.
  const known = loadKeys(user);
  const got = await webauthnAuthenticate(user, { allowIds: known.map(k => k.id) });
  if (!got.success) {
    showFlash('flash-status', keyFailureMessage(got.error), 'failure', 8000);
    return;
  }
  // The handle the key returned; failing that, the one recorded for this
  // credential, since an allow-listed get may come back without one.
  const recorded = known.find(k => k.id === got.credentialId)?.userHandle ?? null;
  const result = { ...got, authenticatedUser: got.authenticatedUser ?? recorded };
  if (!sameUser(user, result.authenticatedUser)) {
    showFlash('flash-status', keyMismatchMessage(user, result.authenticatedUser), 'failure', 8000);
    return;
  }
  const { outcome, record } = recordVerification(user, result);
  if (outcome === 'refused') {
    showFlash('flash-status', `This key was ${record.status === KEY_STATUS.LOST ? 'reported lost' : 'replaced'} ${formatWhen(record.lostAt || record.replacedAt)} and is no longer accepted.`, 'failure', 8000);
  } else if (outcome === 'unknown') {
    showFlash('flash-status', 'This is not the key associated on this phone. Use Encode new FIDO key to change keys.', 'failure', 8000);
  } else {
    setResult(user, 'key', keyResultFrom(result, 'verify'));
    showFlash('flash-status', outcome === 'associated' ? `Key associated ${formatWhen(record.associatedAt)}.` : 'USB key verified', 'success', 4000);
  }
  await renderHome(user);
}

/**
 * Encode new FIDO key: the recovery. The passkey, then the create on the
 * blank replacement; the key reported lost stays refused.
 */
async function encodeNewKey() {
  const user = STATE.loginID;
  if (!user) return;
  if (await showGuide(ENCODE_NEW_GUIDE) !== 'ok') return;

  if (!(await verifyPasskey(user, 'Confirm with your passkey...'))) {
    showFlash('action-status', 'Stopped: passkey not verified', 'failure', 4000);
    return;
  }
  if (await showGuide(NEW_KEY_GUIDE) !== 'ok') {
    await updateUI();
    return;
  }
  await encodeKey(user, 'replace');
  await updateUI();
}

// ---------------------------------------------------------------------------
// logOut
// ---------------------------------------------------------------------------
async function logOut() {
  clearResults(STATE.loginID);
  resetClient();
  STATE.reset();
  await updateUI();
}

// ---------------------------------------------------------------------------
// purgeStorage — Reset Device: everything this phone holds goes, except the
// User ID, and the page reloads on its bare path so a ?userid= from the
// registration QR is not read again. The next Continue sets the phone up
// again: the number, the passkey, which the server still knows and the SDK
// authenticates rather than creating a second one, and the key, which is
// encoded again (a key already holding a credential for this number gets a
// fresh one; nothing on this phone excludes it any more).
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
// DOMContentLoaded — wire up event listeners
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  // Continue
  document.getElementById('login-btn').addEventListener('click', () => login());

  // HOME actions, each busy while its ceremony runs
  const busy = async (btn, run) => {
    btn.classList.add('loading');
    btn.setAttribute('aria-busy', 'true');
    btn.setAttribute('aria-disabled', 'true');
    try {
      await run();
    } finally {
      btn.classList.remove('loading');
      btn.removeAttribute('aria-busy');
      btn.removeAttribute('aria-disabled');
    }
  };
  const authenticateBtn = document.getElementById('authenticate-btn');
  authenticateBtn.addEventListener('click', () => busy(authenticateBtn, authenticateStepUp));
  const verifyKeyBtn = document.getElementById('verify-key-btn');
  verifyKeyBtn.addEventListener('click', () => busy(verifyKeyBtn, verifyUsbKey));
  const lostBtn = document.getElementById('lost-key-btn');
  lostBtn.addEventListener('click', () => busy(lostBtn, reportLost));
  const encodeBtn = document.getElementById('encode-key-btn');
  encodeBtn.addEventListener('click', () => busy(encodeBtn, encodeNewKey));

  // Log Out
  document.getElementById('logout-btn').addEventListener('click', () => logOut());

  // The SNA screen: Verify plays the simulated check and Continue settles
  // the gate the caller is waiting on.
  document.getElementById('sna-verify').addEventListener('click', () => runSnaCheck());
  document.getElementById('sna-continue').addEventListener('click', () => finishSna(true));

  // Reset Device
  document.getElementById('reset-device').addEventListener('click', () => purgeStorage());

  // The guide dialog's button, and the second one some guides show
  document.getElementById('guide-start').addEventListener('click', () => hideGuide('ok'));
  document.getElementById('guide-alt').addEventListener('click', () => hideGuide('alt'));

  // Copy buttons in the challenge blocks (the rows are made on demand)
  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('.btn-copy');
    if (!btn) return;
    e.preventDefault();
    e.stopPropagation();
    const text = btn.closest('details')?.querySelector('.challenge-full')?.textContent;
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      const originalHTML = btn.innerHTML;
      btn.textContent = '✓';
      btn.classList.add('copied');
      setTimeout(() => {
        btn.innerHTML = originalHTML;
        btn.classList.remove('copied');
      }, 1500);
    } catch (err) {
      console.error('Copy failed:', err);
    }
  });

  // Restore username from localStorage
  const savedUsername = localStorage.getItem('username');
  if (savedUsername) {
    document.getElementById('username').value = savedUsername;
  }

  // Auto-populate from URL parameters. ?userid= is what the registration
  // page's QR code carries: the user scans it and arrives with their number
  // already in the field, having typed nothing. Continue then reads the key,
  // which holds that number, and sets this phone up with it.
  const urlParams = new URLSearchParams(window.location.search);
  const urlUserId = urlParams.get('userid');
  if (urlUserId) {
    document.getElementById('username').value = urlUserId;
    localStorage.setItem('username', urlUserId);
  }

  // ?sna= is for the presenter: nomatch or unsupported plays that IDlayr
  // outcome on the next number check, once, and the default success returns.
  const urlSna = urlParams.get('sna');
  if (urlSna) {
    sessionStorage.setItem(SNA_SCENARIO_KEY, urlSna.trim().toLowerCase());
    urlParams.delete('sna');
    const query = urlParams.toString();
    history.replaceState(null, '', location.pathname + (query ? `?${query}` : ''));
  }

  // Show hint when clicking the read-only username field: the session owns
  // the identity once logged in, and the number check owns it while it runs.
  document.getElementById('username').addEventListener('click', (e) => {
    if (!e.target.readOnly) return;
    showFlash('flash-status',
      STATE.loginID ? 'Log Out to change the User ID' : 'Finish the number check first',
      'failure', 3000);
  });

  // Persist username on input, update button state, and recheck the device
  let usernameTimer = null;
  document.getElementById('username').addEventListener('input', () => {
    const user = getUsername();
    localStorage.setItem('username', user);
    document.getElementById('login-btn').disabled = !user;

    if (usernameTimer) clearTimeout(usernameTimer);
    usernameTimer = setTimeout(() => updateUI(), 800);
  });

  updateUI();
});
