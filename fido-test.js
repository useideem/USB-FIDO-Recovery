/**
 * fido-test.js -- FIDO2 Key Tester (Raw WebAuthn create / get)
 *
 * Standalone test page for exercising a hardware security key directly
 * through navigator.credentials, with no Ideem SDK involved. It exposes the
 * options that matter for a roaming USB key and shows what the key actually
 * did in response.
 *
 * OPTIONS EXPOSED:
 *   - residentKey:      required (discoverable) / discouraged (non-discoverable) / preferred
 *   - userVerification: required / preferred / discouraged -- the spec's
 *                       tri-state; the UV flag in the result is the true/false
 *                       outcome
 *   - credProtect:      browser default / userVerificationOptional / userVerificationRequired
 *   - allowCredentials: empty (discoverable lookup) / all saved / one saved
 *
 * WHAT IT CHECKS ON EVERY RESULT:
 *   - Authenticator data flags (UP, UV, BE, BS) and signature counter
 *   - credProps.rk -- whether the key really made a discoverable credential
 *   - The credProtect level the key applied (authenticator extension output)
 *   - clientDataJSON type, challenge and origin, and the rpIdHash
 *   - The assertion signature, verified locally with the public key saved
 *     when the credential was created
 *
 * SPEC REFERENCES:
 *   - W3C WebAuthn Level 3: https://www.w3.org/TR/webauthn-3/
 *   - FIDO CTAP 2.1:        https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html
 *
 * STORAGE:
 *   Created credentials are remembered in localStorage under
 *   'fido_test_credentials' (ID, public key, options) so Get can target them
 *   and verify signatures. The demo's own storage keys are never touched.
 */

import { bufferToBase64url, base64urlToBuffer } from './ishield.js';
import {
  CRED_PROTECT_LEVELS,
  parseAuthenticatorData,
  setFlagNames,
  checkCeremony
} from './webauthn-util.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** localStorage key holding the array of saved credential records. */
const STORAGE_KEY = 'fido_test_credentials';

/** How long the browser waits for a key touch / PIN before failing. */
const TIMEOUT_MS = 120000;

const RP_NAME = 'Swissbit FIDO Test';

/** COSE algorithm identifiers offered at create time, in preference order. */
const COSE_ALGORITHMS = { [-7]: 'ES256', [-8]: 'EdDSA', [-257]: 'RS256' };
const PUB_KEY_CRED_PARAMS = [-7, -8, -257].map(alg => ({ type: 'public-key', alg }));

/** Sentinel values for the Get credential picker. */
const GET_DISCOVERABLE = '__discoverable__';
const GET_ALL_SAVED = '__all__';
const GET_SERVER = '__server__';

/** Chrome throws a RangeError when allowCredentials holds more than 64 entries. */
const MAX_ALLOW_CREDENTIALS = 64;

const RK_HINTS = {
  required: 'Stored on the key together with the user name. Get works with an empty allow list: the key offers the accounts it holds. Most CTAP 2.1 keys need the PIN to create one, even with user verification discouraged. Creating another for the same user name replaces the old one on the key.',
  discouraged: 'Nothing is stored on the key. The credential ID carries the wrapped private key, so Get only works when that ID is sent in allowCredentials, which means from a browser that saved it.',
  preferred: 'The key decides. The Discoverable pill in the result (credProps.rk) shows what you got.'
};

const UV_HINTS = {
  required: 'The key must verify you (PIN or fingerprint) or the call fails. Result flag UV = true.',
  preferred: 'Verify if the key can, otherwise touch only. The UV flag in the result shows which happened.',
  discouraged: 'Touch only, if the key allows it. Result flag UV is normally false.'
};

const CP_HINTS = {
  '': 'Chrome picks the level itself. For discoverable credentials its choice hides them from a Get with an empty list unless the key verifies you (PIN).',
  userVerificationOptional: 'Level 1. The key offers this credential to a Get with an empty list after just a touch, no PIN. The app\'s keys carry a PIN now (verification required), so the level no longer matters to them.',
  userVerificationRequired: 'Level 3. The key never uses this credential without a PIN or fingerprint.'
};

const GET_HINTS = {
  [GET_DISCOVERABLE]: 'Sends an empty allowCredentials list. Only discoverable credentials can answer, and the key returns the user handle so you learn who signed in. With several accounts on the key, the browser lets you pick one.',
  [GET_ALL_SAVED]: 'Sends every saved credential ID. The key answers with one it recognises.',
  [GET_SERVER]: 'Sends the credential IDs issued for this site, fetched from the dev server (newest 64 at most, since Chrome rejects longer lists). Works on any device, so use it on the phones.',
  single: 'Sends just this credential ID. Works for both types, and is the only way to use a non-discoverable credential.'
};

/** Friendlier explanations for the DOMException names WebAuthn throws. */
const ERROR_HINTS = {
  NotAllowedError: 'Cancelled, timed out, or no matching credential on the key.',
  InvalidStateError: 'The key already holds a credential from the exclude list, so it refused to register a second one.',
  SecurityError: 'The RP ID is not valid for this origin. Open the page via http://localhost or HTTPS, not an IP address.',
  NotSupportedError: 'The key supports none of the requested algorithms or options.',
  ConstraintError: 'The key cannot meet a requirement, such as a discoverable credential or user verification.',
  AbortError: 'The operation was aborted.'
};

// ---------------------------------------------------------------------------
// Saved credentials (localStorage)
// ---------------------------------------------------------------------------

function loadCredentials() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY)) || [];
  } catch (_) {
    return [];
  }
}

function saveCredentials(list) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
}

/** Builds a PublicKeyCredentialDescriptor for allow/exclude lists. */
function toDescriptor(saved) {
  return {
    type: 'public-key',
    id: base64urlToBuffer(saved.id),
    transports: saved.transports?.length ? saved.transports : ['usb', 'nfc']
  };
}

// ---------------------------------------------------------------------------
// Issued credentials (dev server)
// ---------------------------------------------------------------------------

/**
 * Credentials issued for this RP ID, shared by dev-server.mjs so a phone can
 * send IDs created on another device. Empty where the endpoint doesn't exist.
 */
let serverCredentials = [];

async function refreshServerCredentials() {
  try {
    const res = await fetch(`./credentials?rpId=${encodeURIComponent(location.hostname)}`, { cache: 'no-store' });
    serverCredentials = res.ok ? await res.json() : [];
  } catch (_) {
    serverCredentials = [];
  }
  renderGetOptions();
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

function concatBuffers(a, b) {
  const out = new Uint8Array(a.byteLength + b.byteLength);
  out.set(new Uint8Array(a), 0);
  out.set(new Uint8Array(b), a.byteLength);
  return out;
}

/** Replaces binary values with base64url strings so options can be shown as JSON. */
function toDisplayJSON(value) {
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return bufferToBase64url(value);
  if (Array.isArray(value)) return value.map(toDisplayJSON);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, toDisplayJSON(v)]));
  }
  return value;
}

function algName(alg) {
  return COSE_ALGORITHMS[alg] ? `${COSE_ALGORITHMS[alg]} (${alg})` : String(alg);
}

function typeLabel(rk) {
  if (rk === true) return 'Discoverable';
  if (rk === false) return 'Non-discoverable';
  return 'Unknown';
}

/** Serializes a PublicKeyCredential, using toJSON() where the browser has it. */
function credentialToJSON(cred) {
  if (typeof cred.toJSON === 'function') return cred.toJSON();
  const response = {};
  for (const key of ['clientDataJSON', 'attestationObject', 'authenticatorData', 'signature', 'userHandle']) {
    if (cred.response[key]) response[key] = bufferToBase64url(cred.response[key]);
  }
  return {
    id: cred.id,
    rawId: bufferToBase64url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment,
    response,
    clientExtensionResults: cred.getClientExtensionResults()
  };
}

// ---------------------------------------------------------------------------
// Parsing and verification
// ---------------------------------------------------------------------------

/**
 * Converts an ASN.1 DER ECDSA signature -- the form authenticators return
 * for ES256 (WebAuthn L3 §6.5.5) -- into the raw r||s form WebCrypto expects.
 *
 * @param {ArrayBuffer} der - DER-encoded SEQUENCE { INTEGER r, INTEGER s }.
 * @param {number} size - Byte length of each integer (32 for P-256).
 */
function derToRawEcdsa(der, size = 32) {
  const b = new Uint8Array(der);
  if (b[0] !== 0x30) throw new Error('Signature is not DER-encoded');
  let offset = (b[1] & 0x80) ? 2 + (b[1] & 0x7f) : 2;
  const out = new Uint8Array(size * 2);
  for (let i = 0; i < 2; i++) {
    if (b[offset] !== 0x02) throw new Error('Malformed DER signature');
    const len = b[offset + 1];
    let int = b.slice(offset + 2, offset + 2 + len);
    while (int.length > size && int[0] === 0) int = int.slice(1);  // strip sign padding
    if (int.length > size) throw new Error('DER integer too long');
    out.set(int, size * (i + 1) - int.length);
    offset += 2 + len;
  }
  return out;
}

/**
 * Verifies an assertion signature locally with the public key saved at
 * create time. The key signs authenticatorData || SHA-256(clientDataJSON).
 *
 * @returns {Promise<boolean|null>} true/false, or null when this browser's
 *   WebCrypto cannot handle the algorithm.
 */
async function verifySignature(saved, response) {
  const clientDataHash = await crypto.subtle.digest('SHA-256', response.clientDataJSON);
  const signedData = concatBuffers(response.authenticatorData, clientDataHash);
  const spki = base64urlToBuffer(saved.publicKey);

  if (saved.alg === -7) {
    const key = await crypto.subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, derToRawEcdsa(response.signature), signedData);
  }
  if (saved.alg === -257) {
    const key = await crypto.subtle.importKey('spki', spki, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, response.signature, signedData);
  }
  if (saved.alg === -8) {
    let key;
    try {
      key = await crypto.subtle.importKey('spki', spki, { name: 'Ed25519' }, false, ['verify']);
    } catch (_) {
      return null;  // Ed25519 not in this browser's WebCrypto
    }
    return crypto.subtle.verify('Ed25519', key, response.signature, signedData);
  }
  return null;
}

// ---------------------------------------------------------------------------
// UI helpers
// ---------------------------------------------------------------------------

const $ = id => document.getElementById(id);

let flashTimer = null;

/** Shows a flash message. A duration of 0 keeps it until the next one. */
function showFlash(message, state, duration = 6000) {
  const el = $('flash-status');
  clearTimeout(flashTimer);
  el.textContent = message;
  el.className = 'flash ' + state;
  if (duration) {
    flashTimer = setTimeout(() => { el.textContent = ''; el.className = 'flash'; }, duration);
  }
}

function radioValue(name) {
  return document.querySelector(`input[name="${name}"]:checked`).value;
}

/** Marks the running ceremony's button as loading and blocks the other one. */
function setBusy(busy, activeBtn) {
  for (const id of ['create-btn', 'get-btn']) {
    const btn = $(id);
    if (btn === activeBtn) btn.classList.toggle('loading', busy);
    else btn.disabled = busy;
  }
}

function flagPill(label, on) {
  return { label, value: on ? 'true' : 'false', state: on ? 'success' : 'neutral' };
}

function checkPill(label, ok) {
  return { label, value: ok ? 'ok' : 'MISMATCH', state: ok ? 'success' : 'danger' };
}

function renderPills(pills) {
  $('result-pills').replaceChildren(...pills.map(({ label, value, state }) => {
    const pill = document.createElement('span');
    pill.className = `pill pill-${state}`;
    const b = document.createElement('b');
    b.textContent = value;
    pill.append(`${label}: `, b);
    return pill;
  }));
}

/**
 * Sends an event to the local dev server's /log endpoint (dev-server.mjs) so
 * results from any browser or phone land in one file. Fire-and-forget: where
 * there is no /log (Vercel, python http.server) the request just fails quietly.
 */
async function sendLog(event) {
  // navigator.userAgent can be frozen or overridden, so it is not a reliable
  // version check. UA Client Hints report the real one, which decides whether
  // this browser understands the `hints` member (Chrome 128+).
  let uaData = null;
  try {
    uaData = await (navigator.userAgentData?.getHighEntropyValues(
      ['fullVersionList', 'platform', 'platformVersion', 'model']
    ) ?? null);
  } catch (_) { /* unsupported, or the user agent declined */ }
  const body = JSON.stringify({
    at: new Date().toISOString(),
    origin: location.origin,
    userAgent: navigator.userAgent,
    ...(uaData && { uaData }),
    ...event
  });
  fetch('./log', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body, keepalive: true })
    .catch(() => {});
}

function showResult({ title, pills, summary, request, response }) {
  sendLog({
    event: 'result',
    title,
    pills: pills.map(p => `${p.label}: ${p.value}`),
    summary: toDisplayJSON(summary),
    request: toDisplayJSON(request)
  });
  $('result-section').hidden = false;
  $('result-title').textContent = title;
  renderPills(pills);
  $('result-summary').textContent = JSON.stringify(toDisplayJSON(summary), null, 2);
  $('result-request').textContent = JSON.stringify(toDisplayJSON(request), null, 2);
  $('result-response').textContent = response ? JSON.stringify(response, null, 2) : '--';
}

function showError(title, err, request) {
  const hint = ERROR_HINTS[err?.name];
  console.error(`[FIDO Test] ${title}:`, err);
  showResult({
    title,
    pills: [{ label: 'Error', value: err?.name || 'Error', state: 'danger' }],
    summary: { error: err?.name, message: err?.message, hint: hint || null },
    request,
    response: null
  });
  showFlash(`${err?.name || 'Error'}: ${hint || err?.message || 'Unknown error'}`, 'failure', 10000);
}

// ---------------------------------------------------------------------------
// Rendering: saved credentials and the Get picker
// ---------------------------------------------------------------------------

function renderCredentials() {
  const list = loadCredentials();
  const body = $('creds-body');
  $('clear-creds').disabled = list.length === 0;

  if (list.length === 0) {
    const td = document.createElement('td');
    td.colSpan = 7;
    td.className = 'ft-empty';
    td.textContent = 'None yet. Create one above.';
    const tr = document.createElement('tr');
    tr.append(td);
    body.replaceChildren(tr);
    return;
  }

  body.replaceChildren(...list.map(c => {
    const tr = document.createElement('tr');
    const cells = [
      c.userName,
      typeLabel(c.rk),
      COSE_ALGORITHMS[c.alg] || String(c.alg),
      c.uvAtCreate ? 'yes' : 'no',
      new Date(c.createdAt).toLocaleString()
    ];
    for (const text of cells) {
      const td = document.createElement('td');
      td.textContent = text;
      tr.append(td);
    }

    const idCell = document.createElement('td');
    idCell.className = 'ft-mono';
    idCell.textContent = c.id.slice(0, 12) + '…';
    idCell.title = c.id;
    tr.append(idCell);

    const actionCell = document.createElement('td');
    const del = document.createElement('button');
    del.className = 'btn-danger-small';
    del.textContent = 'Delete';
    del.setAttribute('aria-label', `Delete saved credential for ${c.userName}`);
    del.addEventListener('click', () => {
      saveCredentials(loadCredentials().filter(x => x.id !== c.id));
      renderCredentials();
      renderGetOptions();
    });
    actionCell.append(del);
    tr.append(actionCell);
    return tr;
  }));
}

/** Rebuilds the Get picker, keeping (or setting) the selection where possible. */
function renderGetOptions(selectId) {
  const select = $('get-credential');
  const wanted = selectId ?? select.value;
  const list = loadCredentials();
  const options = [
    [GET_DISCOVERABLE, 'Any discoverable credential on the key (empty list)'],
    ...(serverCredentials.length
      ? [[GET_SERVER, `Issued credentials from the server (${Math.min(serverCredentials.length, MAX_ALLOW_CREDENTIALS)} IDs)`]]
      : []),
    ...(list.length > 1 ? [[GET_ALL_SAVED, `All ${list.length} saved credentials`]] : []),
    ...list.map(c => [c.id, `${c.userName}: ${typeLabel(c.rk)}, ${c.id.slice(0, 10)}…`])
  ];
  select.replaceChildren(...options.map(([value, label]) => new Option(label, value)));
  select.value = options.some(([value]) => value === wanted) ? wanted : GET_DISCOVERABLE;
  updateHints();
}

function updateHints() {
  $('create-rk-hint').textContent = RK_HINTS[radioValue('create-rk')];
  $('create-uv-hint').textContent = UV_HINTS[radioValue('create-uv')];
  $('create-cp-hint').textContent = CP_HINTS[radioValue('create-cp')];
  $('get-uv-hint').textContent = UV_HINTS[radioValue('get-uv')];
  const choice = $('get-credential').value;
  $('get-credential-hint').textContent = GET_HINTS[choice] || GET_HINTS.single;
}

// ---------------------------------------------------------------------------
// Ceremonies
// ---------------------------------------------------------------------------

/**
 * Registers a new credential on the key with the chosen options, then saves
 * its ID and public key so Get can target it and verify its signatures.
 */
async function createCredential() {
  const userName = $('create-username').value.trim();
  if (!userName) return showFlash('Enter a user name first', 'failure');

  // user.id is the UTF-8 user name so the user handle reads back as text on
  // Get. A real RP should use random, opaque bytes: the spec says user.id
  // must not contain personal information.
  const userId = new TextEncoder().encode(userName);
  if (userId.length > 64) return showFlash('User name must be 64 bytes or less (it is used as user.id)', 'failure');

  const rpId = location.hostname;
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const residentKey = radioValue('create-rk');
  const credProtect = radioValue('create-cp');
  const excludeCredentials = $('create-exclude').checked
    ? loadCredentials().filter(c => c.userName === userName).map(toDescriptor)
    : [];

  const publicKey = {
    rp: { id: rpId, name: RP_NAME },
    user: { id: userId, name: userName, displayName: userName },
    challenge,
    pubKeyCredParams: PUB_KEY_CRED_PARAMS,
    timeout: TIMEOUT_MS,
    excludeCredentials,
    authenticatorSelection: {
      authenticatorAttachment: 'cross-platform',       // Roaming key, not Touch ID
      residentKey,
      requireResidentKey: residentKey === 'required',  // Level 1 compat; ignored when residentKey is understood
      userVerification: radioValue('create-uv')
    },
    attestation: 'none',                              // the page no longer offers a choice
    hints: ['security-key'],                           // Level 3: go straight to the security key UI
    extensions: {
      credProps: true,                                 // Report whether the credential is discoverable
      // An explicit level overrides Chrome's default. Not enforced: Chrome rejects
      // enforceCredentialProtectionPolicy with userVerificationOptional as
      // "inconsistent" (NotSupportedError). The result shows the level applied.
      ...(credProtect && { credentialProtectionPolicy: credProtect })
    }
  };

  const btn = $('create-btn');
  setBusy(true, btn);
  showFlash('Insert and touch your security key...', 'success', 0);

  try {
    const cred = await navigator.credentials.create({ publicKey });
    const r = cred.response;
    const authData = parseAuthenticatorData(r.getAuthenticatorData());
    const checks = await checkCeremony({
      clientDataJSON: r.clientDataJSON, authData, expectedType: 'webauthn.create', challenge, rpId
    });
    const alg = r.getPublicKeyAlgorithm();
    const spki = r.getPublicKey?.();  // null when the browser doesn't understand the algorithm
    const transports = r.getTransports?.() ?? [];
    const rk = cred.getClientExtensionResults().credProps?.rk;

    const entry = {
      id: cred.id,
      userName,
      rk: rk ?? null,
      alg,
      publicKey: spki ? bufferToBase64url(spki) : null,
      transports,
      aaguid: authData.aaguid ?? null,
      uvAtCreate: authData.flags.UV,
      signCount: authData.signCount,
      createdAt: new Date().toISOString()
    };
    saveCredentials([entry, ...loadCredentials().filter(c => c.id !== entry.id)]);
    renderCredentials();
    renderGetOptions();  // keep the current Get choice (e.g. the empty-list lookup)

    // Share the credential with other devices through the dev server
    fetch('./credentials', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...entry, rpId })
    }).then(res => res.ok && refreshServerCredentials()).catch(() => {});

    const rkPill = rk === undefined
      ? { label: 'Discoverable', value: 'not reported', state: 'unknown' }
      : { label: 'Discoverable', value: rk ? 'true' : 'false', state: rk ? 'success' : 'neutral' };
    const cpLevel = authData.extensions?.credProtect;
    const cpPill = cpLevel
      ? { label: 'credProtect', value: `${cpLevel} (${CRED_PROTECT_LEVELS[cpLevel] || 'unknown'})`, state: cpLevel === 1 ? 'success' : 'unknown' }
      : { label: 'credProtect', value: 'not reported', state: 'neutral' };

    showResult({
      title: `Created credential for ${userName}`,
      pills: [
        rkPill,
        cpPill,
        flagPill('UP', authData.flags.UP),
        flagPill('UV', authData.flags.UV),
        flagPill('BE', authData.flags.BE),
        flagPill('BS', authData.flags.BS),
        { label: 'Alg', value: COSE_ALGORITHMS[alg] || String(alg), state: 'neutral' },
        checkPill('Challenge', checks.challenge),
        checkPill('Origin', checks.origin),
        checkPill('RP ID hash', checks.rpIdHash)
      ],
      summary: {
        credentialId: cred.id,
        credentialIdBytes: cred.rawId.byteLength,
        discoverable: rk ?? 'not reported (browser did not return credProps)',
        credProtect: {
          requested: credProtect || 'browser default',
          appliedByKey: cpLevel ? `${cpLevel} (${CRED_PROTECT_LEVELS[cpLevel] || 'unknown'})` : 'not reported'
        },
        authenticatorExtensions: authData.extensions ?? null,
        algorithm: algName(alg),
        publicKeySaved: !!spki,
        aaguid: authData.aaguid ?? null,
        transports,
        authenticatorAttachment: cred.authenticatorAttachment,
        flags: `${authData.flagsByte} (${setFlagNames(authData.flags)})`,
        signCount: authData.signCount,
        checks: {
          type: checks.type,
          challenge: checks.challenge,
          origin: checks.origin,
          rpIdHash: checks.rpIdHash
        },
        clientData: checks.clientData
      },
      request: publicKey,
      response: credentialToJSON(cred)
    });
    showFlash('Credential created', 'success');
  } catch (err) {
    showError('Create failed', err, publicKey);
  } finally {
    setBusy(false, btn);
  }
}

/**
 * Asks the key to sign a fresh challenge, then checks the result: client
 * data, rpIdHash, signature (against the saved public key) and sign count.
 */
async function getAssertion() {
  const choice = $('get-credential').value;
  const saved = loadCredentials();
  const targets = choice === GET_DISCOVERABLE ? []
    : choice === GET_SERVER ? serverCredentials.slice(0, MAX_ALLOW_CREDENTIALS)
    : choice === GET_ALL_SAVED ? saved
    : saved.filter(c => c.id === choice);
  if (choice !== GET_DISCOVERABLE && targets.length === 0) {
    return showFlash('That saved credential no longer exists', 'failure');
  }

  const rpId = location.hostname;
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const publicKey = {
    challenge,
    rpId,
    allowCredentials: targets.map(toDescriptor),
    userVerification: radioValue('get-uv'),
    timeout: TIMEOUT_MS,
    hints: ['security-key']
  };

  const btn = $('get-btn');
  setBusy(true, btn);
  showFlash('Insert and touch your security key...', 'success', 0);

  try {
    const cred = await navigator.credentials.get({ publicKey });
    const r = cred.response;
    const authData = parseAuthenticatorData(r.authenticatorData);
    const checks = await checkCeremony({
      clientDataJSON: r.clientDataJSON, authData, expectedType: 'webauthn.get', challenge, rpId
    });

    const savedMatch = saved.find(c => c.id === cred.id);
    const match = savedMatch || serverCredentials.find(c => c.id === cred.id);

    // Signature: needs the public key saved when this browser created the credential
    let signatureOk = null;
    let signatureNote = null;
    if (!match) {
      signatureNote = 'Credential is not saved in this browser or on the server, so there is no public key to check against';
    } else if (!match.publicKey) {
      signatureNote = 'The browser did not expose the public key at create time';
    } else {
      try {
        signatureOk = await verifySignature(match, r);
        if (signatureOk === null) signatureNote = `${algName(match.alg)} is not supported by this browser's WebCrypto`;
      } catch (err) {
        signatureOk = false;
        signatureNote = err.message;
      }
    }
    const signaturePill = signatureOk === null
      ? { label: 'Signature', value: 'not checked', state: 'unknown' }
      : { label: 'Signature', value: signatureOk ? 'verified' : 'INVALID', state: signatureOk ? 'success' : 'danger' };

    // Sign count must go up on every use, unless the key doesn't keep a counter (always 0)
    let counterPill = { label: 'Sign count', value: String(authData.signCount), state: 'neutral' };
    if (match) {
      if (authData.signCount === 0 && match.signCount === 0) {
        counterPill = { label: 'Sign count', value: '0 (no counter)', state: 'neutral' };
      } else if (authData.signCount > match.signCount) {
        counterPill = { label: 'Sign count', value: `${match.signCount} → ${authData.signCount}`, state: 'success' };
      } else {
        counterPill = { label: 'Sign count', value: `${authData.signCount}, not above ${match.signCount}`, state: 'danger' };
      }
      match.signCount = authData.signCount;
      match.lastUsedAt = new Date().toISOString();
      saveCredentials(saved);
    }

    const userHandleBytes = r.userHandle && r.userHandle.byteLength ? r.userHandle : null;
    const userHandleText = userHandleBytes ? new TextDecoder().decode(userHandleBytes) : null;

    showResult({
      title: `Assertion from ${match ? match.userName : userHandleText || 'unknown credential'}`,
      pills: [
        { label: 'User handle', value: userHandleText ?? 'none', state: userHandleText ? 'success' : 'neutral' },
        flagPill('UP', authData.flags.UP),
        flagPill('UV', authData.flags.UV),
        flagPill('BE', authData.flags.BE),
        flagPill('BS', authData.flags.BS),
        signaturePill,
        counterPill,
        checkPill('Challenge', checks.challenge),
        checkPill('Origin', checks.origin),
        checkPill('RP ID hash', checks.rpIdHash)
      ],
      summary: {
        credentialId: cred.id,
        knownFrom: savedMatch ? 'this browser' : match ? 'server' : null,
        savedAs: match ? { userName: match.userName, type: typeLabel(match.rk), algorithm: algName(match.alg) } : null,
        userHandle: userHandleBytes ? { text: userHandleText, base64url: bufferToBase64url(userHandleBytes) } : null,
        signature: { verified: signatureOk, note: signatureNote },
        flags: `${authData.flagsByte} (${setFlagNames(authData.flags)})`,
        signCount: authData.signCount,
        authenticatorAttachment: cred.authenticatorAttachment,
        checks: {
          type: checks.type,
          challenge: checks.challenge,
          origin: checks.origin,
          rpIdHash: checks.rpIdHash
        },
        clientData: checks.clientData
      },
      request: publicKey,
      response: credentialToJSON(cred)
    });
    renderCredentials();
    showFlash(signatureOk === false ? 'Assertion received, but the signature did not verify' : 'Assertion received',
      signatureOk === false ? 'failure' : 'success');
  } catch (err) {
    showError('Get failed', err, publicKey);
  } finally {
    setBusy(false, btn);
  }
}

/**
 * Names the browser actually rendering this page. navigator.userAgent can be
 * frozen or overridden -- an in-app WebView often reports a version that never
 * shipped -- while UA Client Hints report the real brand and version. The
 * `hints` member that sends a get straight to the security key UI needs
 * Chrome 128 or newer, so the version decides whether that lever works here.
 */
async function showBrowserInfo() {
  const ua = navigator.userAgent;
  let label = null;
  let chromiumMajor = null;

  try {
    const data = await (navigator.userAgentData?.getHighEntropyValues(['fullVersionList']) ?? null);
    const brand = data?.fullVersionList?.find(b => !/not.a.brand/i.test(b.brand));
    if (brand) {
      label = `${brand.brand} ${brand.version}`;
      chromiumMajor = parseInt(brand.version, 10);
    }
  } catch (_) { /* unsupported, or the user agent declined */ }

  if (!label) {                    // WebKit and Gecko do not implement UA Client Hints
    const named = ua.match(/(CriOS|Chrome|Firefox|Version)\/(\d+)/);
    const names = { Version: 'Safari', CriOS: 'Chrome for iOS' };
    if (named) {
      label = `${names[named[1]] || named[1]} ${named[2]} (from the user agent string)`;
      if (named[1] === 'Chrome') chromiumMajor = Number(named[2]);
    } else {
      label = 'unknown';
    }
  }

  const notes = [];
  if (/;\s*wv\)/.test(ua)) notes.push('in-app WebView, not the full browser');
  if (chromiumMajor !== null) {
    notes.push(chromiumMajor >= 128
      ? 'new enough for the security key hint'
      : 'too old for the security key hint, which needs Chrome 128+');
  }
  $('browser-info').textContent = `Browser: ${label}${notes.length ? ' - ' + notes.join('; ') : ''}`;
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', () => {
  sendLog({ event: 'load', savedCredentials: loadCredentials().length });
  showBrowserInfo();
  renderCredentials();
  renderGetOptions();
  refreshServerCredentials();

  for (const input of document.querySelectorAll('input[type="radio"]')) {
    input.addEventListener('change', updateHints);
  }
  $('get-credential').addEventListener('change', updateHints);

  $('create-btn').addEventListener('click', createCredential);
  $('get-btn').addEventListener('click', getAssertion);

  $('clear-creds').addEventListener('click', () => {
    saveCredentials([]);
    renderCredentials();
    renderGetOptions();
    showFlash('Saved credentials cleared from this browser (the key is unchanged)', 'success');
  });

  // WebAuthn needs a secure context and an RP ID that is a domain, not an IP
  let problem = null;
  if (!window.PublicKeyCredential) {
    problem = 'This browser does not support WebAuthn.';
  } else if (!window.isSecureContext) {
    problem = 'WebAuthn needs HTTPS or http://localhost.';
  } else if (/^\[|^\d+(\.\d+){3}$/.test(location.hostname)) {
    problem = `Open this page via localhost, not ${location.hostname}. WebAuthn does not accept an IP address as the RP ID.`;
  }
  if (problem) {
    showFlash(problem, 'failure', 0);
    $('create-btn').disabled = true;
    $('get-btn').disabled = true;
  }
});
