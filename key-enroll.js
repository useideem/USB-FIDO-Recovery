/**
 * key-enroll.js -- The discoverable create that puts a phone number on a
 * FIDO USB key
 *
 * One ceremony: a WebAuthn create with the phone number as user.id, stored
 * on the key as a DISCOVERABLE credential, so that a later get with an empty
 * allowCredentials list hands the number back after the key's PIN and a
 * touch -- no account picker, nothing typed.
 *
 * Since 2026-10-31 the main page runs it on the user's own phone: the bank
 * ships a blank key, the phone is bound first (number check, passkey), then
 * the create encodes the key with the verified number, and the same create
 * encodes the blank replacement after a loss. Because the create requires
 * user verification and a blank key has no PIN, the browser's "create a PIN"
 * step is where the user sets the key's PIN. register.html runs the same
 * function from a desktop browser as a bench tool.
 *
 * THE OPTIONS:
 *   - residentKey: 'required'            the key must store the credential and
 *                                        the user handle, or an empty-list get
 *                                        can never find it
 *   - userVerification: 'required'       the key's PIN protects the credential
 *                                        (the customer's rule, 2026-10-21). The
 *                                        browser makes the user set a PIN on a
 *                                        key that has none and asks for it on
 *                                        every touch afterwards, on every
 *                                        device. The key's minimum is four
 *                                        digits; a page can require
 *                                        verification but cannot set, read or
 *                                        size the PIN.
 *   - hints: ['security-key']            WebAuthn L3: skip the platform passkey
 *                                        UI and go straight to the USB key.
 *                                        Advisory, and needs Chrome 128+.
 *   - authenticatorAttachment:           roaming key, never Touch ID
 *     'cross-platform'
 *   - attestation: 'none'                nothing here checks a metadata
 *                                        statement, so don't ask for one
 *
 * The demo's keys were PIN-less until 2026-10-21 (docs/ishield-pinless-
 * discoverable.md has those measurements). With verification required the
 * credProtect extension no longer matters -- every get verifies the user --
 * so it is not sent. Desktop Chrome, which refused the PIN-less create, may
 * now be able to run this one, since the PIN it insisted on is what the
 * create asks for; that is not yet measured (the doc's section 7).
 *
 * STORAGE: localStorage 'ishield_enrollments', one record per credential
 * written from this browser, so a second create for the same number on the
 * same key is excluded. The main page adds the ids it knows from
 * key-records.js (active, lost and replaced) through `excludeIds`, so a lost
 * key that turns up is refused by the key itself (InvalidStateError).
 * Clearing the list removes nothing from any key.
 */

import { base64urlToBuffer, bufferToBase64url } from './ishield.js';
import { parseAuthenticatorData, checkCeremony } from './webauthn-util.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** localStorage key holding the array of enrollment records. */
export const STORAGE_KEY = 'ishield_enrollments';

/** How long the browser waits for the PIN and a key touch before failing. */
export const TIMEOUT_MS = 120000;

export const RP_NAME = 'FIDO Key Recovery Demo';

/** COSE algorithm identifiers offered at create time, in preference order. */
export const COSE_ALGORITHMS = { [-7]: 'ES256', [-8]: 'EdDSA', [-257]: 'RS256' };
export const PUB_KEY_CRED_PARAMS = [-7, -8, -257].map(alg => ({ type: 'public-key', alg }));

/** Friendlier explanations for the DOMException names WebAuthn throws. */
export const ERROR_HINTS = {
  NotAllowedError: 'Cancelled, timed out, the PIN was wrong or not entered, or the key refused.',
  InvalidStateError: 'This key already holds a credential for that phone number, or it is a key this browser has excluded.',
  SecurityError: 'The RP ID is not valid for this origin. Open the page over HTTPS or http://localhost, not an IP address.',
  NotSupportedError: 'The key supports none of the requested algorithms or options.',
  ConstraintError: 'The key cannot store a discoverable credential under these settings, or could not verify the user.',
  AbortError: 'The operation was aborted.'
};

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

export function loadEnrollments() {
  try {
    const list = JSON.parse(localStorage.getItem(STORAGE_KEY));
    return Array.isArray(list) ? list : [];
  } catch (_) {
    return [];
  }
}

export function saveEnrollments(list) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
}

// ---------------------------------------------------------------------------
// The ceremony
// ---------------------------------------------------------------------------

/**
 * The publicKey member of the create call. user.id is the phone number as
 * UTF-8, so a get on the user's phone reads it straight back out of the user
 * handle. A production RP would use random opaque bytes here: the spec says
 * user.id must not contain personal information. Carrying the number IS the
 * demo.
 */
export function createOptions({ phone, displayName, challenge, rpId, excludeCredentials = [] }) {
  return {
    rp: { id: rpId, name: RP_NAME },
    user: { id: new TextEncoder().encode(phone), name: phone, displayName },
    challenge,
    pubKeyCredParams: PUB_KEY_CRED_PARAMS,
    timeout: TIMEOUT_MS,
    excludeCredentials,
    authenticatorSelection: {
      authenticatorAttachment: 'cross-platform',  // roaming USB key, not Touch ID
      residentKey: 'required',                    // discoverable: the key stores the phone number
      requireResidentKey: true,                   // Level 1 compat; ignored where residentKey is understood
      userVerification: 'required'                // the key's PIN, set now if the key has none
    },
    attestation: 'none',
    hints: ['security-key'],                      // Level 3: go straight to the security key UI
    extensions: {
      credProps: true                             // report whether the credential is really discoverable
    }
  };
}

/**
 * Anything that would break the retrieval flow, as one line each, so the page
 * can call it out while the key is still plugged in.
 */
export function enrollmentWarnings(entry, ceremonyOk = true) {
  const warnings = [];
  if (entry.rk === false) {
    warnings.push('The key did not make this credential discoverable, so a phone will not find it. Encode the key again in another browser.');
  }
  if (entry.uvAtCreate === false) {
    warnings.push('The key did not verify the user, so no PIN protects this credential. Set a PIN on the key and encode it again.');
  }
  if (!ceremonyOk) {
    warnings.push('The challenge, origin or RP ID check did not match. Treat this enrollment as suspect.');
  }
  return warnings;
}

/**
 * The credential ids a create for `phone` must refuse: every one this browser
 * wrote for the number, plus the ids the caller knows from elsewhere (the
 * main page passes its key records). Pure, deduplicated, base64url.
 */
export function excludeIdsFor(phone, excludeIds = []) {
  const written = loadEnrollments().filter(c => c.phone === phone).map(c => c.id);
  return [...new Set([...written, ...excludeIds.filter(Boolean)])];
}

/**
 * Writes a discoverable, PIN-protected credential holding the phone number
 * to the inserted key, records it in the shared enrollment list, and reports
 * what the key actually did: whether the credential is really discoverable
 * and whether the user was verified (the PIN was created or entered).
 *
 * A second credential for the same number on the same key is refused through
 * excludeCredentials, built from the list and from `excludeIds`. Transports
 * are left off so the browser tries every way it can reach the key.
 *
 * Throws what navigator.credentials.create throws; ERROR_HINTS explains the
 * names. InvalidStateError is the key saying it already holds one of the
 * excluded credentials: on the main page, a lost or replaced key.
 *
 * @returns {Promise<{ entry: object, rpId: string, checks: object, ceremonyOk: boolean, warnings: string[], ok: boolean }>}
 */
export async function enrollKey({ phone, displayName = phone, excludeIds = [] }) {
  const rpId = location.hostname;
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const excludeCredentials = excludeIdsFor(phone, excludeIds)
    .map(id => ({ type: 'public-key', id: base64urlToBuffer(id) }));
  const publicKey = createOptions({ phone, displayName, challenge, rpId, excludeCredentials });

  const cred = await navigator.credentials.create({ publicKey });
  const r = cred.response;
  const authData = parseAuthenticatorData(r.getAuthenticatorData());
  const checks = await checkCeremony({
    clientDataJSON: r.clientDataJSON, authData, expectedType: 'webauthn.create', challenge, rpId
  });
  const spki = r.getPublicKey?.();  // null when the browser doesn't understand the algorithm

  const entry = {
    id: cred.id,
    phone,
    displayName,
    rk: cred.getClientExtensionResults().credProps?.rk ?? null,
    credProtect: authData.extensions?.credProtect ?? null,
    alg: r.getPublicKeyAlgorithm(),
    publicKey: spki ? bufferToBase64url(spki) : null,
    transports: r.getTransports?.() ?? [],
    aaguid: authData.aaguid ?? null,
    uvAtCreate: authData.flags.UV,
    signCount: authData.signCount,
    challenge: bufferToBase64url(challenge),
    createdAt: new Date().toISOString()
  };
  saveEnrollments([entry, ...loadEnrollments().filter(c => c.id !== entry.id)]);

  const ceremonyOk = checks.type && checks.challenge && checks.origin && checks.rpIdHash;
  const warnings = enrollmentWarnings(entry, ceremonyOk);
  return { entry, rpId, checks, ceremonyOk, warnings, ok: entry.rk !== false && entry.uvAtCreate !== false && ceremonyOk };
}

/**
 * Shares the credential with the other demo devices through the dev server's
 * /credentials list. Absent in production, so a failure is not worth
 * reporting.
 */
export function shareEnrollment(entry, rpId) {
  fetch('./credentials', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...entry, rpId, userName: entry.phone })
  }).catch(() => {});
}

// ---------------------------------------------------------------------------
// Browser detection
// ---------------------------------------------------------------------------

/**
 * Names the browser actually rendering the page and says whether it is
 * desktop Chromium. UA Client Hints first, because a user agent string can
 * report a version that never shipped; WebKit and Gecko do not implement
 * them, so the string is the fallback.
 *
 * @returns {Promise<{ label: string, chromium: boolean, desktop: boolean }>}
 */
export async function detectBrowser() {
  const ua = navigator.userAgent || '';
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

  if (!label) {
    const named = ua.match(/(CriOS|Chrome|Firefox|Version)\/(\d+)/);
    const names = { Version: 'Safari', CriOS: 'Chrome for iOS' };
    label = named ? `${names[named[1]] || named[1]} ${named[2]}` : 'unknown browser';
    chromium = named?.[1] === 'Chrome';
  }

  return { label, chromium, desktop: !/Android|iPhone|iPad|iPod/.test(ua) };
}
