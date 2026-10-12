/**
 * key-enroll.js -- The discoverable create that puts a phone number on an
 * iShield Key, for register.html
 *
 * One ceremony: a WebAuthn create with the attendee's phone number as user.id,
 * stored on the key as a DISCOVERABLE credential, so that later, on any other
 * device, a get with an empty allowCredentials list hands the number back
 * after a touch -- no PIN, no account picker, nothing typed.
 *
 * THE OPTIONS ARE THE MEASURED ONES (docs/ishield-pinless-discoverable.md),
 * the ones the retired booth page (enroll.js) built inline and fido-test.js
 * (the key tester) defaults to:
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
 * This is the only copy of these options in the repo since the booth page
 * was retired (2026-10-12) in favour of register.html; fido-test.js has its
 * own defaults for the tester's controls.
 *
 * RUN THE CREATE IN SAFARI ON A MAC. Desktop Chrome refuses to create a
 * discoverable credential until the key has a PIN, and once the key has a
 * PIN every retrieval device demands it -- which kills the demo. detectBrowser
 * below is how a page finds out it is in desktop Chrome and says so.
 *
 * STORAGE: localStorage 'ishield_enrollments', one record per credential
 * written from this browser, so a second create for the same number on the
 * same key is excluded. The retired booth page wrote the same list, so its
 * records still count. Clearing it removes nothing from any key.
 */

import { base64urlToBuffer, bufferToBase64url } from './ishield.js';
import { CRED_PROTECT_LEVELS, parseAuthenticatorData, checkCeremony } from './webauthn-util.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** localStorage key holding the array of enrollment records. */
export const STORAGE_KEY = 'ishield_enrollments';

/** How long the browser waits for a key touch before failing. */
export const TIMEOUT_MS = 120000;

export const RP_NAME = 'Demo Swissbit';

/** COSE algorithm identifiers offered at create time, in preference order. */
export const COSE_ALGORITHMS = { [-7]: 'ES256', [-8]: 'EdDSA', [-257]: 'RS256' };
export const PUB_KEY_CRED_PARAMS = [-7, -8, -257].map(alg => ({ type: 'public-key', alg }));

/** Friendlier explanations for the DOMException names WebAuthn throws. */
export const ERROR_HINTS = {
  NotAllowedError: 'Cancelled, timed out, or the key refused. In desktop Chrome this is also what a discoverable credential without a PIN looks like.',
  InvalidStateError: 'This key already holds a credential for that phone number. It is already enrolled.',
  SecurityError: 'The RP ID is not valid for this origin. Open the page over HTTPS or http://localhost, not an IP address.',
  NotSupportedError: 'The key supports none of the requested algorithms or options.',
  ConstraintError: 'The key cannot store a discoverable credential under these settings.',
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
 * UTF-8, so a get on any other device reads it straight back out of the user
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
      userVerification: 'discouraged'             // touch only, no PIN
    },
    attestation: 'none',
    hints: ['security-key'],                      // Level 3: go straight to the security key UI
    extensions: {
      credProps: true,                            // report whether the credential is really discoverable
      // Level 1, and deliberately not enforced: Chrome rejects
      // enforceCredentialProtectionPolicy alongside userVerificationOptional
      // as inconsistent. The result shows the level the key applied.
      credentialProtectionPolicy: 'userVerificationOptional'
    }
  };
}

/**
 * Anything that would break the retrieval flow, as one line each, so the page
 * can call it out while the attendee and the key are still there.
 */
export function enrollmentWarnings(entry, ceremonyOk = true) {
  const warnings = [];
  if (entry.rk === false) {
    warnings.push('The key did not make this credential discoverable, so another device will not find it. Enroll again in Safari on a Mac.');
  }
  if (entry.uvAtCreate) {
    warnings.push('This key verified the user, which means it has a PIN set. Every retrieval device will ask for that PIN. Reset the key to make it PIN-less.');
  }
  if (entry.credProtect && entry.credProtect !== 1) {
    warnings.push(`The key applied credProtect level ${entry.credProtect} (${CRED_PROTECT_LEVELS[entry.credProtect] || 'unknown'}). Level 1 is what lets a touch-only lookup see the credential.`);
  }
  if (!ceremonyOk) {
    warnings.push('The challenge, origin or RP ID check did not match. Treat this enrollment as suspect.');
  }
  return warnings;
}

/**
 * Writes a discoverable credential holding the phone number to the inserted
 * key, records it in the shared enrollment list, and reports what the key
 * actually did: whether the credential is really discoverable, which
 * credProtect level it applied, and whether it stayed PIN-less.
 *
 * A second credential for the same number on the same key is refused through
 * excludeCredentials, built from the list. Transports are left off so the
 * browser tries every way it can reach the key.
 *
 * Throws what navigator.credentials.create throws; ERROR_HINTS explains the
 * names.
 *
 * @returns {Promise<{ entry: object, rpId: string, checks: object, ceremonyOk: boolean, warnings: string[], ok: boolean }>}
 */
export async function enrollKey({ phone, displayName, firstName = '', lastName = '' }) {
  const rpId = location.hostname;
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const excludeCredentials = loadEnrollments()
    .filter(c => c.phone === phone)
    .map(c => ({ type: 'public-key', id: base64urlToBuffer(c.id) }));
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
    firstName,
    lastName,
    displayName,
    rk: cred.getClientExtensionResults().credProps?.rk ?? null,
    credProtect: authData.extensions?.credProtect ?? null,
    alg: r.getPublicKeyAlgorithm(),
    publicKey: spki ? bufferToBase64url(spki) : null,
    transports: r.getTransports?.() ?? [],
    aaguid: authData.aaguid ?? null,
    uvAtCreate: authData.flags.UV,
    signCount: authData.signCount,
    createdAt: new Date().toISOString()
  };
  saveEnrollments([entry, ...loadEnrollments().filter(c => c.id !== entry.id)]);

  const ceremonyOk = checks.type && checks.challenge && checks.origin && checks.rpIdHash;
  const warnings = enrollmentWarnings(entry, ceremonyOk);
  return { entry, rpId, checks, ceremonyOk, warnings, ok: entry.rk !== false && !entry.uvAtCreate && ceremonyOk };
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
 * desktop Chromium, which cannot do a PIN-less discoverable create. UA Client
 * Hints first, because a user agent string can report a version that never
 * shipped; WebKit and Gecko do not implement them, so the string is the
 * fallback.
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
