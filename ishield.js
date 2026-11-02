/**
 * ishield.js -- FIDO USB Key (Raw WebAuthn get)
 *
 * This module reads a FIDO USB security key (the demo's are Swissbit iShield
 * keys) with the Web Authentication API (navigator.credentials.get). It has
 * ZERO SDK dependencies and never touches the DOM.
 *
 * WHAT IT DOES:
 *   - Reads the key: a get that returns the credential id and the user
 *     handle (the phone number the create wrote there), after the key's PIN
 *     and a touch. The page passes the ids of the keys it has recorded
 *     (allowIds), which sends the browser straight to its security-key
 *     sheet; with none it is an open get
 *   - Provides base64url and SHA-256 encoding utilities used by umfa.js,
 *     key-enroll.js and webauthn-util.js
 *
 * The create that writes a key lives in key-enroll.js (the main page runs it
 * at setup and in recovery, the registration page as a bench tool). The
 * records of which keys a browser has encoded or read, reported lost or
 * replaced live in key-records.js.
 *
 * HOW TO USE:
 *   import { webauthnAuthenticate } from './ishield.js';
 *
 *   // allowIds: the credential ids this phone has recorded (key-records.js)
 *   const result = await webauthnAuthenticate('9135551235', { allowIds: ['K7f...'] });
 *   if (result.success) {
 *     // result.credentialId     -- the credential the key answered with (base64url)
 *     // result.authenticatedUser -- the user handle as text, or null
 *     // result.challenge        -- the challenge we sent (base64url)
 *     // result.clientDataHash   -- SHA-256 hex of the clientDataJSON
 *     // result.signatureHex     -- hex-encoded raw signature bytes
 *     // result.userVerified     -- the key verified the user (its PIN)
 *     // result.signCount        -- the key's counter
 *   } else {
 *     // result.error -- the original Error object (check result.error.name)
 *   }
 *
 * INTEGRATION NOTES:
 *   - Requires HTTPS or localhost (WebAuthn security requirement)
 *   - userVerification: 'required' -- the keys carry a PIN (the customer's
 *     rule, 2026-10-21), so every get asks for it. A key with a PIN is asked
 *     for it by every browser whatever the page says, so asking for it
 *     outright is only honest; the UV flag in the result confirms it.
 *   - allowCredentials names the keys this phone has recorded, each on
 *     transports ['usb', 'nfc'] (allowListFor). A get whose allowed
 *     credentials all live on a security key goes straight to the browser's
 *     security-key sheet; the platform passkey is never offered, since its
 *     id is not in the list. That is the lever that works in Safari, iOS,
 *     Chrome and Firefox alike. hints: ['security-key'] is sent too, but it
 *     is advisory: Chrome 128+ honours it, Safari ignores it (2026-11-01,
 *     when Safari's empty-list get put Touch ID first).
 *   - With no ids the list is empty: the open get, where the key answers
 *     with the discoverable credential it holds and the identity comes back
 *     in the user handle. That is what lets a phone that knows nothing about
 *     the key read it (a second phone adopting a key).
 */

// ---------------------------------------------------------------------------
// Encoding utilities
// ---------------------------------------------------------------------------

/**
 * Converts an ArrayBuffer to a base64url-encoded string.
 *
 * base64url is the URL-safe variant of base64: '+' becomes '-',
 * '/' becomes '_', and trailing '=' padding is stripped. This is the
 * standard encoding for WebAuthn credential IDs and challenge values.
 *
 * @param {ArrayBuffer} buffer - The raw bytes to encode.
 * @returns {string} The base64url-encoded string.
 */
export function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Converts a base64url-encoded string back to an ArrayBuffer.
 *
 * Used to decode stored credential IDs before passing them to
 * navigator.credentials.create() as excludeCredentials entries and to
 * navigator.credentials.get() as allowCredentials entries.
 *
 * @param {string} base64url - The base64url-encoded string to decode.
 * @returns {ArrayBuffer} The decoded raw bytes.
 */
export function base64urlToBuffer(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

/** The transports a FIDO USB key answers on. Every id the page records belongs to one. */
export const KEY_TRANSPORTS = ['usb', 'nfc'];

/** Chrome throws a RangeError on a longer allowCredentials list. */
export const MAX_ALLOW_IDS = 64;

/**
 * The allowCredentials entries for the keys a phone has recorded: each id
 * decoded and marked as living on a USB or NFC key, which is what sends the
 * browser to its security-key sheet rather than the passkey chooser. Blank
 * ids and duplicates are dropped and the list is capped at Chrome's 64,
 * keeping the first ids given (the records are newest first). With no ids
 * the result is empty, which is the open get.
 *
 * @param {string[]} [ids] - Credential ids, base64url.
 * @param {string[]} [transports] - Where the credentials live; the keys' by default.
 * @returns {Array<{type: 'public-key', id: ArrayBuffer, transports: string[]}>}
 */
export function allowListFor(ids = [], transports = KEY_TRANSPORTS) {
  const unique = [...new Set((ids ?? []).filter(id => typeof id === 'string' && id))];
  return unique.slice(0, MAX_ALLOW_IDS).map(id => ({
    type: 'public-key',
    id: base64urlToBuffer(id),
    transports: [...transports]
  }));
}

/**
 * Computes the SHA-256 hash of a string and returns it as a hex string.
 *
 * Used to produce human-readable representations of challenge data for
 * display purposes, and by umfa.js to hash clientDataJSON before display.
 *
 * @param {string} input - The string to hash. Must be a string.
 * @returns {Promise<string>} The hex-encoded SHA-256 digest.
 * @throws {TypeError} If input is not a string.
 */
export async function hashSHA256(input) {
  if (typeof input !== 'string') throw new TypeError('hashSHA256 expects a string input.');
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const bytes = new Uint8Array(digest);
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

/** Hex of raw bytes, for the signature. */
function toHex(buffer) {
  return Array.from(new Uint8Array(buffer), byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * The two things an assertion's authenticator data says that the page shows:
 * the flags byte (user present, user verified) and the sign count. The full
 * parser in webauthn-util.js handles create responses too; a get has no
 * attested credential data, so this is all there is to read.
 */
function assertionFlags(authenticatorData) {
  const bytes = new Uint8Array(authenticatorData);
  const flags = bytes[32];
  return {
    userPresent: !!(flags & 0x01),
    userVerified: !!(flags & 0x04),
    signCount: new DataView(authenticatorData).getUint32(33)
  };
}

// ---------------------------------------------------------------------------
// Core WebAuthn operation
// ---------------------------------------------------------------------------

/**
 * Authenticates a user with their FIDO USB key via raw WebAuthn.
 *
 * The ceremony itself is webauthnIdentify below; this wrapper adds the
 * expected username. The `user` parameter is used to VERIFY the
 * authenticated identity: the `userHandle` returned by the key should match
 * it. A mismatch is logged, not failed -- the caller decides what to do
 * (app.js reconciles the two spellings of a phone number, and stops on a
 * different number).
 *
 * RESULT SHAPES: as webauthnIdentify, plus
 *   Failure: { success: false, error: Error('No user specified.') } when
 *   `user` is empty.
 *
 * @param {string} user - The expected username. Compared with userHandle.
 * @param {{allowIds?: string[]}} [options] - allowIds: the credential ids this
 *   phone has recorded for the user (key-records.js); see webauthnIdentify.
 * @returns {Promise<object>} See webauthnIdentify.
 */
export async function webauthnAuthenticate(user, { allowIds = [] } = {}) {
  if (!user) {
    return { success: false, error: new Error('No user specified.') };
  }

  console.log('[FIDO2 Auth] Starting authentication for user:', user);
  const result = await webauthnIdentify({ allowIds });

  // Log mismatch but don't fail — caller decides what to do
  if (result.success && result.authenticatedUser && result.authenticatedUser !== user) {
    console.warn('[FIDO2 Auth] User mismatch:', { expected: user, got: result.authenticatedUser });
  }
  return result;
}

/**
 * Reads the FIDO key: a raw WebAuthn get with no expected user.
 *
 * The credentials are discoverable (resident), so the key can present its
 * own stored credential without an allowCredentials list, on ANY device,
 * and the identity comes back in the credential's userHandle (the phone
 * number the create wrote there). The page still passes the ids it has
 * recorded (`allowIds`): an allow list whose credentials all live on a
 * security key sends the browser straight to its security-key sheet instead
 * of the passkey chooser, where Touch ID or a platform passkey comes first.
 * With no ids the list is empty, and the chooser is the price of adopting a
 * key this phone has never seen. The credential id that answered is
 * returned too: it is how the page tells a replacement key from the one
 * that was reported lost.
 *
 * Returns a structured result object instead of throwing, so the caller
 * can cleanly branch on success vs. failure and display appropriate messages.
 *
 * RESULT SHAPES:
 *   Success: {
 *     success: true,
 *     credentialId: string,            base64url, the key's own identity
 *     authenticatedUser: string|null,  the user handle as text, or null when
 *                                      the credential carries none
 *     challenge: string,               what we sent, base64url
 *     at: string,                      ISO time of the answer
 *     clientDataHash?: string,         SHA-256 hex of the clientDataJSON
 *     signatureHex?: string,           hex of the raw signature bytes
 *     userPresent?: boolean,           the touch
 *     userVerified?: boolean,          the PIN
 *     signCount?: number               the key's counter
 *   }
 *
 *   Failure: { success: false, error: Error }
 *     - error.name === 'NotAllowedError': cancelled, timed out, wrong PIN,
 *       or nothing on the key for this site
 *     - a platform authenticator (Touch ID) answered instead of the key
 *     - Other error names: unexpected failure
 *
 * @param {{userVerification?: string, allowIds?: string[]}} [options] -
 *   allowIds: the credential ids this phone has recorded, base64url; none
 *   for the open get.
 * @returns {Promise<object>}
 */
export async function webauthnIdentify({ userVerification = 'required', allowIds = [] } = {}) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const allowCredentials = allowListFor(allowIds);

  // The keys this phone knows, on usb/nfc transports, send every browser
  // straight to its security-key sheet. An empty list is the open query: the
  // key answers with whatever discoverable credential it holds and we learn
  // who it is from the userHandle. hints is advisory on top of that: Chrome
  // 128+ skips its passkey picker for it; Safari ignores it.
  try {
    console.log('[FIDO2 Auth] Get with', allowCredentials.length, 'allowed credential(s)');
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge,
        rpId: location.hostname,
        allowCredentials,
        userVerification,
        hints: ['security-key'],
        timeout: 60000
      }
    });
    console.log('[FIDO2 Auth] Success, attachment:', assertion.authenticatorAttachment);

    // Verify a cross-platform authenticator (USB key) was used, not platform (Touch ID)
    if (assertion.authenticatorAttachment === 'platform') {
      return {
        success: false,
        error: new Error('Please use your FIDO USB key, not Touch ID or a platform passkey.')
      };
    }

    const response = assertion.response;

    // Decode userHandle to recover the authenticated username
    let authenticatedUser = null;
    if (response.userHandle && response.userHandle.byteLength > 0) {
      authenticatedUser = new TextDecoder().decode(response.userHandle);
    }

    const result = {
      success: true,
      credentialId: assertion.id,
      authenticatedUser,
      challenge: bufferToBase64url(challenge),
      at: new Date().toISOString()
    };

    // Challenge, signature and flags, for display; their absence does not fail the get
    try {
      result.clientDataHash = await hashSHA256(new TextDecoder().decode(response.clientDataJSON));
      result.signatureHex = toHex(response.signature);
      Object.assign(result, assertionFlags(response.authenticatorData));
    } catch (extractErr) {
      console.warn('[FIDO2 Auth] Could not extract challenge data:', extractErr.message);
    }
    return result;
  } catch (err) {
    console.error('[FIDO2 Auth] Error:', { name: err.name, message: err.message });
    return { success: false, error: err };
  }
}
