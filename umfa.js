/**
 * umfa.js -- Ideem ZSM + Passkeys+ Integration
 *
 * This module wraps the Ideem ZSM Client SDK (@ideem/zsm-client-sdk) and
 * Passkeys+ plugin (@ideem/plugins.passkeys-plus) to provide passwordless
 * multi-factor authentication using Zero Share MPC cryptography.
 *
 * It has ONE dependency from this project: hashSHA256 from ishield.js
 * (a pure crypto utility with no DOM access).
 *
 * WHAT IT DOES:
 *   - Loads app config from zsm_app_config.json at module initialization
 *   - Initializes the UMFAClient for a given user (cached per user)
 *   - Checks whether a user has ZSM and/or Passkey credentials enrolled
 *   - Enrolls a user with ZSM + optional Passkeys+
 *   - Authenticates a user with ZSM + optional Passkeys+
 *   - Validates authentication tokens against the Ideem server
 *
 * HOW TO USE:
 *   import { initializeZSMClient, checkAllEnrollment, enroll, authenticate } from './umfa.js';
 *
 *   // Initialize the client for a user (must be called before check/enroll/auth)
 *   await initializeZSMClient('alice');
 *
 *   // Check enrollment status (ZSM + Passkeys+)
 *   const status = await checkAllEnrollment('alice');
 *   // status = { hasZSMCred: true, hasRemotePasskey: true }
 *   // status = false if not enrolled or on error
 *
 *   // Enroll the user (ZSM + Passkeys+)
 *   const enrollResult = await enroll('alice', true);
 *   // Returns the credential object on success, false if already enrolled,
 *   // or an Error instance on SDK failure.
 *
 *   // Authenticate
 *   const auth = await authenticate('alice', true);
 *   if (auth.success) {
 *     // auth.credential    -- the raw credential object from the SDK
 *     // auth.challengeData -- { challenge: string, signedChallenge: string }
 *                          //    for display purposes (may be absent)
 *   }
 *
 * CONFIG (zsm_app_config.json):
 *   {
 *     "application_id": "...",           // Your Ideem application ID
 *     "api_key": "...",                  // Client-side API key
 *     "server_key": "...",               // Server-side key for token validation
 *     "validate_url": "...",             // Token validation endpoint URL
 *     "region": "demo",                  // Environment region
 *     "application_environment": "..."   // 'test' or 'production'
 *   }
 *
 * LOCALHOST DEV MODE:
 *   When running on localhost (detected via window.location.host), all
 *   hex credential values in the config are zeroed out and
 *   application_environment is set to 'test'. This allows the app to
 *   initialize without real Ideem server credentials during development.
 *   On Vercel (or any non-localhost origin), real config values are used.
 *
 * ZSM TERMINOLOGY:
 *   - ZSMCred / hasZSMCred: the user's Zero Share MPC secret share,
 *     stored in IndexedDB on the device
 *   - RemotePasskey / hasRemotePasskey: a Passkeys+ (FIDO2 passkey)
 *     credential registered with the Ideem server for this user
 *   - UMFA: User-centric Multi-Factor Authentication -- Ideem's protocol
 */

import { UMFAClient } from '@ideem/zsm-client-sdk';

import { hashSHA256 } from './ishield.js';

// ---------------------------------------------------------------------------
// Module-level state (private)
// ---------------------------------------------------------------------------

/** Loaded config from zsm_app_config.json. Null until configLoaded resolves. */
let zsmAppConfig = null;

/** Active UMFAClient instance. Null when logged out or before init. */
let umfaClient = null;

/**
 * Promise that resolves when zsm_app_config.json has been fetched and parsed.
 * All exported functions await this before using zsmAppConfig.
 *
 * The localhost override zeroes out hex credentials so the SDK initializes
 * in test mode without needing real Ideem server credentials.
 */
const configLoaded = fetch('./zsm_app_config.json')
  .then(res => res.json())
  .then(config => {
    // Localhost override: zero out hex credential segments so the app
    // initializes without real Ideem server credentials.
    // On Vercel, real credentials from zsm_app_config.json are used as-is.
    if (/localhost:\d+/.test(window.location.host)) {
      for (const key in config) {
        if (typeof config[key] === 'string') {
          config[key] = config[key].replace(/[a-f0-9]{4}/g, '0000');
        }
      }
      config.application_environment = 'TEST';
      console.log('[CONFIG] Using localhost test credentials');
    }
    console.log('[CONFIG] Loaded:', JSON.stringify(config, null, 2));
    zsmAppConfig = config;
  });

// ---------------------------------------------------------------------------
// Exported functions
// ---------------------------------------------------------------------------

/**
 * Initializes (or reuses) the UMFAClient for the given user.
 *
 * This must be called before checkAllEnrollment(), enroll(), or authenticate().
 * It is safe to call multiple times -- it caches the client and only creates
 * a new instance when the user changes (different consumer_id).
 *
 * The function waits for zsm_app_config.json to finish loading before
 * proceeding, so callers do not need to manage config loading separately.
 *
 * INTEGRATION NOTE:
 *   Each UMFAClient is bound to a specific consumer_id (username). If the
 *   active user changes, a new client is created automatically. After logout,
 *   call resetClient() to clear the cached instance.
 *
 * @param {string} user - The username (consumer_id) to initialize the client for.
 * @returns {Promise<UMFAClient>} The initialized client instance.
 * @throws {Error} If the config failed to load or user is empty.
 */
export async function initializeZSMClient(user) {
  await configLoaded;

  if (!user) throw new Error('User identifier is empty.');

  if (!zsmAppConfig) {
    throw new Error('zsm_app_config.json failed to load.');
  }

  const needsNewClient = !umfaClient ||
    (umfaClient.config && umfaClient.config.consumer_id !== user);

  if (needsNewClient) {
    const clientConfig = { ...zsmAppConfig, consumer_id: user };
    console.log('[UMFA] Creating client with:', JSON.stringify(clientConfig, null, 2));
    umfaClient = new UMFAClient(clientConfig);
    await umfaClient.finished();
    console.log('[UMFA] Client ready, internal config:', JSON.stringify(umfaClient.config, null, 2));
  }

  return umfaClient;
}

/**
 * Resets the cached UMFAClient instance.
 *
 * Call this on logout so that the next initializeZSMClient() call creates
 * a fresh client. This prevents stale state from persisting across sessions.
 *
 * @returns {void}
 */
export function resetClient() {
  umfaClient = null;
}

/**
 * Checks whether the given user has ZSM and Passkeys+ credentials enrolled.
 *
 * Calls the SDK's checkAllEnrollments() which returns the full enrollment
 * status for both ZSM and Passkeys+:
 *   { hasZSMCred: boolean, hasRemotePasskey: boolean, ... }
 *
 * Returns false on error or if not enrolled, so callers can use a simple
 * truthy check to determine if the device is trusted.
 *
 * IMPORTANT: initializeZSMClient(user) must be called before this function.
 *
 * @param {string} user - The username to check enrollment for.
 * @returns {Promise<object|false>} Enrollment status object, or false on failure.
 */
export async function checkAllEnrollment(user) {
  console.log('[checkAllEnrollment] Input:', { user });
  try {
    const status = await umfaClient.checkAllEnrollments(user);
    const result = status instanceof Error ? false : status;
    console.log('[checkAllEnrollment] Result:', JSON.stringify(result, null, 2));
    return result;
  } catch (err) {
    console.error('[checkAllEnrollment] Error:', err);
    return false;
  }
}

/**
 * Enrolls the user with ZSM and optionally Passkeys+.
 *
 * This is the last step of setting a phone up (after the key touch and the
 * number check in app.js). It creates the user's ZSM secret share in
 * IndexedDB and, if usingPasskeysPlus is truthy, registers a Passkeys+
 * credential with the Ideem server. On a browser that holds no share for a
 * user whose passkey the server already knows, the SDK's 'required' mode
 * authenticates that passkey and rebuilds the share here instead of
 * registering a second passkey.
 *
 * RETURN VALUES:
 *   - Credential object (truthy): enrollment succeeded
 *   - false: user is already enrolled
 *   - Error instance: SDK-level failure -- show an error to the user
 *
 * On success, the token is automatically validated with the server via
 * validateToken() before returning.
 *
 * IMPORTANT: initializeZSMClient(user) must be called before this function.
 *
 * @param {string} user - The username to enroll.
 * @param {boolean|string} [usingPasskeysPlus=false] - If true, enrolls both
 *   ZSM and Passkeys+ (the SDK's "preferred" mode: a cancelled passkey falls
 *   back to a ZSM-only enrollment). If false, enrolls ZSM only. The SDK's
 *   string modes pass through unchanged; 'required' makes the passkey
 *   mandatory, which the demo page uses everywhere (since 2026-10-21): the
 *   passkey is the recovery factor, so a cancelled sheet has to fail rather
 *   than leave a device bound without one.
 * @returns {Promise<object|false|Error>} The enrollment credential, false if
 *   already enrolled, or an Error on failure.
 */
export async function enroll(user, usingPasskeysPlus = false) {
  console.log('[enroll] Input:', { user, usingPasskeysPlus });
  const result = await umfaClient.enroll(user, usingPasskeysPlus);
  console.log('[enroll] SDK result:', result instanceof Error ? result.message : JSON.stringify(result, null, 2));

  // Already enrolled
  if (result === false) return false;

  // SDK error
  if (result instanceof Error) return result;

  // Validate token with server when we get a token object back
  if (result && typeof result === 'object') {
    await validateToken(user, result);
  }

  return result;
}

/**
 * Authenticates the user with ZSM and optionally Passkeys+.
 *
 * Returns a structured result object so the caller can branch on success
 * vs. failure and extract challenge data for display without this module
 * touching the DOM.
 *
 * RESULT SHAPES:
 *   Success:
 *     {
 *       success: true,
 *       credential: object,           // raw credential from SDK
 *       challengeData?: {             // present when challenge data is extractable
 *         challenge: string,          // SHA-256 hex of clientDataJSON
 *         signedChallenge: string     // JSON-stringified signature
 *       }
 *     }
 *
 *   Failure:
 *     { success: false, error?: string }
 *
 * IMPORTANT: initializeZSMClient(user) must be called before this function.
 *
 * On success, the token is automatically validated with the server via
 * validateToken() before returning.
 *
 * @param {string} user - The username to authenticate.
 * @param {boolean} [usingPasskeysPlus=false] - If true, uses Passkeys+ for
 *   authentication. If false, uses ZSM only (no passkey prompt).
 * @returns {Promise<{success: boolean, credential?: object, challengeData?: object, error?: string}>}
 */
export async function authenticate(user, usingPasskeysPlus = false) {
  console.log('[authenticate] Input:', { user, usingPasskeysPlus });
  let result;
  try {
    result = await umfaClient.authenticate(user, usingPasskeysPlus);
  } catch (err) {
    console.error('[authenticate] Exception:', err);
    return { success: false, error: err.message };
  }
  console.log('[authenticate] SDK result:', result instanceof Error ? result.message : JSON.stringify(result, null, 2));

  // Not enrolled
  if (result === false) return { success: false, error: 'Not enrolled' };

  // SDK error
  if (result instanceof Error) return { success: false, error: result.message };

  // Empty object = MPC/crypto failure
  if (!result || (typeof result === 'object' && Object.keys(result).length === 0)) {
    console.log('[authenticate] Empty result — MPC/crypto failure');
    return { success: false, error: 'MPC/crypto failure' };
  }

  const credential = result?.credential ?? result;

  // Extract challenge data from response for display (does not affect auth outcome)
  const challengeData = await challengeDataFrom(credential);

  const output = JSON.stringify(credential);
  console.log('[authenticate] Output credential:', output.substring(0, 200) + (output.length > 200 ? '...' : ''));

  // Validate token with server
  if (credential && typeof credential === 'object') {
    await validateToken(user, credential);
  }

  return { success: true, credential, challengeData };
}

/**
 * The challenge and signed challenge a credential carries, for display: the
 * SHA-256 of its clientDataJSON and its signature as JSON. authenticate()
 * attaches this to its result; the page calls it on an enroll() result too,
 * so the Passkey block can show the enrollment ceremony as well. Undefined
 * when the credential carries no response or it cannot be read.
 *
 * @param {object} credential - A credential object the SDK returned.
 * @returns {Promise<{challenge: string, signedChallenge: string}|undefined>}
 */
export async function challengeDataFrom(credential) {
  if (!credential?.response) return undefined;
  try {
    const challenge = await hashSHA256(JSON.stringify(credential.response.clientDataJSON));
    const signedChallenge = JSON.stringify(credential.response.signature);
    return { challenge, signedChallenge };
  } catch (err) {
    console.warn('[challengeDataFrom] Could not extract challenge data:', err.message);
    return undefined;
  }
}

/**
 * Validates an authentication or enrollment token with the Ideem server.
 *
 * This is called automatically by enroll() and authenticate() after a
 * successful SDK operation. You generally do not need to call it directly,
 * but it is exported for cases where you need to validate a token obtained
 * through other means.
 *
 * The validation endpoint and credentials come from zsm_app_config.json:
 *   - validate_url: the server endpoint to POST to
 *   - application_id: included in the request body
 *   - server_key: used as a Bearer token in the Authorization header
 *   - application_environment: included in the request body
 *
 * @param {string} userId - The username the token was issued for.
 * @param {object} token - The token object returned by the SDK (enroll or authenticate).
 * @returns {Promise<boolean>} True if the server returned a 2xx response.
 */
export async function validateToken(userId, token) {
  const requestBody = {
    application_id: zsmAppConfig.application_id,
    user_id: userId,
    token: token,
    environment: zsmAppConfig.application_environment
  };
  console.group('[validateToken]');
  console.log('User:', userId, '| URL:', zsmAppConfig.validate_url);
  try {
    const response = await fetch(zsmAppConfig.validate_url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${zsmAppConfig.server_key}`
      },
      body: JSON.stringify(requestBody)
    });
    const data = await response.json();
    console.log('Status:', response.status, response.ok ? 'OK' : 'FAIL');
    if (data.token) console.log('JWT present, length:', data.token.length);
    console.groupEnd();
    return response.ok;
  } catch (err) {
    console.error('Error:', err.message);
    console.groupEnd();
    return false;
  }
}
