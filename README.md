# Ideem ZSM + Passkeys+ Integration Guide

A partner-facing implementation guide for integrating Ideem Zero Share MPC (ZSM) authentication and Passkeys+ into a web application.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Configuration](#3-configuration)
4. [Quick Start](#4-quick-start)
5. [iShield Integration (Optional)](#5-ishield-integration-optional)
6. [API Reference](#6-api-reference)
7. [Architecture](#7-architecture)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Overview

### What is ZSM?

**Zerotrust Secure Module (ZSM)** is Ideem's User-centric Multi-Factor Authentication (UMFA). It uses Multi-Party Computation to split a user's cryptographic secret into shares distributed between the client device and the Ideem server. Neither party holds the full secret -- authentication requires both shares to cooperate, eliminating single points of compromise.

The client-side share is stored in the browser's **IndexedDB** and bound with **WCA**, binding it to a specific device.

### What is Passkeys+?

**Passkeys+** extends ZSM with FIDO2 passkey credentials. When enabled, authentication requires both the ZSM secret share AND a passkey challenge (biometric or security key), giving you two distinct factors in a single user gesture. 

### What is Silent Network Authentication?

**Silent Network Authentication (SNA)** verifies that a phone number belongs to the device in hand by asking the mobile network, with nothing for the user to type: the device opens a one-time URL over cellular data, the carrier recognises the SIM and redirects back with a code, and the backend exchanges the code for a match verdict. The demo plays a **simulation** of that flow, modelled on [IDlayr's Secure SNA walkthrough](https://secure-sna-demo.idlayr.com), in `sna.js`. It makes no network request; a real integration replaces the inside of `verifyNumber()` with calls to a backend that holds the IDlayr key.

### Authentication Flow: Three Phases

The system operates in three phases:

```
Phase 1: TRUST DEVICE
  User enrolls a new device. Creates the ZSM secret share (IndexedDB)
  and registers a Passkeys+ credential (FIDO2 passkey) with the server.
  The demo then runs the simulated Silent Network Authentication check
  (sna.js) and ends on four indicators: iShield, Number Verified,
  Device Bound, Passkey. This is a one-time operation per device.
  An attendee starts on the registration page (register.html): the laptop
  camera reads their badge QR and the user database answers with their
  name, phone and email. A badge the database does not know opens a short
  form instead (name, phone, email), and Manually Enter User opens that
  form without a badge; Register adds the attendee. Enroll iShield Key
  then writes the phone number onto their key as a discoverable credential
  (key-enroll.js), and a second QR opens the demo
  on their phone with the number already in the User ID field: Login
  reads it back off the key, then ZSM + Passkeys+ enroll on the phone.

Phase 2: LOGIN
  User authenticates on a trusted device. The ZSM share in IndexedDB
  cooperates with the server share, optionally combined with a Passkeys+
  challenge. No hardware token needed for daily login.

Phase 3: PROTECTED ACTIONS (step-up auth)
  After login, sensitive operations (authenticating, exchanging contacts,
  viewing standings) trigger a step-up authentication -- the same
  authenticate() call used for login, but scoped to a specific action.
  Authenticate then charges a fixed demo amount to the attendee's record
  in the user database (PATCH /users/:id/balance via the /db proxy) and
  the balance shown on the Actions screen updates; the page refuses the
  charge itself when the balance is short, because the API does not.
  P2P Contact Exchange opens a QR code instead. Another attendee scans
  it, is asked to confirm sharing their contact info, verifies with their
  passkey, and both phones then show the other person's name and phone
  number, read from the user database by api/exchange.js. Each side's
  passkey verification is what authorizes it.

Phase 4: ENABLING / DISABLING DEVICE
  User can disable device with click of button. To re-enable device, user must reinsert iShield Key.
```

### How They Work Together

```
  +------------------+       +------------------+
  |  Client Device   |       |   Ideem Server   |
  |                  |       |                  |
  |  ZSM Share (IDB) |<----->|  ZSM Share       |
  |  Passkey (FIDO2) |<----->|  Passkey Record  |
  +------------------+       +------------------+
         |                          |
         +--- MPC Protocol ---------+
         |                          |
     authenticate()          validate-token
         |                          |
         v                          v
    Credential Object     JWT (on validation)
```

---

## 2. Prerequisites

### NPM Packages

```json
{
  "dependencies": {
    "@ideem/zsm-client-sdk": "^2.7.0",
    "@ideem/plugins.passkeys-plus": "^1.2.1"
  }
}
```

The ZSM Client SDK (`@ideem/zsm-client-sdk`) is the core library. The Passkeys+ plugin (`@ideem/plugins.passkeys-plus`) is a side-effect import that registers itself with the SDK automatically.


### Ideem Account

You need an Ideem application provisioned with:
- An `application_id` (UUID)
- A client-side `api_key` (UUID)
- A server-side `server_key` (UUID, for token validation) ***NOTE*** The tokenValidation will happen on the server in a real environment. It is only included here to make the demo easier to operate. 

Contact Ideem to provision your application.

### Module Loading

The SDK is distributed as ES modules. In the demo, an import map resolves bare specifiers to vendored files. Can also use npm.

If you use a bundler (Vite, webpack, esbuild), standard `node_modules` resolution works and you do not need the import map.

---

## 3. Configuration

### zsm_app_config.json

Create a JSON configuration file with your Ideem application credentials:

```json
{
  "application_id": "ad9bf691-5803-4752-9f35-51f29ab8d58b",
  "api_key": "0f7fdf8e-db1c-4370-88ae-f93078bfb974",
  "region": "demo",
  "server_key": "0f7fdf8e-db1c-4370-88ae-f93078bfb974",
  "validate_url": "https://zsm-authenticator-demo.useideem.com/api/pkp/validate-token"
}
```

### Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `application_id` | UUID string | Your Ideem application identifier. Provided during provisioning. Sent to the SDK during client initialization and to the validation endpoint. |
| `api_key` | UUID string | Client-side API key for SDK authentication. This is safe to include in client-side code -- it authorizes SDK operations but cannot be used for server-side actions. |
| `server_key` | UUID string | Server-side key used as a Bearer token when calling the `validate_url` endpoint. **In a production application, this should live on your backend server, not in client-side code.** The demo includes it client-side for simplicity. |
| `validate_url` | URL string | The Ideem token validation endpoint. After enrollment or authentication, POST the token here to get a validated JWT. |
| `region` | string | Environment region identifier (e.g., `"demo"`, `"us"`, `"eu"`). Determines which Ideem infrastructure the SDK connects to. |

### Security Note on server_key

In the demo, `server_key` is included in the client-side config for simplicity. In production, token validation should happen on your backend:

```
Client: authenticate() -> get token -> send token to YOUR backend
Your Backend: POST token to validate_url with server_key -> return JWT to client
```

This keeps `server_key` out of client-side code entirely.

### Localhost Development Override

The demo zeroes out all hex credential segments when running on `localhost`, allowing the SDK to initialize in test mode without real server credentials:

```javascript
if (/localhost:\d+/.test(window.location.host)) {
  for (const key in config) {
    if (typeof config[key] === 'string') {
      config[key] = config[key].replace(/[a-f0-9]{4}/g, '0000');
    }
  }
  config.application_environment = 'test';
}
```

You can replicate this pattern or use separate config files for dev vs. production.

---

## 4. Quick Start

This section shows the minimal code to integrate ZSM + Passkeys+ into your application. All examples are drawn from [`umfa.js`](./umfa.js).

### Step 1: Import the SDK and Plugin

```javascript
import { UMFAClient } from '@ideem/zsm-client-sdk';
import PasskeysPlus from '@ideem/plugins.passkeys-plus'; // Side-effect: registers plugin
```

The `PasskeysPlus` import is a side-effect -- you do not call it directly. Importing it registers the Passkeys+ plugin with the SDK so that `UMFAClient` can use passkey operations.

### Step 2: Load Configuration and Create the Client

```javascript
// Fetch your config (or import it, or inline it)
const config = await fetch('./zsm_app_config.json').then(r => r.json());

// Create a client for a specific user
const clientConfig = { ...config, consumer_id: 'alice' };
const client = new UMFAClient(clientConfig);

// Wait for WASM initialization to complete
await client.finished();
```

The `consumer_id` is the username or user identifier in your system. Each `UMFAClient` instance is bound to a single user. If the user changes, create a new instance.

`client.finished()` returns a Promise that resolves when the SDK's internal WASM module has loaded and initialized. You must await this before calling any other method.

### Step 3: Check Enrollment Status

Before enrolling or authenticating, check whether the user already has credentials on this device:

```javascript
// Check ZSM + Passkeys+ enrollment
const status = await client.checkAllEnrollments('alice');
// status = { hasZSMCred: boolean, hasRemotePasskey: boolean, ... }
```

| Field | Meaning |
|-------|---------|
| `hasZSMCred` | The device has a ZSM secret share in IndexedDB |
| `hasRemotePasskey` | A Passkeys+ credential is registered on the server for this user |

If both are `true`, the device is trusted and the user can authenticate. If either is `false`, the user needs to enroll.

### Step 4: Enroll the User

Enrollment creates the ZSM secret share and (optionally) registers a Passkeys+ credential:

```javascript
// Enroll with ZSM + Passkeys+ (second argument = true)
const credential = await client.enroll('alice', true);

if (credential === false) {
  // Already enrolled
} else if (credential instanceof Error) {
  // SDK-level failure
  console.error(credential.message);
} else {
  // Success -- credential is the enrollment token
  // Validate it with your server (see Step 6)
}
```

The second parameter (`true`) enables Passkeys+. When `true`, the browser will prompt the user to create a passkey (biometric/security key). When `false`, only the ZSM share is created (no passkey prompt).

### Step 5: Authenticate the User

```javascript
// Authenticate with ZSM + Passkeys+
const result = await client.authenticate('alice', true);

if (result === false) {
  // Not enrolled on this device
} else if (result instanceof Error) {
  // SDK-level failure
  console.error(result.message);
} else if (!result || Object.keys(result).length === 0) {
  // MPC/crypto failure (empty object)
} else {
  // Success -- result is the authentication token
  // Validate it with your server (see Step 6)
}
```

### Step 6: Validate the Token

After enrollment or authentication, validate the token with the Ideem server to get a JWT. ***IMPORTANT*** You must validateToken() after an enroll call or it will not be activated. 

```javascript
const response = await fetch(config.validate_url, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${config.server_key}`
  },
  body: JSON.stringify({
    application_id: config.application_id,
    user_id: 'alice',
    token: credential,  // The token from enroll() or authenticate()
    environment: config.application_environment
  })
});

const data = await response.json();
if (response.ok && data.token) {
  // data.token is a validated JWT
  // Use it for your session management
}
```

### Complete Minimal Example

```javascript
import { UMFAClient } from '@ideem/zsm-client-sdk';
import PasskeysPlus from '@ideem/plugins.passkeys-plus';

const config = await fetch('./zsm_app_config.json').then(r => r.json());

async function trustDevice(username) {
  const client = new UMFAClient({ ...config, consumer_id: username });
  await client.finished();

  const status = await client.checkAllEnrollments(username);
  if (status?.hasZSMCred && status?.hasRemotePasskey) {
    console.log('Already enrolled');
    return;
  }

  const credential = await client.enroll(username, true);
  if (credential && !(credential instanceof Error)) {
    console.log('Enrollment successful');
    // Validate token with your server...
  }
}

async function login(username) {
  const client = new UMFAClient({ ...config, consumer_id: username });
  await client.finished();

  const result = await client.authenticate(username, true);
  if (result && !(result instanceof Error) && Object.keys(result).length > 0) {
    console.log('Authentication successful');
    // Validate token with your server...
    // Start user session...
  }
}
```

---

## 5. iShield Integration (Optional)

The demo includes raw WebAuthn integration with Swissbit iShield USB security keys. This is independent of ZSM/Passkeys+ and uses the browser's `navigator.credentials` API directly. You may want to integrate hardware security keys alongside ZSM for high-assurance scenarios like device suspension/reactivation.

All iShield code lives in [`ishield.js`](./ishield.js).

> **Planned change:** test findings for reading an iShield key on any phone with a touch and no PIN (discoverable credentials, per-browser behaviour, Chrome's limits) are in [`docs/ishield-pinless-discoverable.md`](./docs/ishield-pinless-discoverable.md). They are not yet integrated into the demo.

### How iShield Fits the Flow

In the demo's Trust Device flow, the user enrolls their iShield USB key FIRST (raw WebAuthn), then enrolls ZSM + Passkeys+. The iShield key serves as a recovery mechanism -- if a device is "suspended" (e.g., reported compromised), the user must physically touch their iShield key to reactivate Passkeys+ login.

```
Trust Device:
  1. webauthnEnroll(user)    -- register iShield USB key
  2. enroll(user, true)      -- register ZSM + Passkeys+

Suspended Login (reactivation):
  1. webauthnAuthenticate(user) -- touch iShield USB key
  2. authenticate(user, true)   -- authenticate with Passkeys+
  3. Clear suspension flag
```

### Enrolling an iShield USB Key

```javascript
import { webauthnEnroll, hasStoredCredential } from './ishield.js';

try {
  await webauthnEnroll('alice');
  // Credential ID is now stored in localStorage
  console.log('iShield enrolled:', hasStoredCredential('alice')); // true
} catch (err) {
  if (err.name === 'NotAllowedError') {
    // User cancelled or timed out
  } else if (err.name === 'SecurityError') {
    // Not running on HTTPS or localhost
  } else if (err.name === 'InvalidStateError') {
    // Key already registered for this user
  }
}
```

The WebAuthn options are configured specifically for cross-platform USB keys:

```javascript
authenticatorSelection: {
  authenticatorAttachment: 'cross-platform', // USB keys, not platform (TouchID/FaceID)
  userVerification: 'discouraged',           // iShield is touch-only, no PIN
  residentKey: 'discouraged'
}
```

### Authenticating with an iShield USB Key

```javascript
import { webauthnAuthenticate } from './ishield.js';

const result = await webauthnAuthenticate('alice');
if (result.success) {
  // result.clientDataHash -- SHA-256 hex of clientDataJSON
  // result.signatureHex   -- hex-encoded raw signature bytes
} else {
  // result.error -- the Error object
  if (result.error?.name === 'NotAllowedError') {
    // User cancelled or timed out
  }
}
```

### Credential Storage

iShield credential IDs are stored in `localStorage` under the key `fido2_credential:<username>`:

```json
{ "id": "<base64url-encoded credential ID>", "createdAt": "2025-01-15T..." }
```

This allows `webauthnAuthenticate()` to target the specific credential during `navigator.credentials.get()` via the `allowCredentials` parameter.

### Suspension Mechanism

The demo uses `localStorage` flags to track device suspension:

```javascript
import { isSuspended, setSuspended } from './ishield.js';

// Suspend: require iShield to reactivate
setSuspended('alice', true);

// Check suspension
if (isSuspended('alice')) {
  // Show "Reactivate" flow instead of normal login
}

// Clear suspension after successful iShield + Passkeys+ auth
setSuspended('alice', false);
```

---

#### `resetClient()`

Clears the cached `UMFAClient` instance. Call on logout.

| Param | Type | Description |
|-------|------|-------------|
| (none) | | |

**Returns:** `void`

```javascript
resetClient(); // Call on logout
```

---

#### `checkAllEnrollment(user)`

Checks whether the user has ZSM and Passkeys+ credentials enrolled on this device. Calls the SDK's `checkAllEnrollments()` internally.

| Param | Type | Description |
|-------|------|-------------|
| `user` | `string` | Username to check |

**Returns:** `Promise<object | false>`

```javascript
{
  hasZSMCred: true,       // ZSM share exists in IndexedDB
  hasRemotePasskey: true   // Passkeys+ credential on server
}
```

Returns `false` on error or if not enrolled.

```javascript
await initializeZSMClient('alice');
const status = await checkAllEnrollment('alice');
if (status && status.hasZSMCred && status.hasRemotePasskey) {
  // Device is trusted, user can authenticate
}
```

---

#### `enroll(user, usingPasskeysPlus?)`

Enrolls the user with ZSM and optionally Passkeys+.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `user` | `string` | | Username to enroll |
| `usingPasskeysPlus` | `boolean` | `false` | If `true`, enrolls both ZSM and Passkeys+ |

**Returns:** `Promise<object | false | Error>`

| Return value | Meaning |
|-------------|---------|
| Object (truthy) | Enrollment succeeded. The object is the credential/token. |
| `false` | User is already enrolled. |
| `Error` instance | SDK-level failure. Check `.message` for details. |

On success, `validateToken()` is called automatically before returning.

```javascript
await initializeZSMClient('alice');
const result = await enroll('alice', true);
if (result && result !== false && !(result instanceof Error)) {
  // Enrollment succeeded
}
```

---

#### `authenticate(user, usingPasskeysPlus?)`

Authenticates the user with ZSM and optionally Passkeys+.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `user` | `string` | | Username to authenticate |
| `usingPasskeysPlus` | `boolean` | `false` | If `true`, uses Passkeys+ for authentication |

**Returns:** `Promise<object>` with the following shapes:

**Success:**
```javascript
{
  success: true,
  credential: { /* raw SDK credential object */ },
  challengeData: {                  // Present when extractable
    challenge: '7a3f...',           // SHA-256 hex of clientDataJSON
    signedChallenge: '[1,42,...]'   // JSON-stringified signature
  }
}
```

**Failure:**
```javascript
{ success: false, error: 'Not enrolled' }
{ success: false, error: 'MPC/crypto failure' }
{ success: false, error: 'Some SDK error message' }
```

On success, `validateToken()` is called automatically before returning.

```javascript
await initializeZSMClient('alice');
const auth = await authenticate('alice', true);
if (auth.success) {
  // User is authenticated
  // auth.credential contains the raw credential
  // auth.challengeData?.challenge is the hash (for display)
}
```

---

#### `validateToken(userId, token)`

Validates an authentication or enrollment token with the Ideem server.

| Param | Type | Description |
|-------|------|-------------|
| `userId` | `string` | Username the token was issued for |
| `token` | `object` | Token object from `enroll()` or `authenticate()` |

**Returns:** `Promise<boolean>` -- `true` if the server returned a 2xx response.

Called automatically by `enroll()` and `authenticate()`. You generally do not need to call this directly unless you obtain a token through other means.

```javascript
const isValid = await validateToken('alice', credential);
```

---

### ishield.js Exports

#### `webauthnEnroll(user)`

Enrolls an iShield USB key for a user via raw WebAuthn (`navigator.credentials.create()`).

| Param | Type | Description |
|-------|------|-------------|
| `user` | `string` | Username. Used as WebAuthn `user.name` and localStorage key. |

**Returns:** `Promise<void>` -- resolves on success.

**Throws:** The original WebAuthn error on any failure:
- `NotAllowedError` -- user cancelled or timed out
- `SecurityError` -- not running on HTTPS or localhost
- `InvalidStateError` -- key already registered for this user

```javascript
try {
  await webauthnEnroll('alice');
} catch (err) {
  console.error(err.name, err.message);
}
```

---

#### `webauthnAuthenticate(user)`

Authenticates a user with their enrolled iShield USB key via raw WebAuthn (`navigator.credentials.get()`). The get is `webauthnIdentify()` below; this wrapper takes the expected username and logs a mismatch with the key's user handle (the caller decides what to do with it).

| Param | Type | Description |
|-------|------|-------------|
| `user` | `string` | The expected username. Compared with the user handle the key returns; empty is a failure. |

**Returns:** `Promise<object>`

**Success:**
```javascript
{
  success: true,
  clientDataHash: '7a3f...',     // SHA-256 hex of clientDataJSON
  signatureHex: 'a1b2c3...',     // hex-encoded raw signature bytes
  authenticatedUser: '9135551235' // the key's user handle as text, or null
}
```

**Failure:**
```javascript
{
  success: false,
  error: Error  // The original Error object
}
```

```javascript
const result = await webauthnAuthenticate('alice');
if (result.success) {
  console.log('Signature:', result.signatureHex);
}
```

---

#### `webauthnIdentify()`

Asks whichever iShield key is present who it is: the same open get (empty `allowCredentials`, `userVerification: 'discouraged'`, `hints: ['security-key']`) with no expected username. The identity comes back in `authenticatedUser`, the user handle the registration page wrote onto the key. `partner.html` calls this directly. Same result shapes as `webauthnAuthenticate`, minus the empty-user failure.

```javascript
const result = await webauthnIdentify();
if (result.success && result.authenticatedUser) {
  console.log('The key belongs to', result.authenticatedUser);
}
```

---

#### `hasStoredCredential(user)`

Checks if a FIDO2 credential is stored in localStorage for this user.

| Param | Type | Description |
|-------|------|-------------|
| `user` | `string` | Username to check |

**Returns:** `boolean`

```javascript
if (hasStoredCredential('alice')) {
  // User has an enrolled iShield key on this device
}
```

---

#### `isSuspended(user)`

Checks if the user's device is currently suspended.

| Param | Type | Description |
|-------|------|-------------|
| `user` | `string` | Username to check |

**Returns:** `boolean`

---

#### `setSuspended(user, value)`

Sets or clears the suspension flag for a user's device.

| Param | Type | Description |
|-------|------|-------------|
| `user` | `string` | Username |
| `value` | `boolean` | `true` to suspend, `false` to clear |

**Returns:** `void`

---

#### `getPasskeysToggle(user)`

Returns the saved Passkeys+ toggle preference.

| Param | Type | Description |
|-------|------|-------------|
| `user` | `string` | Username |

**Returns:** `boolean` -- defaults to `true` if not previously set.

---

#### `setPasskeysToggle(user, value)`

Persists the Passkeys+ toggle preference.

| Param | Type | Description |
|-------|------|-------------|
| `user` | `string` | Username |
| `value` | `boolean` | Toggle state to save |

**Returns:** `void`

---

#### `bufferToBase64url(buffer)`

Converts an `ArrayBuffer` to a base64url-encoded string.

| Param | Type | Description |
|-------|------|-------------|
| `buffer` | `ArrayBuffer` | Raw bytes to encode |

**Returns:** `string`

---

#### `base64urlToBuffer(base64url)`

Converts a base64url-encoded string back to an `ArrayBuffer`.

| Param | Type | Description |
|-------|------|-------------|
| `base64url` | `string` | base64url-encoded string |

**Returns:** `ArrayBuffer`

---

#### `hashSHA256(input)`

Computes SHA-256 hash of a string, returns hex.

| Param | Type | Description |
|-------|------|-------------|
| `input` | `string` | String to hash |

**Returns:** `Promise<string>` -- hex-encoded SHA-256 digest.

**Throws:** `TypeError` if input is not a string.

---

#### Storage Key Constants

| Constant | Value | Usage |
|----------|-------|-------|
| `FIDO2_STORAGE_PREFIX` | `'fido2_credential:'` | localStorage key prefix for credential IDs |
| `SUSPENDED_STORAGE_PREFIX` | `'passkeys_suspended:'` | localStorage key prefix for suspension flags |
| `PASSKEYS_TOGGLE_PREFIX` | `'actions_passkeys_toggle:'` | localStorage key prefix for toggle preference |

---

## 7. Architecture

### Project Structure

```
Demo-swissbit/
  ishield.js           -- Raw WebAuthn for iShield USB keys (zero SDK deps)
  umfa.js              -- ZSM + Passkeys+ integration (wraps @ideem SDKs)
  sna.js               -- Simulated Silent Network Authentication (no DOM, no network)
  app.js               -- Demo UI orchestration (wires modules to DOM)
  state.js             -- Simple reactive state class (demo utility, not for production)
  index.html           -- Single-page HTML with five screens
  register.html/.js    -- Registration page: camera scan of the badge QR (BarcodeDetector or the
                          vendored jsQR), lookup by confirmation number or a form, the iShield
                          create, then a QR into the demo with ?userid=<digits>
  key-enroll.js        -- The discoverable create that puts a phone number on an iShield key, as a
                          function for register.js (the measured options; fido-test.js defaults to them)
  partner.html/.js     -- Partner page: Identify reads the User ID off an iShield key, shows the account
                          and moves its balance (+ $500, + $Custom, - $Custom) through the user API
  api/db.js            -- Vercel function: proxy to the user API (/db/*)
  api/exchange.js      -- Vercel function: P2P Contact Exchange matchmaker (/api/exchange)
  zsm_app_config.json  -- Ideem application credentials
  build.js             -- Copies SDK files from node_modules to vendor/
  vendor/              -- Vendored SDK files (served as static assets)
  package.json         -- npm dependencies
  vercel.json          -- Vercel deployment config
  fido-test.html/.js   -- Raw WebAuthn test page for hardware keys (create/get options, result checks)
  dev-server.mjs       -- Local server: static files, /db proxy, /api/exchange, test-page result log
  docs/                -- iShield test findings (ishield-pinless-discoverable.md), the user
                          API's measured behaviour (user-api.md) and its Postman collection
```

### Module Dependency Graph

```
app.js
  |-- imports --> ishield.js   (webauthnEnroll, webauthnAuthenticate, hasStoredCredential, ...)
  |-- imports --> umfa.js      (initializeZSMClient, checkAllEnrollment, enroll, authenticate, ...)
  |-- imports --> sna.js       (verifyNumber, isNumberVerified, setNumberVerified, SNA_STEPS, ...)
                    |
                    |-- imports --> @ideem/zsm-client-sdk  (UMFAClient)
                    |-- imports --> @ideem/plugins.passkeys-plus  (side-effect)
                    |-- imports --> ishield.js  (hashSHA256 only -- a pure crypto utility)
```
