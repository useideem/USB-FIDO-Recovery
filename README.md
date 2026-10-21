# USB FIDO Key Recovery: Ideem ZSM + Passkeys+ Integration Guide

A partner-facing implementation guide for a web app that binds three factors to a phone, a Swissbit iShield USB FIDO key, the phone number, and an Ideem Passkeys+ passkey, and recovers from a lost key by associating a replacement.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Configuration](#3-configuration)
4. [Quick Start](#4-quick-start)
5. [The FIDO Key](#5-the-fido-key)
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

### What is the FIDO key for?

The USB key is a possession factor the user carries. It is written once, on the registration page, with the user's phone number stored on it as a discoverable credential protected by the key's PIN. The phone then reads it with a raw WebAuthn get: the key answers with the number, after the PIN and a touch, and the app associates that credential with the phone. When the key is lost, the user says so in the app, a replacement is written with the same number, and the app associates the replacement: a different credential, the same User ID. The lost one is refused from then on.

### The flows

```
REGISTRATION (register.html, on a Mac in Safari)
  Phone number -> Enroll Key: navigator.credentials.create() with the number
  as user.id, residentKey required, userVerification required (the key's PIN)
  -> QR code and link that open the main page with ?userid=<number>

SETUP (index.html, first Continue on a phone)
  1. webauthnAuthenticate(user)  -- PIN and touch; the key's user handle must
                                    match the User ID; the credential id and
                                    the time are recorded on the phone
  2. verifyNumber(user)          -- the simulated carrier check (sna.js)
  3. enroll(user, 'required')    -- ZSM share + Passkeys+ passkey, one call

SIGN-IN (a phone that holds the ZSM share)
  1. authenticate(user, 'required')  -- the passkey alone

HOME
  The key: credential, associated date and time, last verified, status.
  The factors: USB Key, Phone# Verified, Device Bound, Passkey.
  The challenge and signed challenge each factor's last ceremony produced.
  Authenticate -- a fresh passkey step-up.
  I lost this key -- a dialog; the key is marked lost and refused.
  Associate new FIDO key -- authenticate(user, 'required'), verifyNumber(user)
    again, then webauthnAuthenticate(user) on the replacement: the same number
    under a new credential id becomes the associated key; the previous one is
    marked replaced and refused.
```

There is no backend of the app's own. What the app knows about a user's keys lives in the phone's browser (`key-records.js`); the passkey and the ZSM share live with Ideem and in the browser's IndexedDB; the number check leaves a marker on the phone.

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
    "@ideem/zsm-client-sdk": "latest",
    "qrcode-generator": "^2.0.4"
  }
}
```

The ZSM Client SDK (`@ideem/zsm-client-sdk`) is the core library; Passkeys+ is part of it, there is no separate plugin to import. `qrcode-generator` draws the registration page's hand-off code.

### Ideem Account

You need an Ideem application provisioned with:
- An `application_id` (UUID)
- A client-side `api_key` (UUID)
- A server-side `server_key` (UUID, for token validation) ***NOTE*** The tokenValidation will happen on the server in a real environment. It is only included here to make the demo easier to operate.

Contact Ideem to provision your application.

### Module Loading

The SDK is distributed as ES modules. In the demo, an import map in `index.html` resolves the bare specifier to the vendored copy that `npm run build` places under `vendor/`. Can also use npm.

If you use a bundler (Vite, webpack, esbuild), standard `node_modules` resolution works and you do not need the import map.

---

## 3. Configuration

### zsm_app_config.json

Create a JSON configuration file with your Ideem application credentials:

```json
{
  "application_id": "<your application id>",
  "api_key": "<your client-side api key>",
  "server_key": "<your server key>",
  "validate_url": "https://zsm-authenticator-demo.useideem.com/api/pkp/validate-token",
  "region": "demo"
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
  config.application_environment = 'TEST';
}
```

You can replicate this pattern or use separate config files for dev vs. production.

---

## 4. Quick Start

This section shows the minimal code to integrate ZSM + Passkeys+ into your application. All examples are drawn from [`umfa.js`](./umfa.js).

### Step 1: Import the SDK

```javascript
import { UMFAClient } from '@ideem/zsm-client-sdk';
```

### Step 2: Load Configuration and Create the Client

```javascript
// Fetch your config (or import it, or inline it)
const config = await fetch('./zsm_app_config.json').then(r => r.json());

// Create a client for a specific user
const clientConfig = { ...config, consumer_id: '9135551235' };
const client = new UMFAClient(clientConfig);

// Wait for WASM initialization to complete
await client.finished();
```

The `consumer_id` is the user identifier in your system; the demo uses the phone number, bare digits. Each `UMFAClient` instance is bound to a single user. If the user changes, create a new instance.

`client.finished()` returns a Promise that resolves when the SDK's internal WASM module has loaded and initialized. You must await this before calling any other method.

### Step 3: Check Enrollment Status

Before enrolling or authenticating, check what the user already has on this device and on the server:

```javascript
const status = await client.checkAllEnrollments('9135551235');
```

| Field | Meaning |
|-------|---------|
| `hasZSMCred` | The device has a ZSM secret share in IndexedDB |
| `hasLocalPasskey` | A Passkeys+ credential for this user is usable from this device |
| `hasRemotePasskey` | A Passkeys+ credential is registered on the server for this user |
| `pkpCredential` | The server's challenge for that passkey, when one exists; `enroll` uses it to rebind a device from the passkey |
| `passkeySupported` | This browser can do passkeys at all |
| `isUsingPasswordManager` | An extension has replaced `navigator.credentials.get` |

If `hasZSMCred` is `true`, the device is set up and the user can authenticate. If it is `false`, the user needs to enroll, which on a device whose user the server already knows means proving the existing passkey rather than creating a second one.

### Step 4: Enroll the User

Enrollment creates the ZSM secret share and registers a Passkeys+ credential. The second argument is the SDK's user-verification mode:

```javascript
const credential = await client.enroll('9135551235', 'required');

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

| Mode | What happens |
|------|--------------|
| `'required'` | The passkey is mandatory: a cancelled passkey sheet fails the enrollment. On a device with no share whose user already has a passkey on the server, the SDK authenticates that passkey and rebuilds the share instead of registering a second one. The demo uses this mode everywhere, since the passkey is its recovery factor. |
| `'preferred'` (or `true`) | The browser prompts for a passkey, and a cancelled sheet falls back to a ZSM-only enrollment with no passkey. |
| `'prevented'` (or `false`) | ZSM only; no passkey prompt. |

### Step 5: Authenticate the User

```javascript
const result = await client.authenticate('9135551235', 'required');

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

The same modes apply: `'required'` fails when the passkey does not answer, `'preferred'` falls back to ZSM alone.

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
    user_id: '9135551235',
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

const config = await fetch('./zsm_app_config.json').then(r => r.json());

async function setUpDevice(user) {
  const client = new UMFAClient({ ...config, consumer_id: user });
  await client.finished();

  const status = await client.checkAllEnrollments(user);
  if (status?.hasZSMCred) {
    console.log('Already set up');
    return;
  }

  const credential = await client.enroll(user, 'required');
  if (credential && !(credential instanceof Error)) {
    console.log('Enrollment successful');
    // Validate token with your server...
  }
}

async function signIn(user) {
  const client = new UMFAClient({ ...config, consumer_id: user });
  await client.finished();

  const result = await client.authenticate(user, 'required');
  if (result && !(result instanceof Error) && Object.keys(result).length > 0) {
    console.log('Authentication successful');
    // Validate token with your server...
    // Start user session...
  }
}
```

---

## 5. The FIDO Key

The USB key is handled with the browser's `navigator.credentials` API directly, independently of the SDK. Three modules share the work:

| Module | Role |
|--------|------|
| [`key-enroll.js`](./key-enroll.js) | The create that writes the phone number onto a key (the registration page) |
| [`ishield.js`](./ishield.js) | The get that reads whichever key is present (the main page), plus base64url and SHA-256 helpers |
| [`key-records.js`](./key-records.js) | What a browser knows about a user's keys: associated, lost, replaced, and when |

### Writing a key

```javascript
import { enrollKey } from './key-enroll.js';

const result = await enrollKey({ phone: '9135551235', displayName: '(913) 555-1235' });
// result.entry.id          -- the credential id
// result.entry.uvAtCreate  -- true when the key verified the user (its PIN)
// result.warnings          -- anything that would break retrieval
```

The create options are the measured ones, with one change made on 2026-10-21:

```javascript
authenticatorSelection: {
  authenticatorAttachment: 'cross-platform', // a roaming USB key, not Touch ID
  residentKey: 'required',                   // discoverable: the key stores the number
  userVerification: 'required'               // the key's PIN
},
attestation: 'none',
hints: ['security-key'],
extensions: { credProps: true }
```

`user.id` is the phone number as UTF-8, so a get on any phone reads it straight back out of the user handle. A production RP would use random opaque bytes mapped to the number on the server.

Because verification is required, the browser makes the user set a PIN on a key that has none and asks for it on every touch after that, on every device. A page can require verification; it cannot set, read or size the PIN. The iShield's minimum is four digits.

### Reading a key

```javascript
import { webauthnAuthenticate } from './ishield.js';

const result = await webauthnAuthenticate('9135551235');
if (result.success) {
  // result.credentialId      -- which credential answered
  // result.authenticatedUser -- the user handle as text (the phone number)
  // result.challenge         -- what we sent, base64url
  // result.clientDataHash    -- SHA-256 hex of clientDataJSON
  // result.signatureHex      -- the signature, hex
  // result.userVerified      -- the PIN was entered
  // result.signCount         -- the key's counter
} else if (result.error?.name === 'NotAllowedError') {
  // cancelled, timed out, wrong PIN, or nothing on the key for this site
}
```

The get sends an **empty `allowCredentials` list**, so the key answers with whatever discoverable credential it holds for this site and the app learns who it is from the user handle. That is what lets a phone that has never seen the key read it. The app then checks that the handle names the User ID on screen, adopting the key's spelling of the number.

### Recording keys

```javascript
import { recordVerification, associateKey, markLost, activeKey, refusedKey } from './key-records.js';

// Setup: the first key this browser sees for the user becomes the associated key
const { outcome, record } = recordVerification(user, result);   // 'associated' | 'verified' | 'refused' | 'unknown'

// The user reports the key lost: it is refused from now on
markLost(user);

// Recovery: a replacement with the same number, a different credential id
const swap = associateKey(user, result);   // 'associated' | 'same' | 'refused'
swap.previous;                             // the key it replaced, now marked 'replaced'
```

Records live in `localStorage` under `ishield_keys:<user>`, newest first, with `associatedAt`, `lastVerifiedAt`, `lostAt` and `replacedAt` as ISO dates. There is no backend, so a second phone has its own list.

---

## 6. API Reference

### umfa.js Exports

#### `initializeZSMClient(user)`

Creates or reuses the `UMFAClient` for a user. Must be called before the other functions. Awaits the config and the SDK's WASM initialization.

| Param | Type | Description |
|-------|------|-------------|
| `user` | `string` | The user identifier (`consumer_id`) |

**Returns:** `Promise<UMFAClient>`

---

#### `resetClient()`

Clears the cached `UMFAClient` instance. Call on logout.

**Returns:** `void`

---

#### `checkAllEnrollment(user)`

Calls the SDK's `checkAllEnrollments()`; returns its status object (see Step 3), or `false` on error.

**Returns:** `Promise<object | false>`

---

#### `enroll(user, usingPasskeysPlus?)`

Enrolls the user with ZSM and Passkeys+.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `user` | `string` | | User identifier |
| `usingPasskeysPlus` | `boolean \| string` | `false` | `true` is the SDK's `'preferred'` mode, `false` is `'prevented'`; the strings `'required'`, `'preferred'`, `'discouraged'`, `'prevented'` pass through |

**Returns:** `Promise<object | false | Error>`

| Return value | Meaning |
|-------------|---------|
| Object (truthy) | Enrollment succeeded. The object is the credential/token. |
| `false` | User is already enrolled. |
| `Error` instance | SDK-level failure. Check `.message` for details. |

On success, `validateToken()` is called automatically before returning.

---

#### `authenticate(user, usingPasskeysPlus?)`

Authenticates the user with ZSM and Passkeys+. Same modes as `enroll`.

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

---

#### `challengeDataFrom(credential)`

The `challengeData` above, from any credential object the SDK returned, so an `enroll()` result can be displayed the same way. `undefined` when the credential carries no response.

**Returns:** `Promise<{challenge: string, signedChallenge: string} | undefined>`

---

#### `validateToken(userId, token)`

Validates an authentication or enrollment token with the Ideem server. Called automatically by `enroll()` and `authenticate()`.

**Returns:** `Promise<boolean>` -- `true` if the server returned a 2xx response.

---

### ishield.js Exports

#### `webauthnAuthenticate(user)`

The open get below, with an expected user: a user handle that does not match is logged, not failed, and the caller decides. An empty `user` is a failure.

**Returns:** `Promise<object>` -- see `webauthnIdentify`.

---

#### `webauthnIdentify({ userVerification = 'required' })`

Asks whichever key is present who it is: `navigator.credentials.get()` with an empty `allowCredentials` list, `hints: ['security-key']`, and user verification required.

**Success:**
```javascript
{
  success: true,
  credentialId: 'K7f...',          // base64url
  authenticatedUser: '9135551235', // the user handle as text, or null
  challenge: 'o2L...',             // base64url
  at: '2026-10-21T20:06:44.000Z',
  clientDataHash: '7a3f...',
  signatureHex: 'a1b2c3...',
  userPresent: true,
  userVerified: true,
  signCount: 7
}
```

**Failure:** `{ success: false, error: Error }`. A platform authenticator answering instead of the key is a failure with a message that says so.

---

#### `bufferToBase64url(buffer)`, `base64urlToBuffer(text)`, `hashSHA256(text)`

Encoding helpers used across the modules.

---

### key-records.js Exports

| Function | Description |
|----------|-------------|
| `loadKeys(user)` / `saveKeys(user, list)` / `clearKeys(user)` | The list, newest first |
| `activeKey(user)` | The key this browser accepts, or `null` |
| `findKey(user, id)` / `refusedKey(user, id)` | A record by credential id; `refusedKey` answers only for a lost or replaced one |
| `recordVerification(user, assertion, now?)` | A get at setup or sign-in: `'associated'`, `'verified'`, `'refused'` or `'unknown'` |
| `associateKey(user, assertion, now?)` | A replacement: `'associated'` (with `previous`), `'same'` or `'refused'` |
| `markLost(user, now?)` | The lost report; returns the record or `null` |

---

### sna.js Exports

| Function | Description |
|----------|-------------|
| `verifyNumber(phone, { scenario, onStep, speed, signal })` | Plays the simulated check; resolves to `{ match, checkId, code, reason, verifiedAt, steps }` |
| `isNumberVerified(user)` / `getNumberVerification(user)` | The per-device marker a successful check leaves |
| `setNumberVerified(user, result)` / `clearNumberVerified(user)` | Write or forget it |
| `SNA_STEPS`, `SNA_SCENARIOS` | The six steps the page draws, and `success`, `nomatch`, `unsupported` |

---

### key-enroll.js Exports

| Function | Description |
|----------|-------------|
| `enrollKey({ phone, displayName })` | The create; returns `{ entry, rpId, checks, ceremonyOk, warnings, ok }` and throws what WebAuthn throws |
| `createOptions(...)` / `enrollmentWarnings(entry, ceremonyOk)` | The options and the checks, as pure functions |
| `loadEnrollments()` / `saveEnrollments(list)` | The `ishield_enrollments` list the create excludes against |
| `detectBrowser()` | `{ label, chromium, desktop }` from UA Client Hints or the user agent string |
| `ERROR_HINTS` | Friendlier text for the DOMException names |

---

## 7. Architecture

```
app.js / register.js / fido-test.js       page glue, DOM, screens, dialogs
   |         |              |
   |         +---- key-enroll.js   the discoverable create that writes a key
   |         |          |     |
   |         +---- webauthn-util.js <-+     CBOR decoder, authenticator-data parser, RP-side checks
   |                     |
   +---- umfa.js         |                  Ideem UMFAClient wrapper; the only module that imports the SDK
   |        |            |
   +---- ishield.js <----+                  the raw WebAuthn get; zero SDK deps; base64url + SHA-256 helpers
   |
   +---- key-records.js                     the keys a browser has associated, lost, replaced; no DOM
   |
   +---- sna.js                             simulated Silent Network Authentication; no DOM, no network
```

- `ishield.js`, `umfa.js`, `key-records.js` and `sna.js` never touch the DOM. Keep UI concerns in the page scripts.
- `umfa.js` loads `zsm_app_config.json` at module init and caches one `UMFAClient` per `consumer_id`.
- `state.js` is a classic (non-module) script exposing a global `State` Proxy; the demo only uses `STATE.loginID` and `STATE.reset()`.
- `vendor/` is built from `node_modules` by `npm run build` and is git-ignored.

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Every touch asks for a PIN | The key has a PIN, and the create requires verification | Expected since 2026-10-21. A key with any PIN is asked for it by every browser whatever the page says. |
| Desktop Chrome: "Set up a new PIN" fails on the iShield | A Chrome/iShield quirk seen in the September tests (CTAP `0x37`) | Set the PIN once with the libfido2 CLI (`fido2-token -S`), or enroll in Safari. See `docs/ishield-pinless-discoverable.md`. |
| A passkey answers instead of the key | A password manager stepped in front of the security-key prompt | The app refuses it and says so; pick the USB key in the prompt. The SDK reports `isUsingPasswordManager` when `navigator.credentials.get` has been replaced. |
| The phone cannot find the credential | The key was written on another origin (localhost, a tunnel) | Credentials are bound to the RP ID (hostname). Enroll on the deployment the phone will open. |
| `NotAllowedError` with no prompt at all | The page did not have focus, or the gesture was lost | Every ceremony sits directly behind a button tap; keep it that way. |
| `enroll` returns an Error about the passkey portion | `'required'` mode and the passkey sheet was cancelled | Tap again; the mode is deliberate. |
| Reset Device, then setup asks for the key again | Reset wipes the phone's records, the share and the markers | Expected. The passkey still exists on the server, so the enroll authenticates it rather than creating a second one. |
