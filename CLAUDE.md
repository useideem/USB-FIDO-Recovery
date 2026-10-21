# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

This repository, `USB-FIDO-Recovery` (`useideem/USB-FIDO-Recovery` on GitHub, `~/GitHub/USB-FIDO-Recovery` locally), is a USB FIDO key recovery demo: a static, no-bundler browser app that binds three factors to a phone, a Swissbit iShield USB key read with raw WebAuthn, the phone number checked by a simulated carrier call, and an Ideem ZSM / Passkeys+ passkey, and that recovers from a lost key by associating a replacement. It was cloned on 2026-10-21 from `useideem/authenticate26` at its commit e0ea19e, the Authenticate 2026 conference demo, with the full history, and rebuilt the same day to the customer's brief. Everything conference-shaped went with that rebuild: the partner booths, the landing page and party theme, the points, the P2P contact exchange, the user-database proxy and the exchange function, the badge scanner. The history before 2026-10-21 is the conference demo's and `git show e0ea19e:CLAUDE.md` describes it. The original repository and its deployment are untouched by work here.

Plain ES modules served as-is; there is no framework, no transpiler, and no linter configured. Everything a user reads calls the hardware a **FIDO key** or **USB key**; file names, identifiers and storage keys keep `ishield`. `.gitignore` excludes `tests/`, `test-results/`, and `playwright.config.js`, so tests are local-only and not part of the repo.

Three pages share `style.css` and a handful of modules:

| Page | Role |
|---|---|
| `index.html` + `app.js` | The main page: User ID (the phone number), one **Continue** button, and three screens. A phone that holds no ZSM share for the number is set up: the guide dialog, the key touch with its PIN, the SNA check, the passkey. A phone that holds one signs in on the passkey alone. HOME shows the key this phone associated and when, the four factor rows, the challenge blocks, and the buttons Authenticate, I lost this key, Associate new FIDO key, Log Out. Reset Device in the footer |
| `register.html` + `register.js` | The registration page: a phone number box and **Enroll Key**, which writes the number onto the inserted key as a discoverable, PIN-protected credential (`key-enroll.js`), then a QR code and a link that open the main page with `?userid=<digits>`. The same page encodes a replacement key with the same number |
| `fido-test.html` + `fido-test.js` | Raw WebAuthn tester for hardware keys, no SDK involved. Nothing links to it; open it by URL. It is the measurement tool for the open questions below |

## The customer's brief (2026-10-21, as answered)

- First use: the user already holds an enrolled key. The main page verifies it with a get, runs the SNA check, then enrolls the passkey. The main page never writes a key.
- The key carries a four-digit PIN: the FIDO key's own PIN, not an app code. The create requires user verification; the browser handles setting and entering the PIN, and the page cannot set, read or size it (the iShield's minimum is four digits).
- Sign-in after setup is the passkey alone.
- HOME shows the USB key with the date and time it was associated in this app, on this phone.
- "I lost this key" opens a dialog saying a note would be sent to corporate for a replacement. Once lost, that key is no longer used.
- "Associate new FIDO key" demands the passkey again and the SNA check again, then reads the replacement key, which was enrolled with the same phone number and has its own key pair. The previous key is refused from then on.
- The challenge and signed challenge each factor's ceremony produced stay on HOME.
- There is no backend. Everything the app knows about a user's keys lives in the phone's browser; a second phone has its own records.

## Commands

```sh
npm install              # postinstall runs `npm run build`
npm run build            # node build.js -- copies the SDK + qrcode-generator from node_modules into vendor/
node dev-server.mjs      # http://localhost:8080 (PORT=3000 to change)
./run.sh                 # bare python http.server fallback
node tests/key-records.test.mjs   # the Node harness (tests/ is git-ignored; see Testing)
```

`vendor/` is git-ignored and must exist before any page loads: `index.html` resolves `@ideem/zsm-client-sdk` through an import map to `./vendor/@ideem/zsm-client-sdk/ZSMClientSDK.js`, and `register.js` dynamically imports `./vendor/qrcode-generator/dist/qrcode.mjs`. If a page 404s on an import, run the build. Adding a new npm dependency that a page imports means adding it to the `packages` list in `build.js` as well. The SDK is pinned to `latest` in `package.json`; the vendored copy is 2.9.3.

`dev-server.mjs` serves the directory and keeps two dev-only endpoints for the key tester and the registration page: `POST /log` (appends to `.dev-logs/fido-test.jsonl`) and `GET/POST /credentials` (a shared list in `.dev-logs/credentials.json`). Both are silently absent in production. It proxies nothing: the app has no backend of its own. Listening on a local port is blocked in Claude Code's sandbox (EPERM on listen); run it unsandboxed, or set `sandbox.network.allowLocalBinding: true`.

Testing on a phone needs HTTPS. A Cloudflare quick tunnel works; the hostname changes every run, so credentials made under it are bound to that hostname only:

```sh
cloudflared tunnel --no-autoupdate --url http://localhost:8080
```

## Vercel deployment

This repo deploys from its own Vercel project, which the owner created on 2026-10-21 and connected to GitHub (`useideem/USB-FIDO-Recovery`, branch `main`). Production is `https://usb-fido-recovery.vercel.app` (seen serving on 2026-10-21), and `PUBLIC_DEMO_ORIGIN` in `register.js` names it: it is what a registration QR code made on localhost points at. `vercel.json` sets only the build command, the install command and `outputDirectory: "."`, so the whole repo root is the static site, including `zsm_app_config.json`. There are no serverless functions, no rewrites and no redirects. There is no `.vercel/` link in this checkout and no Vercel CLI installed; push to deploy.

`zsm_app_config.json` carries the Ideem application the owner provisioned for this repo on 2026-10-21 (`application_id` `9215506b-…`); `server_key` is set to the same value as `api_key`, as the conference demo's config was. On any `localhost:<port>` origin, `umfa.js` zeroes every hex segment of the config and sets `application_environment` to `TEST`, so the SDK initialises without real credentials; any other origin (tunnel, Vercel) uses the real values. The conference demo's application id is gone from this repo, so a number that played at the conference starts fresh here.

## Module layering

```
app.js / register.js / fido-test.js       page glue, DOM, screens, dialogs, flash messages
   |         |              |
   |         +---- key-enroll.js   the discoverable create that writes a key, as a function
   |         |          |     |
   |         +---- webauthn-util.js <-+     CBOR decoder, authenticator-data parser, RP-side checks
   |                     |
   +---- umfa.js         |                  Ideem UMFAClient wrapper; the only module that imports the SDK
   |        |            |
   +---- ishield.js <----+                  the raw WebAuthn get; zero SDK deps; also base64url + SHA-256 helpers
   |
   +---- key-records.js                     the keys a browser has associated, lost, replaced, and when; no DOM
   |
   +---- sna.js                             simulated Silent Network Authentication; no DOM, no network, no SDK
```

- `ishield.js`, `umfa.js`, `key-records.js` and `sna.js` are the partner-facing integration code and never touch the DOM. Keep UI concerns in the page scripts.
- `ishield.js` holds one ceremony, `webauthnIdentify`: the open get (empty `allowCredentials`, `userVerification: 'required'`, `hints: ['security-key']`) that returns `credentialId`, `authenticatedUser` (the user handle as text), the challenge sent, `clientDataHash`, `signatureHex`, the `userPresent` and `userVerified` flags and the `signCount`, read from the assertion's authenticator data inline so the module keeps zero imports. `webauthnAuthenticate(user)` wraps it with the expected user and logs a mismatch; the page decides. The non-discoverable create and the suspension helpers the conference demo had are gone.
- `key-enroll.js` holds the create. `createOptions`: `residentKey: 'required'`, `userVerification: 'required'`, `authenticatorAttachment: 'cross-platform'`, `hints: ['security-key']`, `attestation: 'none'`, `extensions: { credProps: true }` and no credProtect extension (with verification on every get the level decides nothing). `user.id` is the phone number as UTF-8. `enrollKey({ phone, displayName })` runs it, excludes credentials already in the `localStorage` list `ishield_enrollments` for that number, stores the entry (id, public key when the browser exposes it, algorithm, `rk`, `uvAtCreate`, sign count, the challenge, the time), and returns `warnings`: a non-discoverable credential, a create whose UV flag is false (no PIN protects it), or a ceremony check that did not match. `detectBrowser` names the browser from UA Client Hints or the user agent string.
- `key-records.js` is the per-browser memory of a user's keys, `localStorage` `ishield_keys:<user>`, newest first: `{ id, userHandle, status: 'active' | 'lost' | 'replaced', associatedAt, lastVerifiedAt, lostAt, replacedAt, userVerified, signCount }`. At most one record is active. `recordVerification(user, assertion, now)` is the setup or sign-in get: `'associated'` when the browser had no active key, `'verified'` for the active key (its `lastVerifiedAt` moves), `'refused'` for a lost or replaced key, `'unknown'` for a different key while one is active (nothing changes; Associate is the way to swap). `associateKey(user, assertion, now)` is the recovery: `'associated'` makes the id the active key and marks the previous one `replaced`, `'same'` leaves the active key as it is, `'refused'` is a lost or replaced key. `markLost(user, now)` marks the active key lost. `refusedKey(user, id)` answers for a lost or replaced id. `now` is a parameter so the Node harness can cover it.
- `sna.js` is a simulation of IDlayr's Secure SNA flow (`https://secure-sna-demo.idlayr.com`). `verifyNumber(phone, { scenario, onStep, speed, signal })` plays six timed steps and resolves to `{ match, checkId, code, reason, verifiedAt, steps }` without any network request; the scenarios are `success`, `nomatch` and `unsupported`. `isNumberVerified` / `setNumberVerified` / `getNumberVerification` keep a per-device marker, `sna_verified:<user>` in `localStorage`, that a successful check writes. A real integration replaces the inside of `verifyNumber` with calls to a backend holding the IDlayr key; nothing in `app.js` changes.
- `umfa.js` loads `zsm_app_config.json` at module init and caches one `UMFAClient` per `consumer_id`. `initializeZSMClient(user)` must precede `checkAllEnrollment`, `enroll`, and `authenticate`; `resetClient()` on logout. `enroll` and `authenticate` take the SDK's mode as their second argument (`true` is `'preferred'`, `false` is `'prevented'`, the strings pass through) and call `validateToken` automatically; an enrollment is not activated until that POST succeeds. The page passes `'required'` everywhere: in `'preferred'` mode a cancelled passkey sheet falls back to a ZSM-only ceremony with no passkey, and the passkey is this demo's recovery factor. In `'required'` mode the SDK's `enroll` on a browser with no share whose user already has a passkey on the server authenticates that passkey and rebuilds the share rather than registering a second one (its `addZSMToPasskeyCredential` path), which is what a phone after Reset Device, or a second browser, gets. `challengeDataFrom(credential)` is the challenge and signed challenge the HOME blocks show, from an `enroll` or `authenticate` result alike.
- `state.js` is a classic (non-module) script exposing a global `State` Proxy. The demo only uses `STATE.loginID` and `STATE.reset()`.

## WebAuthn constraints

The measurements behind these are in `docs/ishield-pinless-discoverable.md`, whose sections 1 to 6 are the September 2026 PIN-less findings and whose section 7 is the PIN change.

- **The keys carry a PIN** (the customer's rule, 2026-10-21). The create requires user verification, so the browser makes the user set a PIN on a key that has none and asks for it on every touch afterwards, on every device. The get requires verification too, and the UV flag it returns is shown on HOME as "PIN verified". The page cannot set, read or size the PIN.
- **Not yet measured, and gating the first real walkthrough**: PIN setup through a browser (Chrome's own PIN setup on the iShield failed with CTAP `0x37` in September; Safari's was never tried; the fallback is `fido2-token -S` once per key), the PIN prompt end to end on iPhone and Android with one credential on the key, and desktop Chrome's discoverable create once a PIN is set. Run them with `fido-test.html` on the deployed origin. Until then, enroll keys in Safari on a Mac.
- **Enroll on the production origin.** Credentials are bound to the RP ID (hostname). Keys enrolled on localhost or a tunnel are invisible to the Vercel site. The QR code points at `location.origin`, except from localhost, where it points at `PUBLIC_DEMO_ORIGIN` and the page says the credential just written will not be found there.
- **Phone numbers are bare digits everywhere**: on the key as `user.id`, in the `?userid=` parameter, in the records. `normalizePhone` (`register.js`) and `phoneDigits` (`app.js`) apply the same rule: strip non-digits, drop a leading US `1` from an 11-digit number. Format for display only.
- **The key is the authority on identity.** After a successful get, `reconcileUserId` in `app.js` compares the typed User ID with the user handle the key returned. A different number stops the flow; a different spelling of the same number is rewritten to the key's form; a key that returns no handle stops it too. The association get applies the same check (`sameUser`) without rewriting the box, since the user is logged in.
- **Every ceremony sits directly behind a tap.** The guide dialogs exist so that the tap on their button is the user gesture the WebAuthn prompt that follows needs; the number check's Continue is followed by a dialog for the same reason before the passkey or the replacement key.
- **A platform passkey answering the key prompt is a stop.** `webauthnIdentify` refuses an assertion whose `authenticatorAttachment` is `platform` and the page says a password manager may be stepping in front of the security-key prompt. There is no "continue without the key" path.

## Registration page (`register.html`)

`register.js` is page glue with no SDK or WebAuthn involvement beyond `enrollKey`. Enroll Key validates the box (`validatePhone`: bare digits, 7 to 15 of them), writes the digits back into it, runs `enrollKey({ phone, displayName })` with the formatted number as the display name, draws the warnings under the button, posts the entry to the dev server's `/credentials` (absent in production), shows what the key did (User ID, the credential id shortened, "PIN verified" yes/no from the UV flag, the time) and then the QR code from `registerUrl`: `<origin>/?userid=<digits>`, with the deployment substituted for a localhost origin and a warning that a credential written on localhost does not exist there. A failed create explains the DOMException name with `ERROR_HINTS`. The footer names the browser, with a word for desktop Chrome. The exported helpers (`normalizePhone`, `formatPhone`, `validatePhone`, `registerUrl`, `shortId`, `PUBLIC_DEMO_ORIGIN`) are pure, so the Node harness covers them; the module's top level only registers a `DOMContentLoaded` listener. The page uses the plain theme (`style.css` only, the `.rg-` classes at its end), as the key tester does.

## Demo flow in `app.js`

Screens are LOGIN, SNA and HOME, chosen by `updateUI()` from a pending number check first, then `STATE.loginID`. The User ID box is editable on LOGIN and read-only on SNA and HOME. Under Continue a hint says whether this phone will ask for the key or just the passkey (`renderLoginHint`, from `factorStates`).

**Continue** runs `login()`. The device's own state picks the ceremony, from `checkAllEnrollment`'s `hasZSMCred`:

- A phone that holds a ZSM share for the number: `verifyPasskey` (`authenticate(user, 'required')`), then `ensureNumberVerified` without force (a phone that holds the SNA marker answers at once), then `STATE.loginID` and HOME.
- A phone that holds none: `ONBOARDING_GUIDE` ("Let's get your phone ready.", the three steps, "Start with the USB FIDO Key", Start), then `verifyKey` (the get, then `reconcileUserId`), then `recordVerification`: a refused key stops with the date it was lost, an unknown key while another is active stops and points at Associate, otherwise the key's result goes to the USB Key block and the flash says "USB key verified"; then `ensureNumberVerified(user, { force: true })`, the SNA screen, always at setup; then `PASSKEY_GUIDE` ("Your number is verified!", Continue), whose tap is the gesture for `enroll(user, 'required')`; then `STATE.loginID` and HOME. A cancelled dialog or a failed step returns to LOGIN with a flash.

**The SNA screen** is the conference demo's: "Verify my number" runs `verifyNumber` from `sna.js` and colours its step rows as they go, a match writes the marker, puts the check id and code into the SNA result, and shows "<phone> Verified" and the four indicators (`renderFactors('sna-ind', …)`); Continue resolves the gate. The presenter can play IDlayr's other two outcomes once with `?sna=nomatch` or `?sna=unsupported`: the value goes to `sessionStorage`, comes off the address bar, and is consumed by the next check, which then offers Try again. There is no Cancel.

**HOME** (`renderHome`): the key card (`renderKeyCard`: the newest record's credential id shortened with the full id as a tooltip, Associated and Last verified as date and time to the second in the phone's locale via `formatWhen`, Status as Active, "Reported lost <when>" or "Replaced <when>"; the records before it as a history list; "No FIDO key is associated on this phone." when the list is empty), the four factor rows (`factorStates`: USB Key from `activeKey`, Phone# Verified from the SNA marker, Cryptographic Device Binding from `hasZSMCred`, Passkey Enrolled from `hasRemotePasskey` or `hasLocalPasskey`), the three challenge blocks, and the buttons.

**The challenge blocks** are the conference demo's terminal-style `details` rows, restored from the commit before its 2026-10-14 clean-up, with the rows cloned from the `#challenge-row-template` by `renderChallengeBlock` and a meta line under each. What each factor's last ceremony produced is kept per User ID in `sessionStorage` `factor_results:<user>` (`setResult` / `loadResults`), so a reload within the tab keeps it, and Log Out clears it. USB Key: Challenge (what was sent, base64url), Client data hash, Signed challenge (the signature, hex), Credential; meta "Key verified" or "Replacement key", "PIN verified" or "PIN not verified", the sign count, the time. Passkey: Challenge and Signed challenge from `challengeDataFrom`; meta Enrollment or Authentication and the time. Silent Network Auth: Check ID and Code; meta the number and the time, falling back to the marker when the tab has no result of its own. The copy buttons are wired by delegation on the document. No signature is verified on HOME: the phone never holds the key's public key, since the create ran on the registration machine.

**Authenticate** is `verifyPasskey` again, drawn into the Passkey block. **I lost this key** opens `LOST_KEY_GUIDE` ("Report this FIDO key lost", the note about corporate, "Report it lost" with "Keep it" as the second button); the report runs `markLost`, the card shows the key as lost, the USB Key factor reads false, and the button is disabled while no key is active. **Associate new FIDO key** opens `ASSOCIATE_GUIDE` (the three steps, "Start with the Passkey"), then `verifyPasskey`, then `ensureNumberVerified(user, { force: true })`, then `NEW_KEY_GUIDE` ("Insert the new FIDO USB Key", "Touch the key"), whose tap is the gesture for the get; the handle must name this User ID (`sameUser`), then `associateKey`: a refused key flashes when it was lost or replaced, the active key flashes "already associated", and a new one becomes the associated key with its time, the previous key marked replaced, the key's result in the USB Key block as "Replacement key". Every path ends in `updateUI`.

**Log Out** clears the tab's results, resets the SDK client and `STATE`, and returns to LOGIN; the key records and the markers stay. There is no session restore: every page load starts on LOGIN and Continue signs in again (the conference demo's 36-hour session was dropped on 2026-10-21 so the ceremonies are always seen). **Reset Device** (`purgeStorage`) wipes `localStorage`, `sessionStorage` and the `ideem` IndexedDB, keeping only the username, and navigates to the bare page path, dropping a `?userid=`; the next Continue sets the phone up again, and the passkey step authenticates the passkey the server still knows.

Arriving via `?userid=` only fills the User ID box: the registration QR carries the number that was just written to a key, and Continue reads it back. The User ID input carries deliberate password-manager opt-outs (`name="ishield-user-id"`, `data-1p-ignore`, etc.) because iOS AutoFill was offering saved `*.vercel.app` logins over it. Keep them if the field is restyled.

## Storage, all per browser

| Key | Where | Written by |
|---|---|---|
| `username` | localStorage | the box, `?userid=`, `reconcileUserId` |
| `ishield_keys:<user>` | localStorage | `key-records.js` |
| `sna_verified:<user>` | localStorage | `sna.js` on a successful check |
| `ishield_enrollments` | localStorage | `key-enroll.js` on the registration machine |
| `factor_results:<user>` | sessionStorage | `app.js`, the challenge blocks |
| `snaScenario` | sessionStorage | `?sna=`, consumed by the next check |
| the `ideem` IndexedDB | IndexedDB | the SDK (the ZSM share) |

## Testing

`tests/key-records.test.mjs` is a Node harness for the pure modules: `key-records.js` end to end (associate, verify, unknown, lost, refused, replace, same, a second user, clear) and the registration page's helpers, with `localStorage` and `document` stubbed. `tests/` is git-ignored, so it is local to this machine; recreate it from this description if it is missing.

On 2026-10-21 both pages were driven in Chrome on localhost with `navigator.credentials` stubbed and the SDK's `UMFAClientBase.prototype` methods replaced (the exported `UMFAClient` is a wrapper whose constructor returns the plugin-managed class, so a stub has to go on the base prototype before the client for a new User ID is created): setup through to HOME, the factor rows and all three blocks, Authenticate, the lost report, the association of a second key, the refusal of the lost key on a later association, Log Out and the passkey-only sign-in, and the registration create with the right options and the QR. No real key, phone or Ideem server has run the new flows yet; the open measurements are listed under WebAuthn constraints.
