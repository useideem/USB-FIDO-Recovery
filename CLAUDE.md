# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A static, no-bundler browser demo for the Authenticate 2026 conference: Swissbit iShield USB keys (raw WebAuthn) combined with Ideem's ZSM / Passkeys+ SDK. Plain ES modules served as-is; there is no framework, no transpiler, and no linter configured. `.gitignore` excludes `tests/`, `test-results/`, and `playwright.config.js`, so any Playwright tests are local-only and not part of the repo.

Three pages share `style.css` and a handful of modules:

| Page | Role |
|---|---|
| `index.html` + `app.js` | The demo: Trust Device, Login, step-up actions, suspend/reactivate |
| `enroll.html` + `enroll.js` | Booth page: writes a discoverable credential (phone number as `user.id`) onto an iShield key, saves the attendee to the user database, shows a QR that opens the demo with `?userid=<digits>` |
| `fido-test.html` + `fido-test.js` | Raw WebAuthn tester for hardware keys, no SDK involved |

## Commands

```sh
npm install              # postinstall runs `npm run build`
npm run build            # node build.js -- copies SDK + qrcode-generator from node_modules into vendor/
node dev-server.mjs      # http://localhost:8080 (PORT=3000 to change)
./run.sh                 # bare python http.server fallback; no /db proxy, no /log
```

`vendor/` is git-ignored and must exist before any page loads: `index.html` resolves `@ideem/zsm-client-sdk` through an import map to `./vendor/@ideem/zsm-client-sdk/ZSMClientSDK.js`, and `enroll.js` dynamically imports `./vendor/qrcode-generator/dist/qrcode.mjs`. If a page 404s on an import, run the build. Adding a new npm dependency that a page imports means adding it to the `packages` list in `build.js` as well.

Use `dev-server.mjs`, not `run.sh`, for anything touching the user database: only the Node server proxies `/db/*`. It also accepts `POST /log` (appends to `.dev-logs/fido-test.jsonl`) and `GET/POST /credentials` (shared list in `.dev-logs/credentials.json`); both are dev-only and silently absent in production.

Testing on a phone needs HTTPS. A Cloudflare quick tunnel works; the hostname changes every run, so credentials made under it are bound to that hostname only:

```sh
cloudflared tunnel --no-autoupdate --url http://localhost:8080
```

## Vercel deployment

Production is `https://swissbit-ideem.vercel.app`, deployed from GitHub (`useideem/authenticate26`, branch `main`). There is no `.vercel/` link in this checkout and no Vercel CLI installed; push to deploy. `vercel.json` sets `outputDirectory` to `.`, so the whole repo root is the static site, including `api/db.js` source and `zsm_app_config.json`.

The one serverless function is `api/db.js`, a proxy to the Ideem user API at `https://sbit.authconcepts.com:3033/api` (override with the `DB_API` env var). The rewrite in `vercel.json` maps `/db/:path*` to `/api/db?path=:path*`. Two constraints were measured on real deployments and must be kept:

- **Flat file, path in the query.** A catch-all `api/db/[...path].js` matched only one path segment on Vercel (`/api/db/users` worked, `/api/db/users/9999` returned Vercel's NOT_FOUND). Keep the function at `api/db.js` with nothing dynamic in its name and pass the remainder as `?path=`.
- **A function, not a plain external rewrite.** Vercel does not document non-standard ports (`:3033`) in rewrite destinations. A server-side fetch has no such ambiguity.

`dev-server.mjs` implements the identical proxy in `handleDb`, so pages always fetch the relative path `./db/...` and work unchanged on localhost, a tunnel, and Vercel. Change the two together.

The upstream API has no authentication and no CORS headers. Its measured behaviours (exact-string phone matching, PUT replaces rather than merges, duplicate phones allowed, PATCH balance is an additive ledger adjustment that permits overdrafts) are in `docs/user-api.md`. Read it before touching any `/db` call. The full route list is the owner's Postman export at `docs/IdeemAPI.postman_collection.json`; it names the 15 routes but has no responses or PUT bodies, so the markdown doc is the behavioural reference and the collection is only the map.

Users are keyed two ways: phone number and badge confirmation number (`/users/conf/:confNumber`). The confirmation-number routes are case-insensitive, the lookup returns an object rather than an array, and only that route and the write-response bodies carry the `confNumber`, `Company`, and `email` fields; list, by-id, and by-phone reads omit them. No write route stores those three fields, so the API cannot assign a confirmation number: the PUT by confirmation number only updates a record that already has one and 404s otherwise, despite the collection calling it "Create". The balance PATCH by confirmation number is the same additive ledger adjustment as the other balance routes. The owner's test user `KVNLHY66K2P` must never be replaced or deleted.

## Module layering

```
app.js / enroll.js / fido-test.js      page glue, DOM, screens, flash messages
   |            |            |
   |            +---- webauthn-util.js   CBOR decoder, authenticator-data parser, RP-side checks
   |                         |
   +---- umfa.js             |           Ideem UMFAClient wrapper; the only module that imports the SDK
   |        |                |
   +---- ishield.js <--------+           raw WebAuthn for the key; zero SDK deps; also base64url + SHA-256 helpers
```

- `ishield.js` and `umfa.js` are the partner-facing integration code and never touch the DOM. Keep UI concerns in the page scripts.
- `umfa.js` loads `zsm_app_config.json` at module init and caches one `UMFAClient` per `consumer_id`. `initializeZSMClient(user)` must precede `checkAllEnrollment`, `enroll`, and `authenticate`; `resetClient()` on logout. `enroll` and `authenticate` call `validateToken` automatically, and an enrollment is not activated until that POST succeeds.
- On any `localhost:<port>` origin, `umfa.js` zeroes every hex segment of the config and sets `application_environment` to `TEST`, so the SDK initialises without real credentials. Any other origin (tunnel, Vercel) uses the real values in `zsm_app_config.json`.
- `state.js` is a classic (non-module) script exposing a global `State` Proxy. The demo only uses `STATE.loginID` and `STATE.reset()`; the `stateChange` events it dispatches are unused.
- The README's quick-start still shows a `@ideem/plugins.passkeys-plus` side-effect import. That package was removed; `umfa.js` imports only `UMFAClient` from `@ideem/zsm-client-sdk`, and the SDK is pinned to `latest` in `package.json`.

## WebAuthn constraints that are not negotiable

These came out of two days of measurement on real keys and browsers (`docs/ishield-pinless-discoverable.md`). Breaking any of them breaks retrieval on attendees' phones.

- **Demo keys must stay PIN-less.** Any PIN makes every browser prompt for it, even with `userVerification: 'discouraged'`.
- **Enroll in Safari on a Mac, never desktop Chrome.** Chrome upgrades a discoverable create on a security key to UV-required and forces PIN setup. `enroll.js` warns on screen when it detects desktop Chrome.
- **Enroll on the production origin.** Credentials are bound to the RP ID (hostname). Keys enrolled on localhost or a tunnel are invisible to the Vercel site. The QR code points at `location.origin`, except from localhost, where it points at `PUBLIC_DEMO_ORIGIN` in `enroll.js` and shows a warning that the credential will not be found there.
- **Create options** (`enroll.js`): `residentKey: 'required'`, `userVerification: 'discouraged'`, `credentialProtectionPolicy: 'userVerificationOptional'` **without** `enforceCredentialProtectionPolicy` (Chrome throws `NotSupportedError` on that pair), `hints: ['security-key']`, `attestation: 'none'`.
- **Get options** (`ishield.js` `webauthnAuthenticate`): empty `allowCredentials`, `userVerification: 'discouraged'`, `hints: ['security-key']`. The empty list is what lets a stranger's phone read the key, and it is what desktop Chrome refuses on a PIN-less key. Phones (iOS any browser, Android Chrome 128+) are the target; desktop Chrome would need an ID list capped at 64 entries, which is not implemented.
- **Phone numbers are bare digits everywhere**: on the key as `user.id`, in the database, in the `?userid=` parameter, in lookups. `normalizePhone` (`enroll.js`) and `phoneDigits` (`app.js`) apply the same rule: strip non-digits, drop a leading US `1` from an 11-digit number. Format for display only.
- **The key is the authority on identity.** After a successful get, `reconcileUserId` in `app.js` compares the typed User ID with the `userHandle` the key returned. A different number stops the flow; a different spelling of the same number is rewritten to the key's form.

## Demo flow in `app.js`

Screens are SETUP, LOGIN, ACTIONS, chosen by `updateUI()` from `STATE.loginID` and the "New" toggle. The toggle picks the ceremony: New on runs `trustDevice()` (iShield **create**, then ZSM enroll); New off runs `login()` (iShield **get** if ZSM is not bound locally, then ZSM enroll or authenticate). Arriving via `?userid=` forces New off and Passkeys off, because the attendee was just enrolled at the booth and must take the get path, not write a second credential.

On ACTIONS, every button runs the ZSM step-up `authenticate` first. Authenticate and P2P Contact Exchange then settle against the user database: `settleAction` re-reads the record by bare-digit phone, refuses the charge on the page if the balance is short (the API allows overdrafts), and sends `PATCH /users/:id/balance` with a **negative** amount, since the API adds what it is sent. The amounts are fixed per action in `ACTION_AMOUNTS`; the other two actions touch no balance. A failed PATCH is re-read, never retried, because the API has no idempotency key. The balance line on the screen is hidden when the User ID has no record, and a missing or unreachable database never blocks the step-up itself.

Suspension is a `localStorage` flag (`passkeys_suspended:<user>`); a suspended device requires an iShield touch plus ZSM authenticate to clear it. "Reset Device" wipes `localStorage`, `sessionStorage`, and the `ideem` IndexedDB, keeping only the username.

The User ID input carries deliberate password-manager opt-outs (`name="ishield-user-id"`, `data-1p-ignore`, etc.) because iOS AutoFill was offering saved `*.vercel.app` logins over it. Keep them if the field is restyled.
