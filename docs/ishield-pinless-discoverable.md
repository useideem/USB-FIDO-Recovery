# iShield PIN-less Discoverable Credentials: Test Findings

What we learned on 2026-09-15 and 2026-09-16 while testing whether a Swissbit
iShield key can identify its owner on someone else's phone with a touch, no PIN
and no typing. Captured here so it can be folded into the demo later.

**Status:** works on every meeting device tested -- iPhone (Safari and Chrome),
Android (Chrome 152) and Mac Safari. Blocked in desktop Chrome unless the page
sends credential IDs.

---

## 1. The conference flow

1. **Booth.** Staff put a passkey on an attendee's iShield key. The attendee's
   phone number is stored as the account ID (`user.id`).
2. **Meeting.** Later, the attendee plugs their key into another attendee's
   phone. The same web app reads the phone number from the key, shows it, and
   the key owner confirms with a touch.
3. **Constraints.** The attendee never enters a PIN and never types their phone
   number. Booth setup is done by staff; meeting devices are whatever phones
   attendees own (iPhone and Android).

The meeting step has no prior knowledge of the key, so the credential must be
**discoverable** (stored on the key), and it is looked up with an **empty
`allowCredentials` list**, unless the app supplies the issued credential IDs
(see section 5).

---

## 2. Summary of results

Key state: no PIN set, one discoverable credential, created touch-only.

| Meeting device / browser | Empty-list Get | Get with credential ID list | Tested |
|---|---|---|---|
| iPhone Safari (iOS 26.6.1) | **works, touch only** | not run | yes |
| iPhone Chrome 152 (iOS) | **works, touch only** | not run | yes |
| Mac Safari 26.5 | **works, touch only** | works, touch only | yes |
| Mac Chrome 152/153 | **refused** | **works, touch only** | yes |
| Android Chrome 152 (Android 13) | **works, touch only** | not run | yes |

If the key has **any PIN set**, Chrome and Safari both prompt for it on the
empty-list Get, even with `userVerification: "discouraged"`. **Keys must stay
PIN-less.**

In every successful touch-only Get the result had `UV = false` and the user
handle came back as the phone number.

---

## 3. Why: what each layer allows

### The key (Swissbit iShield Key 2 Pro MIFARE)

`fido2-token -I` (libfido2 1.17.0) reports:

| Field | Value | Meaning |
|---|---|---|
| USB ID | vendor `0x1370`, product `0x0911` | |
| Versions | `U2F_V2`, `FIDO_2_0`, `FIDO_2_1` | CTAP 2.1 |
| AAGUID | `7787a482-13e8-4784-8a06-c7ed49a7aaf4` | Chrome sees the real value; Safari with `attestation: "none"` returns all zeros |
| Extensions | `credProtect`, `credBlob`, `minPinLength`, `hmac-secret` | no `largeBlob` |
| Options | `rk`, `noalwaysUv`, `credMgmt`, `authnrCfg`, `clientPin` (false after reset), `pinUvAuthToken`, `setMinPINLength`, `makeCredUvNotRqd` | |
| `maxCredentialCountInList` / `maxCredentialIdLength` | not reported (0) | affects Chrome's ID-list probing (section 4) |
| `minPINLength` | 4 | |
| UV modality | `0x801` (test of user presence, external PIN) | no biometrics |
| Remaining discoverable slots | 300 / 299 | **unreliable**: read 300 with a credential stored and 299 at another time. Don't use it to check whether a key is empty. |

**The key itself supports the whole flow.** With no PIN set, libfido2 created
a discoverable credential with only a touch, and read it back with an empty
allow list:

```sh
# create: -r = discoverable, -c 1 = credProtect level 1 (UV optional)
fido2-cred -M -r -c 1 -i cred.in -o cred.out <device> es256
# lookup with no allow list, no PIN
fido2-assert -G -r -p -i assert.in -o assert.out <device>
```

The created credential had `UV = false` and `credProtect = 1`, and both the
attestation and assertion signatures verified. With two credentials on the key,
the empty-list assertion returned both user IDs without a PIN.

### Desktop Chrome

Chrome's behaviour is hard-coded in Chromium, so no page option changes it.
Source read from `chromium/chromium` main (`fido_device_authenticator.cc` last
changed in commit `6cb97600`, 2026-08-11):

- **Empty-list Get forces UV.**
  `device/fido/fido_device_authenticator.cc`, `PINUVDispositionForGetAssertion`
  (lines ~780–805):

  ```cpp
  const UserVerificationRequirement uv_requirement =
      request.allow_list.empty() ? UserVerificationRequirement::kRequired
                                 : request.user_verification;
  ...
  if ((can_collect_pin && pin_configured) || CanGetUvToken()) {
    return PINUVDisposition::kGetToken;      // ask for the PIN
  }
  return PINUVDisposition::kUnsatisfiable;   // no PIN set: refuse
  ```

  So:
  - **No PIN on the key:** Chrome refuses. Its log shows
    `cannot satisfy assertion request` then UI step `kMissingCapability`, and
    the user sees "Your device can't be used with this site". Chrome never
    sends the assertion request to the key.
  - **PIN on the key:** Chrome prompts for it (`kClientPinEntry`), whatever the
    page asked for.

- **A Get with an ID list honours the page's UV setting.** With
  `userVerification: "discouraged"` it's touch only. Tested on a PIN-less key.

- **Discoverable Create on a security key forces UV.**
  `device/fido/make_credential_request_handler.cc` (lines ~1009–1017):

  ```cpp
  // "Upgrade" uv to `required` for discoverable credentials on non-platform
  // authenticators, and on security keys that have the `alwaysUv` config
  // enabled.
  const bool upgrade_uv = (request->resident_key_required &&
                           authenticator->AuthenticatorTransport() !=
                               FidoTransportProtocol::kInternal) ||
                          auth_options.always_uv;
  ```

  On a PIN-less key Chrome opens "Set up a new PIN" (`kClientPinSetup`). So
  **Chrome can't be the booth tool.** Non-discoverable Create does work touch-only.

- **At most 64 IDs in `allowCredentials`.** Chrome throws
  `RangeError: The allowCredentials attribute exceeds the maximum allowed size (64).`

- **Chrome probes the ID list silently.** Because the iShield doesn't report
  `maxCredentialCountInList` / `maxCredentialIdLength`,
  `FilterAndBatchCredentialDescriptors` (`device/fido/make_credential_task.cc`)
  uses batches of one. Measured end to end with 64 IDs (63 random decoys, real
  one last): **2.9 s, one touch**, phone number returned, `UV = false`.

- **Chrome couldn't set a PIN on this key.** Its "Set up a new PIN" step failed
  with CTAP `0x37` (`kCtap2ErrPinPolicyViolation`) for the PINs we entered
  (including `1234`). The same key accepted a PIN via python-fido2
  (`ClientPin(..., PinProtocolV2()).set_pin(...)`). This looks like a
  Chrome/iShield compatibility quirk. It doesn't matter for the PIN-less plan.

- **`credProtect` enforcement is rejected.**
  `credentialProtectionPolicy: "userVerificationOptional"` together with
  `enforceCredentialProtectionPolicy: true` throws `NotSupportedError`
  ("Requested protection policy is inconsistent or incongruent with other
  requested parameters"). Send the policy without `enforce`. When Chrome did
  create a discoverable credential with the policy, the key reported
  `credProtect = 1`.

### Safari (Mac) and iOS

- Discoverable Create on a PIN-less key: **touch only** (`UV = false`).
- Empty-list Get: **touch only**, phone number returned.
- Get with an ID list: **touch only**.
- If the key has a PIN: **prompts for the PIN** on the empty-list Get.
- Safari returns no `credProps` result and no extension output in
  authenticator data (flags `0x41` on create), so the page can't see whether
  the credential is discoverable or which `credProtect` level was applied. The
  empty-list Get working without UV shows it is discoverable and usable
  without UV.
- With **two or more** credentials for the site on the key, Safari shows a
  "Sign In" sheet listing `Credential (<first characters of the credential ID>)`
  entries, not names, because the key doesn't reveal names without UV. It also
  always offers "Scan QR Code" (phone passkey).
- **Chrome on iOS behaves like Safari**, not like desktop Chrome, because it
  uses Apple's WebAuthn stack.

### Android

Android Chrome uses Google Play services for security keys, not the desktop
Chromium code above, so none of the desktop limits apply. Confirmed 2026-09-16
on a Pixel 4 XL (Android 13, Chrome 152.0.7977.82) over a Cloudflare tunnel:

- **Empty-list Get: touch only.** `UV = false`, the phone number came back as
  the user handle, the signature verified and the sign count incremented across
  three consecutive runs.
- It behaves like iOS, not like desktop Chrome. The empty allow list is fine.
- **NFC still untested** -- the transport wasn't recorded for these runs. Test
  it before the conference.

**The browser version matters more than the platform.** The same phone on its
stock **Chrome 101** (May 2022) did complete the same Get, but routed to Google
Password Manager first: the user had to tap "more options" and choose the USB
key, and the first attempts threw `NotReadableError`, then `NotAllowedError`.
The cause is `hints`:

- `hints: ["security-key"]` shipped in **Chrome 128/129**. Older Chrome drops
  the member silently and falls back to its passkey-first picker.
- Hints are **advisory, not binding**. Chrome's documentation notes they "may
  not be respected on platforms such as Windows where the UI is not controlled
  by Chrome" -- Android's Credential Manager is the same kind of OS-owned UI,
  so treat a clean routing as likely, not guaranteed.
- Don't reach for `authenticatorAttachment` instead: it is not a member of the
  get options at all (create only), and where Chrome reads it, it overrides
  hints.

Chrome for Android has required Android 10 or newer since Chrome 139 (August
2025), so any phone able to run current Chrome is new enough for hints.

---

## 4. Rules for the demo

1. **Never set a PIN on a demo key.** A PIN makes every browser ask for it.
   Reset a key that has one (section 6).
2. **Create at the booth with Safari on a Mac** (or the libfido2 CLI). Not
   Chrome, which forces PIN setup.
   - `authenticatorSelection: { authenticatorAttachment: "cross-platform", residentKey: "required", userVerification: "discouraged" }`
   - `extensions: { credProps: true, credentialProtectionPolicy: "userVerificationOptional" }`, without `enforce...`
   - `hints: ["security-key"]`
3. **Create on the production domain.** Credentials are bound to the RP ID
   (the hostname). Ones made on `localhost` or a tunnel domain won't be found
   on the real site.
4. **Store on the server** for every issued key: credential ID, public key
   (`response.getPublicKey()`, SPKI), algorithm, user handle / phone number and
   sign count. The server list is needed for desktop Chrome, and it's where
   signatures get verified.
5. **Meeting step lookup.**
   - **iPhone / iPad (any browser):** empty `allowCredentials`,
     `userVerification: "discouraged"`.
   - **Desktop Chrome:** `allowCredentials` = issued IDs (max 64),
     `userVerification: "discouraged"`.
   - **Android Chrome:** empty `allowCredentials`,
     `userVerification: "discouraged"` -- the same call as iPhone. Chrome 128+
     is what makes `hints` send the user straight to the key rather than to the
     passkey picker.
   - Choose by platform up front. Don't try the empty list first in Chrome:
     users would see the "can't be used with this site" dialog before the
     fallback.
6. **Read the phone number from `response.userHandle`.** It's returned on every
   successful Get, including touch-only ones. Names (`user.name`) aren't
   available without UV.
7. **Verify on the server:** challenge, origin, `rpIdHash`, signature against
   the stored public key, and that the sign count increased (the iShield keeps
   a counter).
8. **Consider an opaque `user.id`** (random bytes) mapped to the phone number on
   the server, rather than the raw number on the key. The tests used the phone
   number directly for simplicity.

### More than 64 keys (desktop Chrome only)

Only the ID-list path hits this limit, so it is a desktop Chrome problem alone:
phones use the empty allow list and never send IDs. Chrome's 64-ID cap means a
single Get can't cover a larger event. Options, none tested yet:

- Issue keys in groups of at most 64 and mark the group on the key (e.g. a
  color the user taps first).
- Try the list in batches of 64. Each batch that doesn't contain the key costs a
  failed Get and an extra touch.
- Put a QR sticker with the credential ID on each key, and send just that ID.

### Relation to the current demo code

`ishield.js` today creates **non-discoverable** credentials and looks them up
with the credential ID saved in `localStorage` on the enrolling device. A second
device has no saved ID, so it can't find the key's credential. The approach
above (discoverable credential plus server-stored IDs) fixes that.

`enroll.html` is the first piece of that work: it enrolls attendees the way
this document says to, independently of `ishield.js`. The retrieval side of the
demo still has to be switched over.

### Handing the attendee off to the demo

The booth Mac enrolls the key; the attendee then carries on with their own
phone. The seam between the two is a query parameter:

```
https://authenticate26.vercel.app/?userid=9135551234
```

`app.js` reads `?userid=` on load and puts it in the User ID field. The value
is the bare digits, and nothing validates its shape.

It also switches **New** off. That matters more than it looks: the toggle
picks the ceremony. New on routes to `trustDevice()`, which calls
`webauthnEnroll` -- a **create**, which on a key that already holds this number
would write a second credential for the same person. New off routes to
`login()`, which calls `webauthnAuthenticate` -- a **get**, which is the whole
point of arriving from the booth. Somebody scanning the QR was enrolled a
moment ago, so they are an existing user on a new device, and that is the path
they belong on.

### The User ID on screen has to be the credential on the key

`reconcileUserId` (`app.js`) settles it after every get. The key is the
authority: it hands back the user handle stored in the credential, and:

- a **different identity** stops the flow -- the demo will not carry on under a
  name the key never vouched for;
- a **different spelling of the same number** (`913-555-1235`, `19135551235`)
  is accepted and the field is rewritten to the key's own spelling, so after a
  successful touch the two are literally equal. The digits rule is the same one
  `normalizePhone` in `enroll.js` applied on the way onto the key;
- a credential that returns **no user handle** -- the old non-discoverable kind
  `ishield.js` used to create -- leaves the typed value alone, because there is
  nothing to compare it against.

Everything downstream (ZSM binding, the enrollment marker, `STATE.loginID`)
then keys off the key's spelling rather than whatever was typed.

### Password managers fight for that field

On an iPhone the field was being covered by an iOS AutoFill sheet offering a
saved `vercel.app` password -- not a passkey prompt, and nothing to do with
WebAuthn; no ceremony has run at that point. `autocomplete="off"` does not stop
it, because the heuristics key off a field that looks like a username, and
`id="username"` under a label reading "USER ID" is exactly that. `vercel.app`
being a shared domain widens the match to any saved `*.vercel.app` login.

What the field carries now: a neutral `name` (WebKit weighs `name` above `id`),
`inputmode="numeric"`, and the documented opt-outs `data-1p-ignore`,
`data-lpignore`, `data-bwignore`, `data-form-type="other"`. Arriving from the
QR also lands on the LOGIN screen, where `showScreen` already makes the field
readonly -- and a readonly field is not offered autofill at all.

The parameter used to be `email`, a leftover from when the demo identified
people by address. Nothing accepts that spelling any more, so a QR code
generated before the rename lands on the demo with an empty field rather than
a filled one.

Once the credential is written *and* the database record is in place,
`enroll.js` shows that URL as a QR code (`showQr`). Both conditions matter: a
code for a number with no record behind it would open the demo on an empty
account. The code is generated in the page from the vendored
`qrcode-generator` package -- no image service sees the phone number -- at
error-correction level M, which for this URL length comes out as a 33x33
version-4 code. The value is percent-encoded even though digits never need it.

The QR points at `location.origin`, so the code matches the origin the
credential's RP ID is bound to. The exception is a page served from
`localhost`, which no phone can reach: there it points at
`PUBLIC_DEMO_ORIGIN`, the Vercel deployment. Enrolling through a tunnel
produces tunnel URLs, which is correct -- those credentials belong to the
tunnel hostname.

---

## 5. Open questions

- **NFC**, on Android and iPhone alike. Every run so far was over a cable.
- **Old browsers in the wild.** Chrome below 128 still works but routes through
  the passkey picker first. Decide whether the booth warns attendees, or the app
  detects the version and shows its own instructions.
- **Desktop Chrome, key with a PIN, ID-list Get:** Chromium source says it
  should stay touch only. Not tested (and irrelevant if keys stay PIN-less).
- **Safari with exactly one credential on the key:** confirm whether the "Sign
  In" sheet still appears (an extra Continue tap) or the Get completes
  straight away.
- **Which `credProtect` level Safari/iOS actually applies** at create (not
  visible to the page).
- **iPad**, and iPhones with Lightning (NFC only).
- **Strategy for more than 64 keys** (see above).

---

## 6. Test tooling in this repo

| File | Purpose |
|---|---|
| `enroll.html`, `enroll.js` | Booth enrollment page: first name, last name, phone number, one button. Creates the discoverable credential with the settings proven above (`residentKey: required`, `userVerification: discouraged`, `credProtect` level 1 unenforced, `hints: ["security-key"]`, `attestation: none`) and `user.id` = the phone number's digits, so any other device reads it back from the user handle. Checks the result and warns on screen when the credential came back non-discoverable, when the key used a PIN (UV true), or when `credProtect` is not level 1 -- all three break retrieval, and the attendee is still standing there. Warns up front in desktop Chrome, which cannot do this create PIN-less. Run it in Safari on a Mac. On success it also writes the attendee to the user database (`docs/user-api.md`) and shows a QR code that opens the demo with that number already filled in. |
| `webauthn-util.js` | The parsing both pages share: the CBOR reader, authenticator data (flags, `signCount`, AAGUID, extension outputs such as `credProtect`), and the relying-party checks on `clientDataJSON` and `rpIdHash`. |
| `fido-test.html`, `fido-test.js` | Raw WebAuthn test page: Create and Get with `residentKey`, `userVerification`, `credProtect` and allow-list choices (`attestation` is fixed at `none`, and both `userVerification` controls default to `discouraged` -- the PIN-less settings this demo needs). Parses authenticator data flags and extensions, verifies signatures, checks counters. The footer names the browser actually rendering the page, read from UA Client Hints rather than `navigator.userAgent` -- that is what caught the stale Chrome 101 above, whose user agent string reported a version it never shipped. |
| `dev-server.mjs` | Local server (`node dev-server.mjs`, port 8080). Writes every page result to `.dev-logs/fido-test.jsonl` and keeps a shared list of issued credentials (`GET/POST /credentials`) in `.dev-logs/credentials.json`. `.dev-logs/` is git-ignored. |

### Testing on phones

Phones need HTTPS. A Cloudflare quick tunnel works:

```sh
node dev-server.mjs
cloudflared tunnel --no-autoupdate --url http://localhost:8080   # prints https://<random>.trycloudflare.com
```

The tunnel address changes each run, so re-create credentials for it. (Tailscale
Funnel isn't available with our Headscale control server.)

### Useful commands

```sh
brew install libfido2
fido2-token -L                        # list keys
fido2-token -I <device>               # capabilities (getInfo), PIN state
```

- **Reset a key** (removes all credentials and the PIN): Chrome →
  `chrome://settings/securityKeys` → Reset your security key, then re-plug and
  touch when prompted.
- **Chrome's internal FIDO log:** launch a separate profile with
  `--user-data-dir=<dir> --enable-logging=stderr --v=1` and grep for `FIDO:`.
  It shows the CTAP commands, the key's answers and each UI step
  (`kMissingCapability`, `kClientPinSetup`, `kClientPinEntry`, …).
- **Chrome's virtual authenticator** (DevTools protocol `WebAuthn.*`) is good
  for checking page logic, but it can't reproduce these results. It always
  reports UV when UV is configured and doesn't report `credProtect`.
