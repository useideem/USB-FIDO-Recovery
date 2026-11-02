# iShield PIN-less Discoverable Credentials: Test Findings

What we learned on 2026-09-15 and 2026-09-16 while testing whether a Swissbit
iShield key can identify its owner on someone else's phone with a touch, no PIN
and no typing. The measurements stand; what the app asks of the key has since
changed.

**Status of the measurements:** the PIN-less open get works on every phone
tested -- iPhone (Safari and Chrome), Android (Chrome 152) -- and in Mac
Safari. Blocked in desktop Chrome unless the page sends credential IDs.

**Status of the app (2026-10-21):** the keys carry a PIN now. The customer's
rule for the recovery demo is a four-digit PIN on the key, so the create on
the registration page requires user verification and every get asks for the
PIN. Section 7 says what that changes and what has not been measured yet.
The conference flow these tests served, and the rules in section 4, describe
the PIN-less world and are kept as the record of it.

---

## 1. The flow these tests were for

The September tests served a conference demo: staff wrote an attendee's phone
number onto a key at a booth, and later the attendee plugged the key into
another attendee's phone, which read the number back with a touch, no PIN and
nothing typed. The reading phone had no prior knowledge of the key, so the
credential had to be **discoverable** (stored on the key) and looked up with
an **empty `allowCredentials` list**, unless the app supplied the issued
credential IDs (see section 5).

The recovery demo this repository holds now keeps the same mechanics: the
registration page writes the number onto the key, and the user's own phone
reads it back with the empty-list get. Two things differ. The phone is the
user's, not a stranger's, and the key has a PIN.

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

- **Chrome couldn't set a PIN on this key, and it was the PIN, not Chrome.**
  Its "Set up a new PIN" step failed with CTAP `0x37`
  (`kCtap2ErrPinPolicyViolation`) for the PINs we entered (including `1234`).
  The same key accepted a PIN via python-fido2
  (`ClientPin(..., PinProtocolV2()).set_pin(...)`). Read at the time as a
  Chrome/iShield compatibility quirk; section 8 (2026-11-01) has the
  explanation: `0x37` is the key enforcing Swissbit's PIN rules, which refuse
  a run such as `1234`, while `minPINLength` 4 is all the browser checks.
  Chrome's PIN setup has not been retried with a PIN the key accepts. It
  didn't matter for the PIN-less plan.

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

These are the PIN-less rules the September tests produced. Rules 1 and 2 no
longer apply to this app: since 2026-10-21 its keys carry a PIN and the create
requires verification (section 7). The rest still hold.

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
   - *2026-11-01:* the recovery demo's main page now sends the ids it has
     recorded on every platform, each with `transports: ["usb", "nfc"]`,
     because Safari's empty-list get opened the passkey chooser with Touch ID
     first; the empty list is kept only for a phone with no records
     (section 8).
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

### Relation to the current code

`key-enroll.js` holds the create (the main page runs it at setup and in
recovery, the registration page as a bench tool), and `webauthnIdentify` in
`ishield.js` holds the get (the main page runs it from Verify USB key, with
the ids it has recorded in the allow list, or the empty list when it has
none). The get also returns the credential id that answered, which is how
`key-records.js` tells a replacement key from the one that was reported lost.

### Handing the user off to the main page

The registration machine writes the key; the user then carries on with their
own phone. The seam between the two is a query parameter:

```
https://<deployment>/?userid=9135551234
```

`app.js` reads `?userid=` on load and puts it in the User ID field. The value
is the bare digits, and nothing validates its shape. Continue then calls
`webauthnAuthenticate` -- a **get**, never a create: the main page only ever
reads a key.

### The User ID on screen has to be the credential on the key

`reconcileUserId` (`app.js`) settles it after the setup get, and the same
check guards the association get. The key is the authority: it hands back
the user handle stored in the credential, and:

- a **different identity** stops the flow -- the app will not carry on under a
  name the key never vouched for;
- a **different spelling of the same number** (`913-555-1235`, `19135551235`)
  is accepted and the field is rewritten to the key's own spelling, so after a
  successful touch the two are literally equal. The digits rule is the same one
  `normalizePhone` in `register.js` applies on the way onto the key;
- a credential that returns **no user handle** stops the flow too; there is
  nothing to compare it against.

Everything downstream (the key record, the ZSM binding, `STATE.loginID`)
then keys off the key's spelling rather than whatever was typed.

### Password managers fight for that field

On an iPhone the field was being covered by an iOS AutoFill sheet offering a
saved `vercel.app` password -- not a passkey prompt, and nothing to do with
WebAuthn; no ceremony has run at that point. `autocomplete="off"` does not stop
it, because the heuristics key off a field that looks like a username, and
`id="username"` under a label reading "USER ID" is exactly that. `vercel.app`
being a shared domain widens the match to any saved `*.vercel.app` login.

What the field carries: a neutral `name` (WebKit weighs `name` above `id`),
`inputmode="numeric"`, and the documented opt-outs `data-1p-ignore`,
`data-lpignore`, `data-bwignore`, `data-form-type="other"`.

The QR code on the registration page is generated in the page from the
vendored `qrcode-generator` package -- no image service sees the phone number
-- at error-correction level M. It points at `location.origin`, so the code
matches the origin the credential's RP ID is bound to. The exception is a
page served from `localhost`, which no phone can reach: there it points at
`PUBLIC_DEMO_ORIGIN`, the deployment, and the page says the credential just
written will not be found there. Encoding through a tunnel produces tunnel
URLs, which is correct -- those credentials belong to the tunnel hostname.

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
| `register.html`, `register.js`, `key-enroll.js` | Registration page: a phone number and one button, which creates the discoverable credential (`residentKey: required`, `userVerification: required` since 2026-10-21, `hints: ["security-key"]`, `attestation: none`, no credProtect extension) with `user.id` = the phone number's digits, so the user's phone reads it back from the user handle. `key-enroll.js` holds that create as a function. The page checks the result and warns on screen when the credential came back non-discoverable or when the key did not verify the user (no PIN). On success it shows the credential id, whether the PIN was used, and a QR code that opens the main page with that number already filled in. |
| `webauthn-util.js` | The parsing `key-enroll.js` and the key tester share: the CBOR reader, authenticator data (flags, `signCount`, AAGUID, extension outputs such as `credProtect`), and the relying-party checks on `clientDataJSON` and `rpIdHash`. |
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

---

## 7. The PIN change (2026-10-21)

The recovery demo's customer asked for a four-digit PIN on the key. WebAuthn
gives a page one lever for that: `userVerification: "required"`. The browser
then makes the user set a PIN on a key that has none (the key's `minPINLength`
is 4, section 3, and its own PIN rules apply on top, section 8) and asks for
it on every get afterwards, on every device. A
page cannot set, read or size the PIN; "four digits" is what the user types
when the browser asks.

What changed in the code:

- `createOptions` in `key-enroll.js` sends `userVerification: "required"` and
  no `credentialProtectionPolicy`: with verification on every get, the
  credProtect level no longer decides anything.
- `webauthnIdentify` in `ishield.js` sends `userVerification: "required"` and
  returns the UV flag, so the page can show that the PIN was entered. A key
  with a PIN is asked for it by every browser whatever the page says
  (section 2), so asking outright is only honest.
- `enrollmentWarnings` flips: a create whose authenticator data has UV
  **false** is the warning now (no PIN protects the credential).

What the September measurements already say about a PIN'd key:

- Safari (Mac, iOS) and Chrome on iOS prompt for the PIN on the empty-list
  get and complete it (section 3, "If the key has a PIN").
- Desktop Chrome prompts for the PIN on the empty-list get instead of
  refusing it: the PIN was the capability it found missing. So desktop Chrome
  can now read a key, which it could not in the PIN-less world.
- Desktop Chrome's own PIN setup on the iShield failed with CTAP `0x37`
  (`PinPolicyViolation`) for every PIN tried, `1234` included, while
  python-fido2 set a PIN on the same key without trouble. Explained on
  2026-11-01: the key's PIN rules refuse a run such as `1234` (section 8).

What has not been measured:

- **PIN setup through a browser.** Measured in Safari on a Mac on 2026-11-01
  (section 8): it works once the PIN meets the key's rules. Chrome's failed
  in September on those same rules and has not been retried. If a phone
  browser cannot set the PIN, set it once with the CLI and let the create
  merely require it:

  ```sh
  fido2-token -S <device>        # prompts for the new PIN, then confirms it
  ```

- **The PIN prompt on a phone with exactly one credential on the key**, end
  to end through the main page's setup, on iPhone and Android.
- **Desktop Chrome's discoverable create with a PIN already set** (it should
  no longer open PIN setup, and the create should complete touch-and-PIN).

Run these on the deployed origin with `fido-test.html` (set its Create
controls to Discoverable and User verification Required) before the first
real walkthrough.

## 8. The phone writes the key (2026-10-31)

The customer's flow moved the create onto the phone. The bank ships a
*blank* key; the user's phone verifies the number, enrolls the passkey, then
runs the discoverable create itself (`enrollKey` in `key-enroll.js`, now
called from `app.js`), and runs it again on a blank replacement after a
loss. The registration page is a bench tool from here on.

Two consequences for the measurements:

- **The PIN is created during the create, on the phone.** A blank key has
  no PIN and the create requires user verification, so the browser's own
  "create a PIN" step is where the user sets it, and the key enforces the
  PIN rules (the iShield's `minPINLength` is 4, section 3). The unmeasured
  item from section 7, PIN setup through a browser, is therefore the first
  thing the user sees rather than a convenience. Pre-setting the PIN with
  `fido2-token -S` would skip the step the customer asked for, so it is the
  fallback only if a phone browser cannot set one. Measure the create on a
  blank key from Safari on an iPhone and Chrome on Android with
  `fido-test.html` (Discoverable, User verification Required) on the Vercel
  origin before the walkthrough. Desktop Chrome's `0x37` in section 3 is the
  known failure of this exact step on this key.
- **The phone now holds the public key.** The create's `getPublicKey()`
  result goes into the key record (`publicKey` and `alg` in
  `key-records.js`), so a later get's signature could be verified on the
  phone. HOME does not do that yet; for the create it shows the public key
  in the USB Key block, since a create with `attestation: 'none'` signs
  nothing.

Every key this phone has recorded (active, lost or replaced) is passed as
`excludeCredentials`, so a lost key inserted at the replacement step is
refused by the key itself (`InvalidStateError`), not only by the app. For
demo resets, `fido2-token -R <device>` returns a key to blank, no
credentials and no PIN, so the next run goes through PIN creation again.

### 2026-11-01: the first run on hardware

The owner ran the main page's setup in Safari on a Mac (macOS 26.5.2) with
the iShield Key 2 Pro MIFARE inserted. Two findings.

**The key's PIN rules, not the browser, refuse a PIN.** Safari's "Set Up
Security Key" sheet, the PIN-creation step, answered "Unrecognized PIN code.
Please try again." The key's state at that moment, read over SSH with
`fido2-token -I` (libfido2 on the MacBook):

```
options: rk, noalwaysUv, credMgmt, authnrCfg, noclientPin, pinUvAuthToken, setMinPINLength, makeCredUvNotRqd
minpinlen: 4
pin protocols: 1, 2
pin retries: undefined
pin change required: false
remaining rk(s): 300
```

`noclientPin` means no PIN was set, so the only PIN command Safari could
have sent was setPIN, and the only refusal the key documents for that is its
policy. Swissbit's iShield Key 2 FAQ (v1.0, 2025-01-17) gives it: section
3.2.1, FIDO2, "PIN length: min. 4 characters (min. 6 characters for FIPS
model)"; section 3.2.5, PIN Rules, for every applet "unless otherwise
specified": at least 6 characters, a new PIN different from the current one,
no 4 identical characters (`2222as` refused, `222asd` allowed), no
sequences (`123456`, `abcdef`). The user manual (rev 1.1, 2025-05-02, page
12) repeats the rules and says the FIDO PIN set through Windows is "between
four and eight characters". The browser checks only `minPINLength`, 4, and
passes the PIN on; the key answers `0x37`, CTAP `PIN_POLICY_VIOLATION`,
which is the code desktop Chrome logged in September for `1234`. Apple's
sheet renders that as "Unrecognized PIN code". The owner retried with a PIN
that met the rules and the create completed: the key was encoded from the
main page, with the PIN created in Safari's sheet. A refused attempt costs
nothing: with no PIN set there is no retry counter. The guides and the
encode flash in `app.js` now state the two rules the sheet cannot.

**The empty-list get opens Safari's passkey chooser.** Verify USB key put
the device biometric first, since an empty `allowCredentials` is the
"who are you" query and Safari offers every passkey it has for the site,
the Ideem passkey included, with security keys behind it. `hints:
["security-key"]` did nothing: WebKit's Safari 18.4 notes list PIN setup for
security keys, not hints, and Chrome 128+ is where hints are honoured. The
lever that works everywhere is the allow list: `webauthnIdentify` now takes
`allowIds`, the ids this phone has recorded (`allowListFor`: each on
`transports: ["usb", "nfc"]`, deduplicated, capped at 64), and a get whose
allowed credentials all live on a security key goes straight to the
security-key sheet. Lost and replaced keys are listed too, so a lost key
still signs and the app's refusal, with its date, is what the user sees.
With no records the list is empty and the open get stays, for a phone
adopting a key it did not encode. What to measure next, on the Mac and
then on the phones: that the allow-listed get opens the security-key sheet,
and that the user handle still comes back (CTAP 2.1 makes at least the user
id mandatory in a discoverable credential's assertion; if a browser drops it
with an allow list, `verifyUsbKey` falls back to the handle recorded for the
matched credential).
