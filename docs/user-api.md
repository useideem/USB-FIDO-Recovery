# The Ideem user API

The demo's user records live in an Express service at
`https://sbit.authconcepts.com:3033/api`, database `Authenticate2026`. The
enrollment page writes to it; the retrieval side reads from it, keyed by the
phone number the iShield Key hands back.

Everything below was measured against the live service (2026-09-22, 2026-10-02,
2026-10-09 and, for the create route's new fields, 2026-10-14) unless a line
says otherwise. The Postman collection the API's
owner shared is beside this file as `IdeemAPI.postman_collection.json`; it is
the list of the 15 routes, but it carries no saved responses and no bodies for
its PUT requests, so it says what exists, not how it behaves.

---

## 1. The record

```json
{
  "userId": 1,
  "firstName": "Chris",
  "lastName": "Test",
  "phone": "512-555-1234",
  "balance": 1250.5,
  "photo": null,
  "customAttrib": "Demo user"
}
```

`userId` is assigned by the server; a create body leaves it out. `photo` has
been null in every record so far, so its format is still unknown.

A read **by confirmation number** (§3b) returns three more fields: `Company`
(capital C), `email` and `confNumber`. So do the bodies that POST, PUT, PATCH
and DELETE echo back. The list, by-id and by-phone reads return only the seven
above, so the shape of "a user" depends on which route handed it to you. None
of the three can be set through the API: every write route accepts them in a
body and stores nothing (§3b).

## 2. Endpoints

| Method | Path | Answers with |
|---|---|---|
| GET | `/health` | `{"status":"OK","database":"Authenticate2026"}` |
| POST | `/users` | **201** and the created record, `userId` included |
| GET | `/users` | array of every record |
| GET | `/users/:id` | a single **object** |
| GET | `/users/phone/:phone` | an **array**, one element per match |
| PUT | `/users/:id`, `/users/phone/:phone` | 200 and the updated record |
| DELETE | `/users/:id`, `/users/phone/:phone` | `{"message":"User deleted","user":{…}}` |
| PATCH | `/users/:id/balance`, `/users/phone/:phone/balance` | `{"message":"Balance updated","user":{…}}`; the body needs `partner` as well as `amount` since 2026-10-16 -- see §3a |
| GET | `/users/conf/:confNumber` | a single **object**, with `confNumber`, `Company` and `email` added -- see §3b |
| PUT | `/users/conf/:confNumber` | updates a record that already has that number; **404** otherwise -- an update, not a create, see §3b |
| DELETE | `/users/conf/:confNumber` | 404 when no record has that number; the success shape was not observed -- see §3b |
| PATCH | `/users/conf/:confNumber/balance` | `{"message":"Balance updated","user":{…}}`, the same additive `{"amount": …}` body as §3a -- see §3b |
| POST | `/exchanges` | **201** `{"exchangeId","senderId","receiverId","exchangedAt"}` -- see §3c |
| GET | `/users/id/:id/contacts`, `/users/phone/:phone/contacts`, `/users/:confNumber/contacts` | `{"limit","offset","contacts":[…]}` -- see §3c |
| GET | `/users/id/:id/exchanges`, `/users/phone/:phone/exchanges`, `/users/:confNumber/exchanges` | `{"limit","offset","exchanges":[…]}` -- see §3c |

A missing record gives `404 {"error":"User not found"}`. An unknown route
gives Express's HTML error page, not JSON.

Note the shape difference: a by-id read returns an object, a by-phone read
returns an array. Code that handles both has to unwrap.

## 3. Four behaviours worth knowing

**Phone lookup is an exact string match.** `/users/phone/512-555-1234` finds
the seeded record; `/users/phone/5125551234` returns 404. There is no
normalisation on the server, so the whole demo has to agree on one spelling.
**Ours is bare digits** -- on the key, in the database, and in the lookup.
Format for display only.

**PUT replaces, it does not merge.** A body of `{"firstName":"Renamed"}`
against an existing user returns `500 {"error":"Failed to update user"}` and
changes nothing. Send every field.

**Phone numbers are not unique.** Two POSTs with the same number produce two
records with different `userId`s. Nothing on the server prevents it, so
`saveAttendee` in `register.js` looks the number up first and PUTs when it already exists.

**There is no authentication.** No key, no token, no session. Anyone who knows
the URL can read, edit and delete every record, `balance` included. Fine for a
booth demo with invented data; do not put anything real in it.

## 3a. The balance endpoint

`PATCH /users/:id/balance` or `/users/phone/:phone/balance` with a body of
`{"amount": 500.00}`. Measured on 2026-10-02 against a throwaway record that
started at 1000:

| Sent | Result |
|---|---|
| `500.00` by id | 200, balance **1500** -- the amount is **added** |
| `-200` by phone | 200, balance 1300 -- a negative amount subtracts |
| `12.345` | 200, balance 1312.35 -- the result is rounded to cents |
| `"50"` (a string) | 200, balance 1362.35 -- numeric strings are accepted |
| `0` | 200, balance unchanged |
| body `{}` | **400** `{"error":"A valid numeric amount is required"}` |
| `-999999` | 200, balance **-998636.65** -- nothing stops an overdraft |
| unknown id or phone | 404 `{"error":"User not found"}` |

So it is a ledger adjustment, not a setter: to charge somebody, send a negative
amount; to set an exact balance, use PUT with the full record (§3). Two
consequences for the demo:

- **The page has to refuse an overdraft itself.** The API will happily take a
  balance below zero, so if a payment must fail when funds are short, check the
  balance first and decide on the client side.
- **A retried request applies twice.** Each PATCH adds again, and there is no
  idempotency key, so a timeout followed by a retry can charge twice. Do not
  auto-retry a PATCH; re-read the balance instead.

The by-phone form is subject to the same exact-string match as every other
phone route, and with duplicate phone numbers possible (§3) it is not clear
which record a by-phone PATCH adjusts. Prefer the by-id form once the user has
been looked up.

**The `partner` attribute (measured 2026-10-16).** The owner added a
`partner` string to the body of every balance PATCH, naming who credits or
debits: `{"amount": 100, "partner": "IDEEM"}` is the owner's example.
Measured against a throwaway record (`userId` 240, created at 0):

| Sent | Result |
|---|---|
| `{"amount":100,"partner":"IDEEM"}` by id | 200, balance 100 -- the reply is the usual `{"message","user"}`, with no `partner` in it |
| `"partner":"Swissbit"`, `"ICE CREAM"`, `"zzz-probe-unknown"` | 200 each -- free text: any case, spaces, and names the owner never heard of |
| `"partner":""`, `123`, `null`, or no `partner` at all | **400** `{"error":"partner must be a nonblank string of at most 100 characters"}` |
| `{"amount":-5,"partner":"RSA"}` by phone | 200, balance 115 -> 110 -- debits take it too |
| `PATCH /users/conf/THROWAWAYPT/balance` with a partner | 404 -- the throwaway has no number (§3b); the by-badge form was not measured with a partner |
| `GET /users/240`, `GET /users/phone/9995550003` | the usual seven fields, nothing about partners |
| `GET /users/id/240/transactions`, `…/ledger`, `…/balance`, `…/credits`, `…/points`, `…/history`, `/transactions`, `/ledger`, `/partners`, `/balances` | 404 (Express's HTML page) -- no read of the ledger was found |
| `DELETE /users/240`, `DELETE /users/phone/9995550003` | **500** `{"error":"Failed to delete user"}` -- after its balance moves the record could not be deleted, like a user with an exchange row (§3c); it is still there |

So the attribute is **required**: a PATCH without it is refused, which is
what every balance move in this repo sent until 2026-10-16. `adjustBalance`
in `app.js` and `partner.js` takes a `partner` since then and every caller
passes one: `IDEEM` for the demo page's Authenticate credit
(`CREDIT_PARTNER`), and the booth's `apiName` from `PARTNERS` (`RSA`,
`SWISSBIT`, `HID`, `ICE CREAM`, `POPCORN`, `OXYGEN`) on the partner page.
The server keeps the string as sent, so spelling is the only grouping the
owner's reports will have; the upper-case names follow the owner's example.
Nothing we can read returns it.

## 3b. Confirmation-number routes

Added by the API's owner in early October 2026 for attendees who opt in and
present a badge: the badge's confirmation number becomes a second key for the
record, beside the phone number. Four routes, all under `/users/conf/`.

**Measured on 2026-10-09.** Reads against the owner's test user; writes
against throwaway records created and deleted in the same run (`userId` 196
and 197, both gone), plus a net-zero balance adjustment on the test user,
which the owner's email gave as the example for that route.

| Request | Result |
|---|---|
| `GET /users/conf/KVNLHY66K2P` | 200, a single **object** (not an array, unlike by-phone) |
| `GET /users/conf/kvnlhy66k2p` | 200, the **same record** -- the lookup is **case-insensitive**, unlike the exact-string phone routes |
| `GET /users/conf/ZZZNOTREAL000` | 404 `{"error":"User not found"}` |
| `GET /users` | 190 records, **none** carrying `confNumber`, `Company` or `email` |
| `POST /users` with `confNumber`, `Company`, `email` in the body | 201, but all three come back **`null`** -- the fields are ignored (**changed 2026-10-14**: `Company` and `email` are now stored, `confNumber` still is not; see below) |
| `PUT /users/:id` and `PUT /users/phone/:phone` with the three fields | 200, all three still **`null`** -- ignored here too |
| `PUT /users/conf/CLAUDEDOCTEST1` (no record has that number), full body | **404** `{"error":"User not found"}` -- it does not create |
| `PUT /users/conf/CLAUDEDOCTEST1`, no body | 500 `{"error":"Failed to update user"}` |
| `PATCH /users/conf/KVNLHY66K2P/balance` `{"amount":5}` | 200, balance 4650 -> 4655 -- **additive**, as §3a |
| `PATCH /users/conf/kvnlhy66k2p/balance` `{"amount":-5}` | 200, balance back to 4650 -- lowercase works on writes too |
| `PATCH /users/conf/CLAUDEDOCTEST1/balance` `{}` | 400 `{"error":"A valid numeric amount is required"}` -- the body is checked before the lookup |
| `PATCH /users/conf/CLAUDEDOCTEST1/balance` `{"amount":5}` | 404 |
| `DELETE /users/conf/CLAUDEDOCTEST1` | 404 |

The by-confirmation record looks like this:

```json
{
  "userId": 1,
  "firstName": "Chris",
  "lastName": "Test",
  "phone": "512-555-1234",
  "balance": 4650,
  "photo": null,
  "customAttrib": "Demo user",
  "Company": null,
  "email": null,
  "confNumber": "KVNLHY66K2P"
}
```

What this adds up to:

- **The API cannot assign a confirmation number.** No write route stores
  `confNumber`; it is echoed back as `null` whatever the body says. A record
  gets its number out of band, on the owner's side, so a confirmation number
  is something to *look up*, never something the booth or the demo can
  create. "Create User by Confirmation Number" in the collection is a
  misnomer: the PUT updates a record that already has the number and 404s
  otherwise.
- **`POST /users` stores `Company` and `email` since 2026-10-14; nothing else
  does, and no read returns them.** Measured that day, after the owner said
  the create had been updated to take both, with a throwaway record (`userId`
  223, deleted in the same run). The POST answered 201 with
  `"Company":"Probe Co","email":"probe0077@example.com","confNumber":null`.
  `PUT /users/:id` with new values for both answered 200 but echoed the
  *stored* values, so the PUT ignores them, as it still ignores `confNumber`.
  The list, by-id and by-phone reads still omit all three, and the read by
  confirmation number 404s because the number was never stored. The two
  fields come back only in write responses: the POST, the PUT, and the
  `user` inside the DELETE reply. So a registration's email and company are
  kept, but nothing we can call reads them back. Until 2026-10-14 the POST
  dropped them too, as the 2026-10-09 table above records.
- **Nothing lists them.** The list, by-id and by-phone reads omit the field,
  so there is no way to enumerate which users have a number; the only way to
  resolve one is to ask for it.
- **Reads and writes by number are case-insensitive**, unlike the exact-string
  phone routes, so there is no spelling to agree on.
- **The balance PATCH is the same ledger adjustment as §3a**: additive,
  rounds to cents, no overdraft check, no idempotency key. Everything in §3a
  about refusing overdrafts client-side and never auto-retrying applies.
- **Still not observed:** a successful `PUT` or `DELETE` by confirmation
  number. Both need a record that already carries a number, and the only one
  we know of is the owner's test user, which is not ours to replace or delete.
  Expect the by-id shapes (200 and the full record; `{"message":"User
  deleted","user":{…}}`), and expect the PUT to replace rather than merge
  like every other PUT here.

The owner's test user `KVNLHY66K2P` (`userId` 1) is to be read and, at most,
balance-adjusted back to where it started -- never replaced, never deleted.

## 3c. Exchanges and contacts

Added by the API's owner on 2026-10-14 for the P2P Contact Exchange and
delivered as a second Postman collection,
`docs/IdeemP2P.postman_collection.json` (seven requests, no responses). An
exchange is a row `{ exchangeId, senderId, receiverId, exchangedAt }`; a
user's contacts are the senders of the exchanges they received, one entry per
sender. The user CRUD and balance routes are untouched.

**Measured on 2026-10-14.** Reads against the owner's test user (`userId` 1)
and `userId` 5; writes between two throwaway records, `userId` 231 and 232
(phones 9995550001 and 9995550002), which turned out to be undeletable once
they had exchanges (below) and are still in the database.

| Request | Result |
|---|---|
| `POST /exchanges` `{"senderId":231,"receiverId":232}` | **201** `{"exchangeId":7,"senderId":231,"receiverId":232,"exchangedAt":"2026-10-14T21:23:14.777Z"}` |
| the same again | 201, `exchangeId` 8 -- **duplicates are allowed**, a new row each time |
| `{"senderId":"231","receiverId":"232"}` (strings) | 400 -- the ids must be JSON integers |
| `{"senderPhone":"9995550001","receiverPhone":"9995550002"}` | 201, `exchangeId` 9, the same `senderId`/`receiverId` as by id |
| `{"senderPhone":"999-555-0001",…}` (formatted; the record holds bare digits) | 404 `{"error":"Sender not found"}` -- **exact-string phone matching**, as §3 |
| `{"senderConfNumber":"THROWAWAYXA","receiverConfNumber":"throwawayxb"}` | 404 `{"error":"Sender not found"}` -- the throwaways' numbers were never stored (§3b), so by badge works only for records the owner numbered |
| `{"senderId":231,"receiverId":231}` | 400 `{"error":"Self-exchanges are not allowed"}` |
| `{"senderId":231,"receiverId":999999}` | 404 `{"error":"Receiver not found"}` |
| `{}`, `{"senderId":231}`, `{"senderId":231,"receiverPhone":"…"}` | 400 `{"error":"Supply one complete pair: senderId/receiverId (JSON integers 1–2147483647), senderConfNumber/receiverConfNumber (1–100 non-whitespace characters), or senderPhone/receiverPhone (phone strings up to 50 characters). Do not mix formats or add fields."}` |
| `GET /users/id/232/contacts` (the receiver) | 200 `{"limit":50,"offset":0,"contacts":[{"userId":231,"firstName":"Throwaway","lastName":"ExchA","phone":"9995550001","Company":"Probe","email":"a@probe.invalid","lastExchangedAt":"2026-10-14T21:23:15.225Z"}]}` -- **one entry for the sender after three exchanges**, carrying the latest time |
| `GET /users/id/231/contacts` (the sender) | 200, `"contacts":[]` -- **one-directional**: sending adds nothing to the sender's list |
| `GET /users/id/231/exchanges` | 200, three rows, newest first, each with `"direction":"sent"` |
| `GET /users/id/232/exchanges` | 200, the same three rows with `"direction":"received"` |
| `GET /users/phone/9135551111/contacts`, `/users/phone/9135551111/exchanges` | 200, the by-phone form, exact string as everywhere |
| `GET /users/KVNLHY66K2P/exchanges`, `/users/kvnlhy66k2p/exchanges` | 200, the by-badge form, **no `conf/` segment** and case-insensitive; `/users/conf/KVNLHY66K2P/contacts` is Express's HTML 404 |
| `GET /users/1/contacts` | 404 `{"error":"User not found"}` -- a bare number after `/users/` is read as a confirmation number here; the by-id form is `/users/id/1/contacts` |
| `GET /users/id/5/contacts?limit=1000` | 400 `{"error":"limit must be 1–100; offset must be 0–2147483647"}`; `?limit=2&offset=1` pages as expected, the default is 50 |
| `GET /users/id/999/contacts`, `/users/NOPE/exchanges` | 404 `{"error":"User not found"}` |
| `GET /exchanges`, `GET /exchanges/6` | Express's HTML 404 -- no list, no single-row read |
| `DELETE /users/231`, `DELETE /users/phone/9995550001` | **500** `{"error":"Failed to delete user"}` -- **a user with an exchange row cannot be deleted**, by either route |

What this adds up to:

- **Record it by id.** The by-id form is the only one that cannot miss: the
  by-phone form matches the stored string exactly (the owner's test user
  holds `512-555-1234` while every record the booth writes holds bare
  digits), and the by-badge form needs a number the API never stores for
  records we create. The demo's `api/exchange.js` reads both records by
  bare-digit phone and posts `{ senderId, receiverId }` with their
  `userId`s.
- **Contacts are one-directional, and the demo's exchange is not.** The
  receiver gains the sender; the sender gains nothing. Both phones in the
  demo show the other person, so `api/exchange.js` posts two rows per
  completed exchange, one each way, and each side's contact list gets the
  other. Dropping to one row is one line there.
- **Contacts carry `Company` and `email`**, which no user read other than
  the by-badge one returns (§3b), and `lastExchangedAt`. Repeats collapse
  into the one entry; the exchanges list keeps every row.
- **Exchanges make a user undeletable.** Both DELETE routes answer 500 once a
  record is a sender or receiver. This is why `userId` 5 (the live
  registration of 2026-10-12, which the owner has been exchanging with since
  that day) would not delete, and why the two throwaways from this run are
  still there: the owner has to remove the rows first. Create throwaway users
  for exchange tests expecting to leave them behind. Since 2026-10-16 a
  balance PATCH has the same effect (§3a, `userId` 240), so a throwaway for
  a balance test stays too.
- **No idempotency and no way back.** A repeated POST is a new row, nothing
  deletes an exchange, and there is no read of a single one.
  `api/exchange.js` posts once per completion, inside the claim that
  already makes a code single-use, and never retries.

## 4. CORS, and why the proxy exists

The service sends **no `Access-Control-Allow-Origin` header**, on any method.
A preflight `OPTIONS` returns Express's default `Allow: GET, HEAD, POST` with
no CORS headers at all. So a browser will not let our pages call it directly,
whatever origin they are served from.

Rather than ask for a server change -- which would also need an allow-list
covering localhost, a tunnel hostname that changes every run, the Vercel
domain and any future custom domain -- the site proxies the API from its own
origin. Pages fetch the relative path `./db/...` and the same code works
everywhere:

| Where | What forwards `/db/*` |
|---|---|
| Local | `dev-server.mjs`, in `handleDb` |
| Vercel | `api/db.js`, reached by the rewrite in `vercel.json` |

Both take `DB_API` from the environment to point somewhere else.

**A catch-all function file does not work here.** The first attempt put the
proxy in `api/db/[...path].js`, and on a real deployment that matched exactly
one path segment: `/api/db/users` answered, `/api/db/users/9999` and
`/api/db/users/phone/…` returned Vercel's own `NOT_FOUND` page rather than the
upstream's 404. The fix is a flat `api/db.js` with nothing dynamic in the
name, and a rewrite that hands the rest of the path over as a query
parameter:

```json
{ "source": "/db/:path*", "destination": "/api/db?path=:path*" }
```

The function reads the path from `?path=` and falls back to the pathname, so
it behaves the same when called directly.

**The function's source is readable.** Because `outputDirectory` is `.`, the
whole repository is the static root, so `/api/db.js` serves its own source
over HTTP. Nothing in it is secret -- the upstream URL is in the Postman
collection anyway and there are no credentials anywhere in this repo -- but it
is worth knowing before anything sensitive goes in that file.

A plain Vercel rewrite straight to the upstream was the obvious alternative and
was deliberately not used: external rewrite destinations are documented, but
Vercel documents nothing about a **non-standard port** such as `:3033` in a
destination. It passes schema validation and survives the build-time
transform, so it would not fail at build -- it would fail silently at runtime
if the edge proxy declines the port. A server-side `fetch` has no such
ambiguity.

## 5. Commands

```sh
curl -s https://sbit.authconcepts.com:3033/api/health
curl -s https://sbit.authconcepts.com:3033/api/users/conf/KVNLHY66K2P   # the owner's test user
curl -s https://sbit.authconcepts.com:3033/api/users/id/1/contacts     # the test user's contacts (§3c)
curl -s http://localhost:8080/db/users                  # through the local proxy
curl -s https://authenticate26.vercel.app/db/users      # through the Vercel proxy
```
