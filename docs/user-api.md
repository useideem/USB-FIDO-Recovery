# The Ideem user API

The demo's user records live in an Express service at
`https://sbit.authconcepts.com:3033/api`, database `Authenticate2026`. The
enrollment page writes to it; the retrieval side reads from it, keyed by the
phone number the iShield Key hands back.

Everything below was measured against the live service (2026-09-22, 2026-10-02
and 2026-10-09) unless a line says otherwise. The Postman collection the API's
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
| PATCH | `/users/:id/balance`, `/users/phone/:phone/balance` | `{"message":"Balance updated","user":{…}}` -- see §3a |
| GET | `/users/conf/:confNumber` | a single **object**, with `confNumber`, `Company` and `email` added -- see §3b |
| PUT | `/users/conf/:confNumber` | updates a record that already has that number; **404** otherwise -- an update, not a create, see §3b |
| DELETE | `/users/conf/:confNumber` | 404 when no record has that number; the success shape was not observed -- see §3b |
| PATCH | `/users/conf/:confNumber/balance` | `{"message":"Balance updated","user":{…}}`, the same additive `{"amount": …}` body as §3a -- see §3b |

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
| `POST /users` with `confNumber`, `Company`, `email` in the body | 201, but all three come back **`null`** -- the fields are ignored |
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
  `confNumber`, `Company` or `email`; they are echoed back as `null` whatever
  the body says. A record gets its number out of band, on the owner's side,
  so a confirmation number is something to *look up*, never something the
  booth or the demo can create. "Create User by Confirmation Number" in the
  collection is a misnomer: the PUT updates a record that already has the
  number and 404s otherwise.
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
curl -s http://localhost:8080/db/users                  # through the local proxy
curl -s https://authenticate26.vercel.app/db/users      # through the Vercel proxy
```
