/**
 * api/exchange.js -- P2P Contact Exchange matchmaker
 *
 * Pairs two logged-in attendees. The initiator (A) taps "P2P Contact
 * Exchange", passes the ZSM step-up, and the page POSTs A's User ID here. A
 * record is stored under a fresh code, and A's page shows that code as a QR
 * and polls it. The responder (B) scans the QR, is asked to confirm sharing,
 * verifies with their passkey (the demo's own login), and B's page POSTs B's
 * User ID with the code. Both pages then show the other person's name and
 * phone. The completed exchange is also written to the user API's exchanges
 * table (POST /exchanges, added by the owner on 2026-10-14; docs/user-api.md
 * §3c), one row in each direction, so each attendee gains the other as a
 * contact there and the pages can list those contacts. The record's
 * `upstream` field says whether that landed; the exchange itself goes
 * through either way.
 *
 * The server never sees a ZSM token: the SDK's validate-token call has a
 * window of a few seconds and stays inside umfa.js, exactly as for login. So
 * this function trusts the User ID it is sent. That is deliberate for a
 * conference demo, and it is the same trust the user API itself extends to
 * every caller. What it does NOT trust is the contact details: those are
 * read from the user database by phone number, never taken from the browser.
 *
 * ROUTES (one flat file, like api/db.js -- a catch-all route matched a single
 * segment on Vercel):
 *   POST /api/exchange              { userId }   -> 201 record   create
 *   GET  /api/exchange?code=XXXX                 -> 200 record   status (poll)
 *   POST /api/exchange?code=XXXX    { userId }   -> 200 record   complete
 *   GET  /api/exchange                           -> 200 health   which store, which env names
 *
 * Status codes the page branches on: 404 no such code (never issued or
 * expired), 409 the code was already completed by someone else.
 *
 * STORE: Redis over Upstash's REST API when the Vercel Marketplace integration
 * has injected its URL and token, otherwise a process-local Map. The Map is
 * what dev-server.mjs runs on (one process, so it is exact). On Vercel it is
 * only a fallback: A's poll and B's completion can land on different function
 * instances, so every response carries `store` and the page warns when it
 * reads "memory" off localhost.
 *
 * Records expire on a TTL (default 10 minutes) and nothing else removes them.
 */

/** Upstream user API, the same one api/db.js proxies. */
const DB_API = process.env.DB_API || 'https://sbit.authconcepts.com:3033/api';

/** How long a code stays valid, in seconds. */
const TTL_SECONDS = Number(process.env.EXCHANGE_TTL_SECONDS) || 600;

/** After completion the record only has to outlive A's next poll. */
const MIN_TTL_AFTER_COMPLETION = 60;

/** How long one call to the user API may take; a completion makes three. */
const UPSTREAM_TIMEOUT_MS = 4000;

/** Unambiguous characters, in case a code is ever read out loud. */
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const CODE_LENGTH = 8;

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/**
 * Finds the Upstash REST credentials in the environment. Both naming schemes
 * are accepted: the Upstash integration on the Vercel Marketplace injects
 * KV_REST_API_URL / KV_REST_API_TOKEN, and a store created on upstash.com
 * directly documents UPSTASH_REDIS_REST_URL / _TOKEN. A Custom Prefix set when
 * connecting the Vercel resource prepends `PREFIX_` to both names, so a suffix
 * match is accepted too. Returns null when nothing usable is set.
 */
function redisCredentials(env = process.env) {
  const names = Object.keys(env);
  for (const base of ['KV_REST_API_URL', 'UPSTASH_REDIS_REST_URL']) {
    const urlKey = names.includes(base) ? base : names.find(name => name.endsWith(`_${base}`));
    if (!urlKey) continue;
    const tokenKey = urlKey.slice(0, -'URL'.length) + 'TOKEN';
    if (env[urlKey] && env[tokenKey]) return { url: env[urlKey], token: env[tokenKey], urlKey };
  }
  return null;
}

/** Names, never values, of the Redis-looking variables, for the health check. */
function redisEnvNames(env = process.env) {
  return Object.keys(env).filter(name => /KV|REDIS|UPSTASH/i.test(name)).sort();
}

const REDIS = redisCredentials();

/**
 * A key-value store with expiry. Values are strings.
 *   get(key)                      -> string | null
 *   set(key, value, ttlSeconds)   -> void
 *   setIfAbsent(key, value, ttl)  -> true when written, false when the key existed
 */
function memoryStore() {
  const entries = new Map();   // key -> { value, expiresAt }
  const live = (key) => {
    const entry = entries.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= Date.now()) {
      entries.delete(key);
      return null;
    }
    return entry;
  };
  return {
    kind: 'memory',
    async get(key) {
      return live(key)?.value ?? null;
    },
    async set(key, value, ttlSeconds) {
      entries.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
    },
    async setIfAbsent(key, value, ttlSeconds) {
      if (live(key)) return false;
      entries.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
      return true;
    }
  };
}

/**
 * Upstash's REST API takes a Redis command as a JSON array in a POST body
 * and answers { result } or { error }. SET with NX answers null when the
 * key already exists, which is the atomic claim that makes a code single-use.
 */
function redisStore(url, token) {
  async function command(...args) {
    const res = await fetch(url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(args)
    });
    const body = await res.json();
    if (!res.ok || body.error) throw new Error(body.error || `Redis returned ${res.status}`);
    return body.result;
  }
  return {
    kind: 'redis',
    get: (key) => command('GET', key),
    set: async (key, value, ttlSeconds) => { await command('SET', key, value, 'EX', String(ttlSeconds)); },
    setIfAbsent: async (key, value, ttlSeconds) =>
      (await command('SET', key, value, 'EX', String(ttlSeconds), 'NX')) === 'OK'
  };
}

const store = REDIS ? redisStore(REDIS.url, REDIS.token) : memoryStore();

const recordKey = (code) => `exchange:${code}`;
const claimKey = (code) => `exchange:${code}:claim`;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const code = cleanCode(url.searchParams.get('code'));

    try {
      if (request.method === 'GET') {
        return code ? await status(code) : health();
      }
      if (request.method === 'POST') {
        const body = await readJson(request);
        if (!body) return json({ error: 'Body must be JSON' }, 400);
        const userId = cleanUserId(body.userId);
        if (!userId) return json({ error: 'userId is required' }, 400);
        return code ? await complete(code, userId) : await create(userId);
      }
      return json({ error: `Method ${request.method} is not supported` }, 405);
    } catch (err) {
      return json({ error: 'Exchange failed', detail: err.message }, 500);
    }
  }
};

/** Issues a code for the initiator and stores the open record under it. */
async function create(userId) {
  const initiator = await lookupContact(userId);
  const now = Date.now();
  const record = {
    code: null,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + TTL_SECONDS * 1000).toISOString(),
    initiator,
    responder: null,
    completedAt: null,
    upstream: null
  };
  // A collision on 40 random bits is not expected; the loop is only so a
  // collision would never silently overwrite someone's open exchange.
  for (let attempt = 0; attempt < 5; attempt++) {
    record.code = randomCode();
    if (await store.setIfAbsent(recordKey(record.code), JSON.stringify(record), TTL_SECONDS)) {
      return json(withStore(record), 201);
    }
  }
  return json({ error: 'Could not allocate a code' }, 500);
}

/** What A's page polls. 404 once the record has expired. */
async function status(code) {
  const raw = await store.get(recordKey(code));
  if (!raw) return json({ error: 'No open exchange for that code', code }, 404);
  return json(withStore(JSON.parse(raw)));
}

/**
 * Fills in the responder. The claim key is written with NX first, so two
 * phones completing the same code at once cannot both win.
 */
async function complete(code, userId) {
  const raw = await store.get(recordKey(code));
  if (!raw) return json({ error: 'No open exchange for that code', code }, 404);
  const record = JSON.parse(raw);
  if (record.responder) return json({ error: 'This code was already used', ...withStore(record) }, 409);

  const remaining = Math.max(
    MIN_TTL_AFTER_COMPLETION,
    Math.ceil((Date.parse(record.expiresAt) - Date.now()) / 1000)
  );
  if (!(await store.setIfAbsent(claimKey(code), userId, remaining))) {
    return json({ error: 'This code was already used', code }, 409);
  }

  record.responder = await lookupContact(userId);
  record.completedAt = new Date().toISOString();
  record.upstream = await recordExchange(record.initiator, record.responder);
  await store.set(recordKey(code), JSON.stringify(record), remaining);
  return json(withStore(record));
}

// ---------------------------------------------------------------------------
// Contact lookup
// ---------------------------------------------------------------------------

/**
 * Reads the attendee's record from the user database by bare-digit phone,
 * the way app.js and register.js key every record. A User ID that is not a
 * phone number, a number with no record, or a database that is down all
 * give a contact with found:false, so the exchange still goes through and
 * the pages show the User ID alone. Only the four fields the by-phone read
 * returns are kept, plus the record's integer id as `recordId`, which the
 * exchanges route and the contacts route are keyed by; Company and email
 * exist solely on the badge-number route (docs/user-api.md).
 */
async function lookupContact(userId) {
  const contact = { userId, recordId: null, found: false, firstName: '', lastName: '', phone: '', photo: null };
  const digits = phoneDigits(userId);
  if (!digits) return contact;
  try {
    const res = await dbFetch(`/users/phone/${encodeURIComponent(digits)}`);
    if (res.status === 404) return contact;
    if (!res.ok) throw new Error(`user lookup returned ${res.status}`);
    const body = await res.json();
    const record = Array.isArray(body) ? body[0] : body;
    if (!record) return contact;
    return {
      ...contact,
      recordId: Number.isInteger(record.userId) ? record.userId : null,
      found: true,
      firstName: String(record.firstName ?? ''),
      lastName: String(record.lastName ?? ''),
      phone: String(record.phone ?? digits),
      photo: typeof record.photo === 'string' ? record.photo : null
    };
  } catch (err) {
    console.warn(`[exchange] contact lookup for ${userId} failed: ${err.message}`);
    return contact;
  }
}

/** The same rule as phoneDigits in app.js and normalizePhone in register.js. */
function phoneDigits(value) {
  const digits = String(value).replace(/\D/g, '');
  return digits.length === 11 && digits.startsWith('1') ? digits.slice(1) : digits;
}

// ---------------------------------------------------------------------------
// Upstream record
// ---------------------------------------------------------------------------

/**
 * Writes the completed exchange to the user API. Its exchanges are
 * one-directional (POST /exchanges { senderId, receiverId }: the receiver
 * gains the sender as a contact, the sender gains nothing) and the demo's
 * exchange is mutual, so two rows go up, one each way. By record id, because
 * the by-phone form of the route matches the stored string exactly and the
 * by-badge form needs numbers the API never stores for records we create
 * (docs/user-api.md §3c). A side with no record, a refused POST, or a
 * database that does not answer in time all give { saved: false } with a
 * reason; the exchange itself has already gone through, as it did before the
 * route existed. The two POSTs run together and `exchangeIds` lists
 * whichever landed. Nothing retries: the API has no idempotency key and a
 * repeat is a new row.
 *
 * @returns {Promise<{ saved: boolean, exchangeIds: number[], reason: string }>}
 */
async function recordExchange(initiator, responder) {
  const missing = [initiator, responder].filter(c => !c.found || !Number.isInteger(c.recordId));
  if (missing.length) {
    return {
      saved: false,
      exchangeIds: [],
      reason: `${missing.map(c => c.userId).join(' and ')} ${missing.length > 1 ? 'have' : 'has'} no record in the user database`
    };
  }
  const directions = [[initiator, responder], [responder, initiator]];
  const results = await Promise.allSettled(
    directions.map(([sender, receiver]) => postExchange(sender.recordId, receiver.recordId))
  );
  const exchangeIds = results.filter(r => r.status === 'fulfilled').map(r => r.value);
  const reasons = results.filter(r => r.status === 'rejected').map(r => r.reason?.message || String(r.reason));
  if (reasons.length) console.warn(`[exchange] upstream record failed: ${reasons.join('; ')}`);
  return { saved: reasons.length === 0, exchangeIds, reason: reasons.join('; ') };
}

/** One POST /exchanges: resolves to the new exchangeId, rejects with the API's error text. */
async function postExchange(senderId, receiverId) {
  const res = await dbFetch('/exchanges', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ senderId, receiverId })
  });
  let body = {};
  try { body = await res.json(); } catch (_) { /* no JSON body */ }
  if (!res.ok) throw new Error(body.error || `exchange POST returned ${res.status}`);
  return body.exchangeId;
}

/** fetch against the user API with a timeout, so a stalled upstream cannot hold a completion. */
function dbFetch(path, init = {}) {
  return fetch(DB_API + path, { ...init, signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS) });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function randomCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(CODE_LENGTH));
  return Array.from(bytes, (b) => CODE_ALPHABET[b % CODE_ALPHABET.length]).join('');
}

/** Codes are case-insensitive and only ever contain the alphabet above. */
function cleanCode(value) {
  const code = String(value ?? '').trim().toUpperCase();
  return /^[A-Z2-9]{1,32}$/.test(code) ? code : '';
}

/** User IDs are what the page holds in STATE.loginID: lower-cased, trimmed. */
function cleanUserId(value) {
  if (typeof value !== 'string') return '';
  return value.trim().toLowerCase().slice(0, 128);
}

async function readJson(request) {
  try {
    const body = await request.json();
    return body && typeof body === 'object' ? body : null;
  } catch (_) {
    return null;
  }
}

function withStore(record) {
  return { ...record, store: store.kind };
}

/**
 * GET without a code. Says which store this deployment runs on, which
 * variable supplied the Redis URL, and the names of every Redis-looking
 * variable it can see, so a mis-wired Vercel connection can be diagnosed from
 * a browser without exposing any value.
 */
function health() {
  return json({
    ok: true,
    store: store.kind,
    redisVar: REDIS ? REDIS.urlKey : null,
    redisEnv: redisEnvNames(),
    ttlSeconds: TTL_SECONDS
  });
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
  });
}
