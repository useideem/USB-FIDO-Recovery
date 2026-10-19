/**
 * api/db.js -- Server-side proxy to the Ideem user API
 *
 * The user API at sbit.authconcepts.com:3033 sends no CORS headers, so a
 * browser refuses to let our pages call it. This function forwards
 * /db/<anything> to it from the server, where the same-origin rule does not
 * apply, and hands the answer back unchanged, with one exception, the phone
 * lookup matched on digits (below). dev-server.mjs does exactly the
 * same for local testing, so pages fetch the relative path ./db/... and work
 * on localhost, through a tunnel, and on Vercel without a change.
 *
 * WHY A FUNCTION AND NOT A PLAIN REWRITE: Vercel documents rewrites to
 * external origins, but says nothing about a non-standard port in the
 * destination. A port is fine for a server-side fetch, so this route leaves
 * nothing undocumented in the path.
 *
 * WHY ONE FLAT FILE AND NOT api/db/[...path].js: measured on a deployment,
 * the catch-all matched a single path segment only -- /api/db/users worked
 * while /api/db/users/9999 returned Vercel's own NOT_FOUND. So the rewrite in
 * vercel.json hands the rest of the path over in ?path= instead, and this
 * file's name contains nothing dynamic.
 *
 * NO AUTHENTICATION is involved: the upstream has none. Anything reachable
 * here is reachable by anyone who finds the deployment, exactly as it already
 * is on the upstream itself.
 */

/** Upstream user API. Override with the DB_API environment variable. */
const DB_API = process.env.DB_API || 'https://sbit.authconcepts.com:3033/api';

// PATCH is the balance endpoint (/users/:id/balance, /users/phone/:phone/balance).
const ALLOWED_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'];

// ---------------------------------------------------------------------------
// The one answer this proxy changes (2026-10-19): a GET /users/phone/:value
// the upstream answers 404 is matched on bare digits against the whole list.
// The attendee list the owner loaded that day holds 108 of 251 numbers
// formatted, "(212) 614-6927" or "+44 7511 509261", while every page looks
// up by bare digits (the User ID the booth QR gives the phone) and the API
// matches the stored string exactly, so those attendees had no balance, no
// contacts and no saved exchange. The reply keeps the route's shape, an
// array of records, first match first, so no page changed. dev-server.mjs
// and api/exchange.js import these two to do the same.
// ---------------------------------------------------------------------------
const PHONE_ROUTE = /^\/users\/phone\/([^/]+)$/;

/** Bare digits, with a leading US 1 dropped from an 11-digit number: the rule app.js and register.js apply. */
export function phoneDigits(value) {
  const digits = String(value ?? '').replace(/\D/g, '');
  return digits.length === 11 && digits.startsWith('1') ? digits.slice(1) : digits;
}

/** The phone value of a GET /users/phone/:value path (no sub-route), or null for any other request. */
export function phoneLookupValue(method, path) {
  if (method !== 'GET') return null;
  const m = PHONE_ROUTE.exec(path);
  return m ? m[1] : null;
}

/**
 * The records whose phone, as bare digits, is `value` as bare digits, in the
 * list's order; an empty array when none, null when the list cannot be read.
 * `fetchImpl` and `base` let the exchange function pass its own timed fetch.
 */
export async function matchByDigits(value, fetchImpl = fetch, base = DB_API) {
  const digits = phoneDigits(safeDecode(value));
  if (!digits) return null;
  try {
    const res = await fetchImpl(`${base}/users`);
    if (!res.ok) return null;
    const list = await res.json();
    return Array.isArray(list) ? list.filter(r => phoneDigits(r?.phone) === digits) : null;
  } catch (_) {
    return null;
  }
}

function safeDecode(value) {
  try { return decodeURIComponent(value); } catch (_) { return value; }
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (!ALLOWED_METHODS.includes(request.method)) {
      return json({ error: `Method ${request.method} is not proxied` }, 405);
    }

    const path = upstreamPath(url);
    const target = DB_API + path + upstreamQuery(url);

    const hasBody = request.method !== 'GET' && request.method !== 'HEAD';
    try {
      const upstream = await fetch(target, {
        method: request.method,
        headers: hasBody
          ? { 'Content-Type': request.headers.get('content-type') || 'application/json' }
          : {},
        body: hasBody ? await request.text() : undefined
      });
      let text = await upstream.text();
      let status = upstream.status;
      let type = upstream.headers.get('content-type') || 'application/json; charset=utf-8';
      // A phone lookup the upstream could not match as a string: matched on digits
      const phone = status === 404 ? phoneLookupValue(request.method, path) : null;
      const matches = phone ? await matchByDigits(phone) : null;
      if (matches?.length) {
        status = 200;
        text = JSON.stringify(matches);
        type = 'application/json; charset=utf-8';
      }
      return new Response(text, {
        status,
        headers: { 'Content-Type': type, 'Cache-Control': 'no-store' }
      });
    } catch (err) {
      return json({ error: 'Upstream user API unreachable', detail: err.message }, 502);
    }
  }
};

/**
 * Works out which upstream path was asked for. The rewrite passes it in
 * ?path=, but a request that reaches this file directly carries it in the
 * pathname instead, so both are accepted.
 */
function upstreamPath(url) {
  const fromQuery = url.searchParams.get('path');
  if (fromQuery) return '/' + fromQuery.replace(/^\/+/, '');
  return url.pathname.replace(/^\/(?:api\/)?db/, '');
}

/** Everything the caller sent except the path parameter the rewrite adds. */
function upstreamQuery(url) {
  const params = new URLSearchParams(url.search);
  params.delete('path');
  const query = params.toString();
  return query ? '?' + query : '';
}

function json(body, status) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
  });
}
