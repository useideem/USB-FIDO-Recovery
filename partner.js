/**
 * partner.js -- Identify: one touch of an iShield key, then on to a partner's
 * page with the User ID in the query string
 *
 * One button. Identify runs the demo's open get (webauthnIdentify in
 * ishield.js: empty allowCredentials, userVerification discouraged, the
 * security-key hint), so whatever discoverable credential the key holds for
 * this site answers with a touch and hands back its user handle: the phone
 * number register.html wrote there, as bare digits. The page then opens the
 * partner URL with that number added as ?userid=<digits>, the same parameter
 * the demo itself reads on arrival.
 *
 * WHERE IT GOES: the <meta name="partner-url"> in partner.html. An absolute
 * URL, or a path relative to this page; a query string already on it is kept
 * and userid is added. Left empty, the page shows the number and says the
 * URL is not set rather than going anywhere -- and never back to itself. The
 * destination is deliberately not read from this page's own query string: a
 * link that could name any destination would hand the number to whoever
 * wrote the link.
 *
 * BROWSERS: the open get is what phones do (iOS in any browser, Android
 * Chrome 128+) and Safari on a Mac. Desktop Chrome refuses it for a PIN-less
 * key, so the page says so up front, as register.html does for the create.
 *
 * The helpers (userIdFromHandle, partnerTarget, partnerUrl, describeGetError)
 * are pure or take the document, so a Node harness can cover them; the
 * module's top level only registers a DOMContentLoaded listener.
 */

import { webauthnIdentify } from './ishield.js';
import { detectBrowser } from './key-enroll.js';

/** The query parameter the partner page receives; the demo reads the same one. */
export const USER_PARAM = 'userid';

/** The <meta> in partner.html that names the destination. */
export const TARGET_META = 'partner-url';

/** What a failed get usually means, by DOMException name. */
export const GET_ERROR_HINTS = {
  NotAllowedError: 'Cancelled, timed out, no key inserted, or the browser refused the open query. Desktop Chrome does that for a PIN-less key: use a phone, or Safari on a Mac.',
  SecurityError: 'The RP ID is not valid for this origin. Open the page over HTTPS or http://localhost, not an IP address.',
  NotSupportedError: 'This browser cannot run a get without a credential list.',
  AbortError: 'The operation was aborted.'
};

/** E.164 allows 15 digits; 7 is the shortest number worth treating as one (as register.js). */
const MIN_DIGITS = 7;
const MAX_DIGITS = 15;

/**
 * The User ID a key's user handle stands for. register.html writes bare
 * digits, and a handle that reads as a phone number comes back in that form
 * whatever its spelling (the rule phoneDigits in app.js applies: strip
 * non-digits, drop a leading US 1 from 11). Any other non-empty handle is
 * passed through trimmed, since that is what the key vouches for; an empty
 * or missing handle gives null.
 */
export function userIdFromHandle(handle) {
  const text = String(handle ?? '').trim();
  if (!text) return null;
  const stripped = text.replace(/\D/g, '');
  const digits = stripped.length === 11 && stripped.startsWith('1') ? stripped.slice(1) : stripped;
  const phoneLike = /^[\d\s().+-]+$/.test(text) && digits.length >= MIN_DIGITS && digits.length <= MAX_DIGITS;
  return phoneLike ? digits : text;
}

/** The destination named by <meta name="partner-url">, trimmed, or '' when unset. */
export function partnerTarget(doc = document) {
  const meta = doc.querySelector(`meta[name="${TARGET_META}"]`);
  return String(meta?.content ?? '').trim();
}

/**
 * The partner URL with the User ID on it: `base` resolved against this page
 * (so a relative path works), its own query string kept, USER_PARAM set to
 * `userId`. An empty base gives null rather than a link back to this page.
 */
export function partnerUrl(userId, base, from = location.href) {
  const target = String(base ?? '').trim();
  if (!target) return null;
  const url = new URL(target, from);
  url.searchParams.set(USER_PARAM, userId);
  return url.href;
}

/** One line for a failed get: the DOMException name and what it usually means. */
export function describeGetError(err) {
  const name = err?.name || 'Error';
  const hint = GET_ERROR_HINTS[name];
  if (hint) return `${name}. ${hint}`;
  return err?.message || 'The key could not be read.';
}

// ---------------------------------------------------------------------------
// Page glue
// ---------------------------------------------------------------------------

const $ = id => document.getElementById(id);
let flashTimer = null;

function showFlash(message, state, duration = 6000) {
  const el = $('flash-status');
  clearTimeout(flashTimer);
  el.textContent = message;
  el.className = 'flash ' + state;
  if (duration) {
    flashTimer = setTimeout(() => { el.textContent = ''; el.className = 'flash'; }, duration);
  }
}

/**
 * Identify: the open get, the User ID off the handle, then the redirect. A
 * failure of any kind stays on this page with the reason in the flash.
 */
async function identify() {
  const btn = $('identify-btn');
  $('result').hidden = true;
  btn.disabled = true;
  btn.classList.add('loading');
  showFlash('Insert the iShield key and touch it when the browser asks...', 'info', 60000);
  try {
    const result = await webauthnIdentify();
    if (!result.success) {
      showFlash(describeGetError(result.error), 'failure', 12000);
      return;
    }
    const userId = userIdFromHandle(result.authenticatedUser);
    if (!userId) {
      showFlash('The key answered, but its credential carries no User ID. Enroll it on the registration page first.', 'failure', 12000);
      return;
    }

    $('result-user').textContent = userId;
    $('result').hidden = false;
    const target = partnerUrl(userId, partnerTarget());
    if (!target) {
      // Nowhere to go: say so, and show what would have been sent
      $('result-note').textContent = `No partner URL is set. Put it in <meta name="${TARGET_META}"> in partner.html; the page would have opened it with ?${USER_PARAM}=${userId}.`;
      $('result-note').hidden = false;
      showFlash(`Identified ${userId}`, 'success');
      return;
    }
    $('result-note').hidden = true;
    showFlash(`Identified ${userId}. Opening the partner page...`, 'success', 0);
    location.assign(target);
  } finally {
    btn.disabled = false;
    btn.classList.remove('loading');
  }
}

/** Names the browser in the footer and warns in desktop Chrome, where the open get fails. */
async function showBrowserInfo() {
  const { label, chromium, desktop } = await detectBrowser();
  $('browser-info').textContent = `Browser: ${label}`;
  $('chrome-warning').hidden = !(chromium && desktop);
}

document.addEventListener('DOMContentLoaded', () => {
  $('identify-btn').addEventListener('click', () => identify());
  if (!window.PublicKeyCredential) {
    $('identify-btn').disabled = true;
    $('identify-btn').textContent = 'This browser has no WebAuthn support';
  }
  showBrowserInfo();
});
