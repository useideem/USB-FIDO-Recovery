/**
 * sna.js -- Simulated Silent Network Authentication (SNA)
 *
 * Silent Network Authentication proves that a phone number belongs to the
 * device in hand by asking the mobile network, with nothing for the user to
 * type. The device opens a one-time URL over its cellular data connection,
 * the carrier recognises the SIM behind that connection and redirects back
 * with a code, and the verifier's backend exchanges the code for a verdict:
 * does the SIM match the number that was claimed?
 *
 * This module SIMULATES that flow, modelled on IDlayr's Secure SNA
 * walkthrough (https://secure-sna-demo.idlayr.com). It makes no network
 * request. Each step resolves on a timer, and the result is shaped like the
 * real API's so the page can show the check ID and code the way it shows
 * the iShield and Passkeys+ challenges.
 *
 * THE STEPS, as the real flow runs them:
 *   1. Backend creates a check          POST /secure-sna-checks        -> 201 { check_id, url }
 *   2. Device opens the check URL       GET  <url>  over cellular data
 *   3. Mobile network verifies the SIM
 *   4. Network redirects with a code    302  redirect_url?code=...
 *   5. Backend completes the check      PATCH /secure-sna-checks/<id>  { code } -> 200 { match }
 *   6. Verified                         match: true
 *
 * A real integration keeps the IDlayr API key on a server, so steps 1 and 5
 * become calls to the partner's backend and step 2 a real fetch that the
 * phone must make over cellular, not Wi-Fi. Nothing in app.js would change:
 * replace the inside of verifyNumber() and keep its contract.
 *
 * Like ishield.js, this module never touches the DOM. The "number verified"
 * marker is a localStorage flag per User ID on this device, the same shape
 * as the iShield enrollment marker, and Reset Device wipes it with the rest.
 *
 * HOW TO USE:
 *   import { verifyNumber, isNumberVerified, setNumberVerified } from './sna.js';
 *
 *   const result = await verifyNumber('9135551235', {
 *     onStep: (index, step, status) => { ... }   // status: 'active' | 'done' | 'failed'
 *   });
 *   // result = { match: true, checkId, code, phone, verifiedAt, reason: null, steps: [...] }
 *   if (result.match) setNumberVerified(user, result);
 *
 * SCENARIOS (the IDlayr walkthrough offers the same three):
 *   'success'      every step passes and match is true
 *   'nomatch'      the network answers, but for a different SIM: match is false
 *   'unsupported'  the network cannot verify this connection (Wi-Fi only, an
 *                  unsupported carrier): the flow stops at step 3
 *
 * The simulation does not care whether the value it is given is a phone
 * number; a User ID like "test2" plays through just the same, so the demo
 * never blocks on it.
 */

/** localStorage key prefix for the per-device "number verified" marker. */
export const NUMBER_VERIFIED_PREFIX = 'sna_verified:';

/** The outcomes the simulation can play. */
export const SNA_SCENARIOS = Object.freeze(['success', 'nomatch', 'unsupported']);

/**
 * The steps in order: what each stands for in the real flow, how long the
 * simulation dwells on it, and what it reads when it is the one that fails.
 * The page draws its step list from this, so the wording lives here once.
 */
export const SNA_STEPS = Object.freeze([
  Object.freeze({
    id: 'create',
    label: 'Create verification check',
    detail: 'POST /secure-sna-checks → 201 { check_id, url }',
    ms: 700
  }),
  Object.freeze({
    id: 'open',
    label: 'Open the check URL over cellular',
    detail: 'GET /secure-sna-checks/{check_id}/redirect',
    ms: 800
  }),
  Object.freeze({
    id: 'network',
    label: 'Mobile network verifies the number',
    detail: 'carrier matches the SIM behind this connection',
    failDetail: 'carrier cannot verify this connection',
    ms: 1200
  }),
  Object.freeze({
    id: 'redirect',
    label: 'Network redirects with a one-time code',
    detail: '302 redirect_url?code=…',
    ms: 600
  }),
  Object.freeze({
    id: 'complete',
    label: 'Complete the check',
    detail: 'PATCH /secure-sna-checks/{check_id} { code } → 200 { match: true }',
    failDetail: 'PATCH /secure-sna-checks/{check_id} { code } → 200 { match: false }',
    ms: 800
  }),
  Object.freeze({
    id: 'verified',
    label: 'Number verified',
    detail: 'match: true',
    ms: 300
  })
]);

/** Where each scenario stops, and the reason the result carries. */
const FAILS_AT = Object.freeze({
  success: null,
  nomatch: Object.freeze({ step: 'complete', reason: 'no_match' }),
  unsupported: Object.freeze({ step: 'network', reason: 'network_unsupported' })
});

// ---------------------------------------------------------------------------
// The simulated check
// ---------------------------------------------------------------------------

/**
 * Plays the SNA flow for a phone number and resolves to its result.
 *
 * onStep(index, step, status) is called as each step starts ('active') and
 * ends ('done' or 'failed'), with the SNA_STEPS entry, so a page can draw
 * progress. speed scales every dwell time (2 halves them). signal is an
 * AbortSignal; aborting rejects with an AbortError at the next step boundary.
 *
 * @param {string} phone - The number being verified; stored on the result as given.
 * @param {object} [options]
 * @param {'success'|'nomatch'|'unsupported'} [options.scenario='success']
 * @param {(index: number, step: object, status: string) => void} [options.onStep]
 * @param {number} [options.speed=1]
 * @param {AbortSignal} [options.signal]
 * @returns {Promise<{match: boolean, scenario: string, phone: string, checkId: string,
 *   code: string|null, reason: string|null, verifiedAt: string|null,
 *   steps: Array<{id: string, status: string}>}>}
 */
export async function verifyNumber(phone, { scenario = 'success', onStep = () => {}, speed = 1, signal } = {}) {
  if (!SNA_SCENARIOS.includes(scenario)) throw new Error(`Unknown SNA scenario: ${scenario}`);
  if (!(speed > 0)) throw new Error('speed must be a positive number');

  const result = {
    match: false,
    scenario,
    phone: String(phone ?? '').trim(),
    checkId: randomUuid(),
    code: null,
    reason: null,
    verifiedAt: null,
    steps: []
  };
  const failure = FAILS_AT[scenario];

  for (let index = 0; index < SNA_STEPS.length; index++) {
    const step = SNA_STEPS[index];
    throwIfAborted(signal);
    onStep(index, step, 'active');
    await wait(step.ms / speed, signal);

    if (failure && failure.step === step.id) {
      result.reason = failure.reason;
      result.steps.push({ id: step.id, status: 'failed' });
      onStep(index, step, 'failed');
      return result;
    }
    if (step.id === 'redirect') result.code = oneTimeCode();
    result.steps.push({ id: step.id, status: 'done' });
    onStep(index, step, 'done');
  }

  result.match = true;
  result.verifiedAt = new Date().toISOString();
  return result;
}

// ---------------------------------------------------------------------------
// The per-device marker
// ---------------------------------------------------------------------------

/**
 * The stored verification for this user on this device, or null. Only a
 * successful check is ever stored.
 *
 * @param {string} user - The User ID.
 * @returns {{checkId: string, code: string, phone: string, verifiedAt: string, simulated: true}|null}
 */
export function getNumberVerification(user) {
  if (!user) return null;
  try {
    const raw = localStorage.getItem(NUMBER_VERIFIED_PREFIX + user);
    return raw ? JSON.parse(raw) : null;
  } catch (_) {
    return null;
  }
}

/**
 * True when this device has verified the user's number.
 *
 * @param {string} user - The User ID.
 * @returns {boolean}
 */
export function isNumberVerified(user) {
  return getNumberVerification(user) !== null;
}

/**
 * Records a successful check for the user on this device. Pass the result
 * of verifyNumber(); only the fields the page later shows are kept.
 *
 * @param {string} user - The User ID.
 * @param {{checkId: string, code: string|null, phone: string, verifiedAt: string|null}} result
 */
export function setNumberVerified(user, result) {
  if (!user) return;
  const { checkId, code, phone, verifiedAt } = result;
  localStorage.setItem(NUMBER_VERIFIED_PREFIX + user, JSON.stringify({
    checkId,
    code,
    phone,
    verifiedAt: verifiedAt || new Date().toISOString(),
    simulated: true
  }));
}

/**
 * Forgets the verification for the user on this device.
 *
 * @param {string} user - The User ID.
 */
export function clearNumberVerified(user) {
  if (user) localStorage.removeItem(NUMBER_VERIFIED_PREFIX + user);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function randomUuid() {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** The one-time code the network's redirect would carry: opaque, single use. */
function oneTimeCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(18));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function abortError() {
  return new DOMException('The number check was cancelled', 'AbortError');
}

function throwIfAborted(signal) {
  if (signal?.aborted) throw abortError();
}

function wait(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortError());
      return;
    }
    const onAbort = () => {
      clearTimeout(timer);
      reject(abortError());
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}
