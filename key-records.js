/**
 * key-records.js -- The FIDO USB keys this browser has seen for a User ID
 *
 * The app has no backend, so what it knows about a user's keys lives in the
 * browser: one list per User ID in localStorage, newest first, one record
 * per credential id the key handed back on a get. The key itself holds the
 * credential; these records only say what THIS browser has associated,
 * reported lost or replaced, and when.
 *
 * A record:
 *   {
 *     id:             the credential id (base64url), the key's own identity
 *     userHandle:     the User ID the key carries, as the key spells it
 *     status:         'active' | 'lost' | 'replaced'
 *     associatedAt:   when this browser first verified the key (ISO date)
 *     lastVerifiedAt: the last successful get with it
 *     lostAt:         set by markLost
 *     replacedAt:     set when a later key took over
 *     userVerified:   whether the key verified the user (its PIN) on the last get
 *     signCount:      the key's counter on the last get
 *   }
 *
 * At most one record is active. A key reported lost, or replaced by a newer
 * one, is refused from then on: refusedKey() answers with its record and the
 * page says when it was lost. Reset Device wipes the list with everything
 * else.
 *
 * No DOM here, and `now` can be passed in, so a Node harness can cover it.
 */

/** localStorage key prefix: KEY_RECORDS_PREFIX + User ID. */
export const KEY_RECORDS_PREFIX = 'ishield_keys:';

export const KEY_STATUS = Object.freeze({ ACTIVE: 'active', LOST: 'lost', REPLACED: 'replaced' });

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

export function loadKeys(user) {
  if (!user) return [];
  try {
    const list = JSON.parse(localStorage.getItem(KEY_RECORDS_PREFIX + user));
    return Array.isArray(list) ? list : [];
  } catch (_) {
    return [];
  }
}

export function saveKeys(user, list) {
  if (!user) return;
  localStorage.setItem(KEY_RECORDS_PREFIX + user, JSON.stringify(list));
}

export function clearKeys(user) {
  if (user) localStorage.removeItem(KEY_RECORDS_PREFIX + user);
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/** The key this browser currently accepts for the user, or null. */
export function activeKey(user) {
  return loadKeys(user).find(k => k.status === KEY_STATUS.ACTIVE) || null;
}

export function findKey(user, id) {
  return loadKeys(user).find(k => k.id === id) || null;
}

/** The record of a key that is no longer accepted (lost or replaced), or null. */
export function refusedKey(user, id) {
  const record = findKey(user, id);
  return record && record.status !== KEY_STATUS.ACTIVE ? record : null;
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

function newRecord(assertion, now) {
  return {
    id: assertion.credentialId,
    userHandle: assertion.authenticatedUser ?? null,
    status: KEY_STATUS.ACTIVE,
    associatedAt: now,
    lastVerifiedAt: now,
    lostAt: null,
    replacedAt: null,
    userVerified: assertion.userVerified ?? null,
    signCount: assertion.signCount ?? null
  };
}

function touch(record, assertion, now) {
  return {
    ...record,
    lastVerifiedAt: now,
    userVerified: assertion.userVerified ?? record.userVerified,
    signCount: assertion.signCount ?? record.signCount
  };
}

/**
 * A successful get at setup or sign-in. The outcome says what the id was:
 *   'refused'     a key reported lost or replaced; nothing changes
 *   'verified'    the active key; its last-verified time moves
 *   'associated'  this browser had no active key, so this one is it now
 *   'unknown'     an active key exists and this is a different one; nothing
 *                 changes, the caller decides (Associate is the way to swap)
 *
 * @param {string} user
 * @param {{credentialId: string, authenticatedUser?: string|null, userVerified?: boolean, signCount?: number}} assertion
 * @param {string} [now]
 * @returns {{outcome: string, record: object|null}}
 */
export function recordVerification(user, assertion, now = new Date().toISOString()) {
  const list = loadKeys(user);
  const existing = list.find(k => k.id === assertion.credentialId) || null;
  if (existing && existing.status !== KEY_STATUS.ACTIVE) return { outcome: 'refused', record: existing };
  if (existing) {
    const record = touch(existing, assertion, now);
    saveKeys(user, list.map(k => (k.id === record.id ? record : k)));
    return { outcome: 'verified', record };
  }
  if (list.some(k => k.status === KEY_STATUS.ACTIVE)) return { outcome: 'unknown', record: null };
  const record = newRecord(assertion, now);
  saveKeys(user, [record, ...list]);
  return { outcome: 'associated', record };
}

/**
 * Associate a replacement key: the id becomes the active key, and whatever
 * was active before is marked replaced. The outcome says what happened:
 *   'refused'     the id belongs to a key reported lost or replaced
 *   'same'        the id is already the active key; nothing changes
 *   'associated'  the swap was made; `previous` is the key it replaced, if any
 *
 * @returns {{outcome: string, record: object|null, previous: object|null}}
 */
export function associateKey(user, assertion, now = new Date().toISOString()) {
  const list = loadKeys(user);
  const existing = list.find(k => k.id === assertion.credentialId) || null;
  if (existing && existing.status !== KEY_STATUS.ACTIVE) return { outcome: 'refused', record: existing, previous: null };
  if (existing) {
    const record = touch(existing, assertion, now);
    saveKeys(user, list.map(k => (k.id === record.id ? record : k)));
    return { outcome: 'same', record, previous: null };
  }
  let previous = null;
  const retired = list.map(k => {
    if (k.status !== KEY_STATUS.ACTIVE) return k;
    previous = { ...k, status: KEY_STATUS.REPLACED, replacedAt: now };
    return previous;
  });
  const record = newRecord(assertion, now);
  saveKeys(user, [record, ...retired]);
  return { outcome: 'associated', record, previous };
}

/**
 * The "I lost this key" report: the active key is marked lost and refused
 * from now on. Returns the record, or null when there was no active key.
 */
export function markLost(user, now = new Date().toISOString()) {
  const list = loadKeys(user);
  let lost = null;
  const updated = list.map(k => {
    if (k.status !== KEY_STATUS.ACTIVE) return k;
    lost = { ...k, status: KEY_STATUS.LOST, lostAt: now };
    return lost;
  });
  if (lost) saveKeys(user, updated);
  return lost;
}
