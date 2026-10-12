/**
 * webauthn-util.js -- Shared WebAuthn response parsing
 *
 * The parts of a ceremony result that any page here needs to read: the
 * authenticator data flags and extension outputs, and the relying-party
 * checks a server would run on clientDataJSON. Used by key-enroll.js (the
 * registration page's create) and the raw key tester (fido-test.js).
 *
 * SPEC REFERENCES:
 *   - W3C WebAuthn Level 3: https://www.w3.org/TR/webauthn-3/
 *   - FIDO CTAP 2.1:        https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html
 */

import { bufferToBase64url } from './ishield.js';

/** credProtect levels as reported by the key (CTAP 2.1 §12.1). */
export const CRED_PROTECT_LEVELS = {
  1: 'UV optional',
  2: 'UV optional with ID list',
  3: 'UV required'
};

export function toHex(buffer) {
  return Array.from(new Uint8Array(buffer), b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Minimal CBOR decoder -- just enough to step over the COSE public key in
 * authenticator data and read the extension outputs that follow it.
 * Handles definite-length items only (all CTAP2 requires).
 *
 * @param {Uint8Array} bytes
 * @param {number} offset - Where the item starts.
 * @returns {{value: *, offset: number}} The decoded item and the offset just past it.
 */
export function decodeCbor(bytes, offset = 0) {
  const initial = bytes[offset++];
  const major = initial >> 5;
  const info = initial & 0x1f;
  const view = new DataView(bytes.buffer, bytes.byteOffset);
  let arg = info;
  if (info === 24) { arg = bytes[offset]; offset += 1; }
  else if (info === 25) { arg = view.getUint16(offset); offset += 2; }
  else if (info === 26) { arg = view.getUint32(offset); offset += 4; }
  else if (info === 27) { arg = Number(view.getBigUint64(offset)); offset += 8; }
  else if (info > 27) throw new Error('Indefinite-length CBOR is not supported');

  switch (major) {
    case 0: return { value: arg, offset };
    case 1: return { value: -1 - arg, offset };
    case 2: return { value: bytes.slice(offset, offset + arg), offset: offset + arg };
    case 3: return { value: new TextDecoder().decode(bytes.slice(offset, offset + arg)), offset: offset + arg };
    case 4: {
      const items = [];
      for (let i = 0; i < arg; i++) {
        const item = decodeCbor(bytes, offset);
        items.push(item.value);
        offset = item.offset;
      }
      return { value: items, offset };
    }
    case 5: {
      const map = {};
      for (let i = 0; i < arg; i++) {
        const key = decodeCbor(bytes, offset);
        const val = decodeCbor(bytes, key.offset);
        map[key.value] = val.value;
        offset = val.offset;
      }
      return { value: map, offset };
    }
    case 6: return decodeCbor(bytes, offset);  // tag: ignore it, decode the tagged item
    default: return { value: { 20: false, 21: true, 22: null }[info], offset };  // simple values / floats
  }
}

/**
 * Parses the fixed part of authenticator data (WebAuthn L3 §6.1):
 *   bytes 0-31   rpIdHash
 *   byte  32     flags: bit0 UP, bit2 UV, bit3 BE, bit4 BS, bit6 AT, bit7 ED
 *   bytes 33-36  signCount (big-endian uint32)
 *   bytes 37-52  AAGUID, 53-54 credential ID length, then the credential ID
 *                and COSE public key (only when AT is set)
 *   then         extension outputs as a CBOR map (only when ED is set)
 *
 * @param {ArrayBuffer} buffer - Raw authenticator data.
 */
export function parseAuthenticatorData(buffer) {
  const bytes = new Uint8Array(buffer);
  const view = new DataView(buffer);
  const f = bytes[32];
  const flags = {
    UP: !!(f & 0x01),
    UV: !!(f & 0x04),
    BE: !!(f & 0x08),
    BS: !!(f & 0x10),
    AT: !!(f & 0x40),
    ED: !!(f & 0x80)
  };
  const parsed = {
    rpIdHash: toHex(bytes.slice(0, 32)),
    flags,
    flagsByte: '0x' + f.toString(16).padStart(2, '0'),
    signCount: view.getUint32(33)
  };
  try {
    let offset = 37;
    if (flags.AT && bytes.length >= 55) {
      const a = toHex(bytes.slice(37, 53));
      parsed.aaguid = `${a.slice(0, 8)}-${a.slice(8, 12)}-${a.slice(12, 16)}-${a.slice(16, 20)}-${a.slice(20)}`;
      parsed.credentialIdLength = view.getUint16(53);
      offset = decodeCbor(bytes, 55 + parsed.credentialIdLength).offset;  // step over the COSE key
    }
    if (flags.ED && offset < bytes.length) {
      parsed.extensions = decodeCbor(bytes, offset).value;  // e.g. { credProtect: 1 }
    }
  } catch (err) {
    parsed.parseError = err.message;
  }
  return parsed;
}

export function setFlagNames(flags) {
  return Object.keys(flags).filter(k => flags[k]).join(' ') || 'none';
}

/**
 * Checks clientDataJSON and rpIdHash the way a relying party server would
 * (WebAuthn L3 §7.1 / §7.2): ceremony type, our challenge, our origin, and
 * that the key scoped the credential to our RP ID.
 */
export async function checkCeremony({ clientDataJSON, authData, expectedType, challenge, rpId }) {
  const clientData = JSON.parse(new TextDecoder().decode(clientDataJSON));
  const expectedRpIdHash = toHex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId)));
  return {
    clientData,
    type: clientData.type === expectedType,
    challenge: clientData.challenge === bufferToBase64url(challenge),
    origin: clientData.origin === location.origin,
    rpIdHash: authData.rpIdHash === expectedRpIdHash
  };
}
