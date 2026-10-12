/**
 * register.js -- Badge registration: scan a badge, look the attendee up, hand
 * their number to the demo on their own phone
 *
 * The page has one button. Register opens this computer's camera and decodes
 * frames until a QR code is read. The code on a conference badge is the
 * attendee's confirmation number, which the user API resolves to a record
 * (GET /users/conf/:confNumber, see docs/user-api.md section 3b): first name,
 * last name, phone, email. Those go on screen, and the phone number, as bare
 * digits, becomes a second QR code pointing at the demo with
 * ?userid=<digits>&new=1. The attendee scans that with their phone, lands on
 * the SETUP screen with the number in the User ID field and New switched on,
 * and presses Trust Device: iShield create, ZSM + Passkeys+ enrollment, then
 * the number check.
 *
 * This is the other way into the demo beside enroll.html. The booth page
 * writes the key itself and sends the attendee to the login path (New off);
 * this page writes nothing and sends them to the create path (New on),
 * because nothing has been put on a key for them yet.
 *
 * DECODING: Chromium ships a BarcodeDetector backed by the platform (Vision
 * on macOS), which is used when it reports QR support. Safari has none, so
 * the vendored jsQR (window.jsQR, loaded by register.html as a classic
 * script) decodes a downscaled copy of each frame instead. The loop runs on
 * a timer rather than every animation frame; six or seven decodes a second
 * is plenty for a badge held still.
 *
 * NOTHING IS WRITTEN: the lookup is a read, the camera stream is stopped the
 * moment a code is decoded, and no frame leaves the page.
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * The Ideem user API, reached through the proxy this site runs at /db.
 * dev-server.mjs and api/db.js both forward to it.
 */
const DB_BASE = './db';

/**
 * Where the QR code sends the attendee's phone. A phone cannot reach this
 * computer's localhost, so a page served from there points at the deployment
 * instead, which is also where the credential Trust Device creates belongs.
 */
const PUBLIC_DEMO_ORIGIN = 'https://authenticate26.vercel.app';
const LOCAL_HOSTNAMES = ['localhost', '127.0.0.1', '[::1]', '::1'];

/** How often a camera frame is decoded, and the width it is scaled to for jsQR. */
const SCAN_INTERVAL_MS = 150;
const SCAN_WIDTH = 640;

/** Friendlier explanations for what getUserMedia throws. */
const CAMERA_ERRORS = {
  NotAllowedError: 'Camera access was blocked. Allow the camera for this site in the address bar, then press Register again.',
  PermissionDeniedError: 'Camera access was blocked. Allow the camera for this site in the address bar, then press Register again.',
  NotFoundError: 'No camera was found on this computer.',
  DevicesNotFoundError: 'No camera was found on this computer.',
  NotReadableError: 'The camera is in use by another app. Close it and press Register again.',
  TrackStartError: 'The camera is in use by another app. Close it and press Register again.',
  OverconstrainedError: 'No camera on this computer matched the request.',
  SecurityError: 'The camera only opens over HTTPS or on localhost.'
};

// ---------------------------------------------------------------------------
// Pure helpers (exported for the test harness)
// ---------------------------------------------------------------------------

/**
 * Bare digits of a phone number, the form the key, the database and the
 * ?userid= parameter all use. The US trunk prefix on an 11-digit number is
 * dropped, the same rule as normalizePhone in enroll.js and phoneDigits in
 * app.js. The record the API returns may carry dashes (the owner's test user
 * is "512-555-1234"), so this runs on everything before it is handed on.
 */
export function normalizePhone(raw) {
  const digits = String(raw || '').replace(/\D/g, '');
  return digits.length === 11 && digits.startsWith('1') ? digits.slice(1) : digits;
}

/** "(913) 555-1234" for a ten-digit number; anything else as it came. */
export function formatPhone(value) {
  const text = String(value || '');
  const digits = normalizePhone(text);
  return digits.length === 10 ? `(${digits.slice(0, 3)}) ${digits.slice(3, 6)}-${digits.slice(6)}` : text;
}

/**
 * The URL the attendee's phone opens: the demo with the number in the User ID
 * field and New on. app.js reads both parameters on load.
 */
export function registerUrl(phone, origin, hostname) {
  const base = LOCAL_HOSTNAMES.includes(hostname) ? PUBLIC_DEMO_ORIGIN : origin;
  return `${base}/?userid=${encodeURIComponent(phone)}&new=1`;
}

/** First and last name from a record, or a placeholder when both are blank. */
export function attendeeName(record) {
  return [record?.firstName, record?.lastName].map(s => String(s || '').trim()).filter(Boolean).join(' ') || 'Unnamed attendee';
}

/** One line for a camera error, by DOMException name. */
export function cameraErrorMessage(err) {
  return CAMERA_ERRORS[err?.name] || `${err?.name || 'Error'}: ${err?.message || 'the camera could not be opened'}`;
}

/**
 * Looks an attendee up by the confirmation number their badge carries. The
 * route is case-insensitive and answers with a single object, unlike the
 * by-phone route, which answers with an array.
 *
 * @returns {Promise<object|null>} The record, or null when there is none.
 */
export async function lookupAttendee(id, fetchImpl = fetch) {
  const res = await fetchImpl(`${DB_BASE}/users/conf/${encodeURIComponent(id)}`, { cache: 'no-store' });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`lookup returned ${res.status}`);
  const body = await res.json();
  return Array.isArray(body) ? body[0] ?? null : body;
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

const $ = id => document.getElementById(id);

let flashTimer;
let stream = null;        // the open camera stream while scanning
let scanTimer = null;     // the decode loop's pending timeout
let decoder = null;       // { name, decode(video) } once chosen

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
 * Picks the decoder once: the browser's own BarcodeDetector when it can read
 * QR codes, otherwise jsQR on a canvas copy of the frame. Null when neither
 * exists, which means the vendor directory was not built.
 */
async function makeDecoder() {
  if ('BarcodeDetector' in window) {
    try {
      const formats = await window.BarcodeDetector.getSupportedFormats();
      if (formats.includes('qr_code')) {
        const detector = new window.BarcodeDetector({ formats: ['qr_code'] });
        return {
          name: 'BarcodeDetector',
          async decode(video) {
            const codes = await detector.detect(video);
            return codes[0]?.rawValue ?? null;
          }
        };
      }
    } catch (_) { /* present but unusable; fall through to jsQR */ }
  }

  if (typeof window.jsQR === 'function') {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    return {
      name: 'jsQR',
      async decode(video) {
        const scale = Math.min(1, SCAN_WIDTH / (video.videoWidth || SCAN_WIDTH));
        canvas.width = Math.round(video.videoWidth * scale) || SCAN_WIDTH;
        canvas.height = Math.round(video.videoHeight * scale) || Math.round(SCAN_WIDTH * 0.75);
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const image = ctx.getImageData(0, 0, canvas.width, canvas.height);
        return window.jsQR(image.data, image.width, image.height)?.data ?? null;
      }
    };
  }

  return null;
}

/** Opens the camera and starts the decode loop. */
async function startScan() {
  if (stream) return;
  if (!navigator.mediaDevices?.getUserMedia) {
    showFlash('This browser cannot open the camera here. Use HTTPS or localhost.', 'failure', 0);
    return;
  }
  decoder ??= await makeDecoder();
  if (!decoder) {
    showFlash('No QR decoder is available: vendor/jsqr is missing. Run npm run build.', 'failure', 0);
    return;
  }

  clearResult();
  try {
    // facingMode is a preference, not a requirement: a laptop has only the
    // front camera, and that is what it gets.
    stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment', width: { ideal: 1280 }, height: { ideal: 720 } },
      audio: false
    });
  } catch (err) {
    showFlash(cameraErrorMessage(err), 'failure', 0);
    return;
  }

  const video = $('camera');
  video.srcObject = stream;
  try {
    await video.play();
  } catch (err) {
    stopScan();
    showFlash(`The camera preview could not start: ${err.message}`, 'failure', 0);
    return;
  }

  $('scanner').hidden = false;
  $('register-btn').hidden = true;
  $('decoder-info').textContent = `Decoding with ${decoder.name}`;
  showFlash('Hold the QR code on your badge up to the camera', 'info', 0);
  scanLoop();
}

/** Decodes one frame, then schedules the next until something is read. */
async function scanLoop() {
  if (!stream) return;
  const video = $('camera');
  if (video.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA) {
    let value = null;
    try {
      value = await decoder.decode(video);
    } catch (err) {
      console.warn('[register] decode failed:', err);
    }
    if (value && stream) {
      stopScan();
      await handleScanned(value);
      return;
    }
  }
  scanTimer = setTimeout(scanLoop, SCAN_INTERVAL_MS);
}

/** Releases the camera and hides the preview. Safe to call twice. */
function stopScan() {
  clearTimeout(scanTimer);
  scanTimer = null;
  if (stream) {
    for (const track of stream.getTracks()) track.stop();
    stream = null;
  }
  const video = $('camera');
  video.pause();
  video.srcObject = null;
  $('scanner').hidden = true;
  $('register-btn').hidden = false;
}

/** The value a scan (or the typed fallback) produced: look it up and show it. */
async function handleScanned(value) {
  const id = String(value).trim();
  if (!id) return;
  clearResult();
  showFlash(`Looking up ${id}...`, 'info', 0);

  let record;
  try {
    record = await lookupAttendee(id);
  } catch (err) {
    showFlash(`The user database could not be reached (${err.message}). Press Register to try again.`, 'failure', 0);
    return;
  }
  if (!record) {
    showFlash(`No attendee has the badge ID ${id}. Press Register to scan again.`, 'failure', 0);
    return;
  }

  showFlash(`Found ${attendeeName(record)}`, 'success');
  showAttendee(record, id);
}

/** Fills the details section and, when the record has a number, the QR. */
function showAttendee(record, id) {
  $('attendee-name').textContent = attendeeName(record);
  $('attendee-phone').textContent = record.phone ? formatPhone(record.phone) : 'not on record';
  $('attendee-email').textContent = record.email || 'not on record';
  $('attendee-id').textContent = record.confNumber || id;
  $('attendee-section').hidden = false;
  $('register-btn').textContent = 'Register another badge';

  const phone = normalizePhone(record.phone);
  if (!phone) {
    $('attendee-note').textContent = 'This record has no phone number, so there is nothing to hand to the demo. Enroll at the booth instead.';
    $('attendee-note').hidden = false;
    return;
  }
  showQr(phone);
}

/**
 * Draws the scan-to-open code. The generator is vendored and loaded on
 * demand, so if it is missing the link is still shown.
 */
async function showQr(phone) {
  const url = registerUrl(phone, location.origin, location.hostname);
  $('qr-link').textContent = url;
  $('qr-link').href = url;

  const sameOrigin = url.startsWith(location.origin + '/');
  $('qr-note').textContent = sameOrigin ? '' :
    `This page is running on ${location.origin}, which a phone cannot reach, so the code opens the deployment instead.`;
  $('qr-note').hidden = sameOrigin;

  try {
    const { qrcode } = await import('./vendor/qrcode-generator/dist/qrcode.mjs');
    const qr = qrcode(0, 'M');    // 0: smallest version the data fits in
    qr.addData(url);
    qr.make();
    // Geometry only; nothing from the record reaches the markup.
    $('qr-code').innerHTML = qr.createSvgTag({ cellSize: 8, margin: 8 * 4, scalable: true });
    $('qr-code').hidden = false;
  } catch (err) {
    console.error('[register] QR generator failed:', err);
    $('qr-code').replaceChildren();
    $('qr-code').hidden = true;
  }

  $('qr-section').hidden = false;
  $('qr-section').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/** Back to the one-button state, without touching the camera. */
function clearResult() {
  $('attendee-section').hidden = true;
  $('attendee-note').hidden = true;
  $('qr-section').hidden = true;
  $('qr-code').replaceChildren();
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', () => {
  $('register-btn').addEventListener('click', () => startScan());

  $('cancel-scan-btn').addEventListener('click', () => {
    stopScan();
    showFlash('Scan cancelled', 'info');
  });

  $('manual-form').addEventListener('submit', event => {
    event.preventDefault();
    stopScan();
    handleScanned($('badge-id').value);
  });

  // Leaving the page must not leave the camera light on
  window.addEventListener('pagehide', () => stopScan());
});
