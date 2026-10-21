#!/usr/bin/env node

/**
 * dev-server.mjs -- Local static server with a result log for fido-test.html
 *
 * Serves this directory (dotfiles such as .git are never served) and accepts
 * POST /log from fido-test.js, appending each JSON body as one line to
 * .dev-logs/fido-test.jsonl. That lets results from any browser -- including
 * phones reaching this machine through a tunnel -- be read from one file.
 *
 * It also keeps a shared list of issued credentials in
 * .dev-logs/credentials.json, which the registration page and the key tester
 * post to and the tester reads back:
 *   POST /credentials           store { id, rpId, userName, publicKey, ... }
 *   GET  /credentials?rpId=...  list the credentials issued for that RP ID
 *
 * Local testing only; Vercel serves the static files in production and the
 * two endpoints simply aren't there. Nothing else is proxied: the app has no
 * backend of its own.
 *
 * USAGE:
 *   node dev-server.mjs          # http://localhost:8080
 *   PORT=3000 node dev-server.mjs
 */

import { createServer } from 'http';
import { readFile, writeFile, appendFile, mkdir } from 'fs/promises';
import { join, extname, normalize, dirname } from 'path';
import { fileURLToPath } from 'url';

const ROOT = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT) || 8080;
const LOG_FILE = join(ROOT, '.dev-logs', 'fido-test.jsonl');
const CREDS_FILE = join(ROOT, '.dev-logs', 'credentials.json');
const MAX_LOG_BYTES = 256 * 1024;

const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.md': 'text/markdown; charset=utf-8'
};

async function handleLog(req, res) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (body.length > MAX_LOG_BYTES) {
      res.writeHead(413).end();
      return;
    }
  }
  try {
    const entry = { receivedAt: new Date().toISOString(), ip: req.socket.remoteAddress, ...JSON.parse(body) };
    await mkdir(dirname(LOG_FILE), { recursive: true });
    await appendFile(LOG_FILE, JSON.stringify(entry) + '\n');
    console.log(`[log] ${entry.event || '?'} ${entry.title || ''}`);
    res.writeHead(204).end();
  } catch (err) {
    res.writeHead(400, { 'Content-Type': 'text/plain' }).end(err.message);
  }
}

async function loadStoredCredentials() {
  try {
    return JSON.parse(await readFile(CREDS_FILE, 'utf8'));
  } catch (_) {
    return [];
  }
}

async function handleCredentials(req, res, url) {
  if (req.method === 'GET') {
    const rpId = url.searchParams.get('rpId');
    const list = (await loadStoredCredentials()).filter(c => !rpId || c.rpId === rpId);
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store'
    }).end(JSON.stringify(list));
    return;
  }

  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (body.length > MAX_LOG_BYTES) {
      res.writeHead(413).end();
      return;
    }
  }
  try {
    const entry = JSON.parse(body);
    if (!entry.id || !entry.rpId) throw new Error('id and rpId are required');
    // Newest first, one record per credential ID
    const list = [
      { ...entry, storedAt: new Date().toISOString() },
      ...(await loadStoredCredentials()).filter(c => c.id !== entry.id)
    ];
    await mkdir(dirname(CREDS_FILE), { recursive: true });
    await writeFile(CREDS_FILE, JSON.stringify(list, null, 2));
    console.log(`[credentials] stored ${entry.userName} for ${entry.rpId} (${list.length} total)`);
    res.writeHead(204).end();
  } catch (err) {
    res.writeHead(400, { 'Content-Type': 'text/plain' }).end(err.message);
  }
}

async function handleStatic(req, res) {
  const path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  const relative = normalize(path === '/' ? '/index.html' : path).replace(/^([/\\])+/, '');
  if (relative.startsWith('..') || relative.split(/[/\\]/).some(part => part.startsWith('.'))) {
    res.writeHead(404).end();
    return;
  }
  try {
    const data = await readFile(join(ROOT, relative));
    res.writeHead(200, {
      'Content-Type': CONTENT_TYPES[extname(relative)] || 'application/octet-stream',
      'Cache-Control': 'no-store'  // always serve the latest edit
    }).end(data);
  } catch (_) {
    res.writeHead(404).end();
  }
}

createServer((req, res) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
  const url = new URL(req.url, 'http://x');
  if (req.method === 'POST' && url.pathname === '/log') return handleLog(req, res);
  if (url.pathname === '/credentials' && (req.method === 'GET' || req.method === 'POST')) {
    return handleCredentials(req, res, url);
  }
  if (req.method === 'GET' || req.method === 'HEAD') return handleStatic(req, res);
  res.writeHead(405).end();
}).listen(PORT, '127.0.0.1', () => {
  console.log(`Serving ${ROOT} at http://localhost:${PORT} (results -> ${LOG_FILE})`);
});
