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
 * .dev-logs/credentials.json, standing in for the demo's future backend:
 *   POST /credentials           store { id, rpId, userName, publicKey, ... }
 *   GET  /credentials?rpId=...  list the credentials issued for that RP ID
 *
 * It proxies /db/* to the Ideem user API. That API sends no CORS headers,
 * so a page cannot call it from the browser; going through this server's
 * own origin sidesteps that. Vercel does the same thing in production, so
 * pages fetch the same relative /db/... path either way.
 *
 * Finally it mounts the P2P Contact Exchange function (api/exchange.js) at
 * /api/exchange, the path Vercel gives it, so the exchange works locally
 * with records held in this process.
 *
 * Local testing only; Vercel serves the static files in production and
 * /log simply isn't there.
 *
 * USAGE:
 *   node dev-server.mjs          # http://localhost:8080
 *   PORT=3000 node dev-server.mjs
 */

import { createServer } from 'http';
import { readFile, writeFile, appendFile, mkdir } from 'fs/promises';
import { join, extname, normalize, dirname } from 'path';
import { fileURLToPath } from 'url';

import exchange from './api/exchange.js';

const ROOT = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT) || 8080;
const LOG_FILE = join(ROOT, '.dev-logs', 'fido-test.jsonl');
const CREDS_FILE = join(ROOT, '.dev-logs', 'credentials.json');
const MAX_LOG_BYTES = 256 * 1024;

/** Where /db/* is forwarded. The same upstream Vercel rewrites to. */
const DB_API = process.env.DB_API || 'https://sbit.authconcepts.com:3033/api';

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

/**
 * Forwards /db/<path> to the user API and returns its answer verbatim.
 * The upstream sends no Access-Control-Allow-Origin, so the browser refuses
 * to call it directly; from here it is same-origin and the question never
 * comes up. Nothing is cached, and no credentials are attached.
 */
async function handleDb(req, res, url) {
  const target = DB_API + url.pathname.slice('/db'.length) + url.search;
  let body;
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    body = '';
    for await (const chunk of req) {
      body += chunk;
      if (body.length > MAX_LOG_BYTES) {
        res.writeHead(413).end();
        return;
      }
    }
  }
  try {
    const upstream = await fetch(target, {
      method: req.method,
      headers: { ...(body !== undefined && { 'Content-Type': req.headers['content-type'] || 'application/json' }) },
      body
    });
    const text = await upstream.text();
    console.log(`[db] ${req.method} ${target} -> ${upstream.status}`);
    res.writeHead(upstream.status, {
      'Content-Type': upstream.headers.get('content-type') || 'application/json; charset=utf-8',
      'Cache-Control': 'no-store'
    }).end(text);
  } catch (err) {
    console.error(`[db] ${req.method} ${target} failed: ${err.message}`);
    res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' })
      .end(JSON.stringify({ error: 'Upstream user API unreachable', detail: err.message }));
  }
}

/**
 * Runs the P2P Contact Exchange function in-process. It is written against
 * the web Request/Response pair Vercel hands it, so this only bridges Node's
 * req/res to that. Without Redis configured it keeps its records in a Map,
 * which in this single process is exactly right.
 */
async function handleExchange(req, res, url) {
  let body;
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    body = '';
    for await (const chunk of req) {
      body += chunk;
      if (body.length > MAX_LOG_BYTES) {
        res.writeHead(413).end();
        return;
      }
    }
  }
  const request = new Request(`http://localhost:${PORT}${url.pathname}${url.search}`, {
    method: req.method,
    headers: { 'Content-Type': req.headers['content-type'] || 'application/json' },
    body
  });
  const response = await exchange.fetch(request);
  const text = await response.text();
  console.log(`[exchange] ${req.method} ${url.pathname}${url.search} -> ${response.status}`);
  res.writeHead(response.status, Object.fromEntries(response.headers)).end(text);
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
  if (url.pathname === '/db' || url.pathname.startsWith('/db/')) return handleDb(req, res, url);
  if (url.pathname === '/api/exchange') return handleExchange(req, res, url);
  if (req.method === 'GET' || req.method === 'HEAD') return handleStatic(req, res);
  res.writeHead(405).end();
}).listen(PORT, '127.0.0.1', () => {
  console.log(`Serving ${ROOT} at http://localhost:${PORT} (results -> ${LOG_FILE})`);
});
