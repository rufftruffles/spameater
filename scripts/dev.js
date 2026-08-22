#!/usr/bin/env node
'use strict';

// Local development server. Not used in production (nginx serves the
// frontend there). Serves frontend/ on :8080, proxies /api/* to the API on
// :3001, and serves inbox JSON straight from $SPAMEATER_HOME/data/inboxes.
//
// Usage:
//   SPAMEATER_HOME=$PWD/.devhome node api-server.js &
//   SPAMEATER_HOME=$PWD/.devhome node scripts/dev.js

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 8080;
const API_PORT = 3001;
const FRONTEND_DIR = path.join(__dirname, '..', 'frontend');
const HOME = process.env.SPAMEATER_HOME || '/opt/spameater';
const INBOX_DIR = path.join(HOME, 'data', 'inboxes');
const DOMAIN = process.env.EMAIL_DOMAIN || 'spameater.io';

const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.woff2': 'font/woff2',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.txt': 'text/plain; charset=utf-8'
};

function send(res, status, body, type) {
    res.writeHead(status, { 'Content-Type': type || 'text/plain; charset=utf-8' });
    res.end(body);
}

function serveStatic(res, urlPath) {
    const rel = urlPath === '/' ? 'index.html' : urlPath.slice(1);
    const file = path.normalize(path.join(FRONTEND_DIR, rel));
    if (!file.startsWith(FRONTEND_DIR)) return send(res, 400, 'Bad path');
    fs.readFile(file, (err, data) => {
        if (err) return send(res, 404, 'Not found');
        const ext = path.extname(file);
        if (rel === 'index.html') {
            data = Buffer.from(data.toString('utf8').replaceAll('EMAIL_DOMAIN_PLACEHOLDER', DOMAIN));
        }
        send(res, 200, data, MIME[ext] || 'application/octet-stream');
    });
}

function serveInboxJson(res, urlPath) {
    const name = path.basename(urlPath);
    if (!/^[a-zA-Z0-9._-]+\.json$/.test(name) || name.includes('..')) {
        return send(res, 400, 'Bad inbox name');
    }
    fs.readFile(path.join(INBOX_DIR, name), (err, data) => {
        if (err) return send(res, 404, JSON.stringify({ error: 'Inbox not found' }), MIME['.json']);
        send(res, 200, data, MIME['.json']);
    });
}

function proxyApi(req, res) {
    const upstream = http.request(
        { host: '127.0.0.1', port: API_PORT, path: req.url, method: req.method, headers: req.headers },
        (upRes) => {
            res.writeHead(upRes.statusCode, upRes.headers);
            upRes.pipe(res);
        }
    );
    upstream.on('error', () => send(res, 502, 'API not running (start api-server.js first)'));
    req.pipe(upstream);
}

http.createServer((req, res) => {
    const urlPath = req.url.split('?')[0];
    if (urlPath.startsWith('/api/inbox/') && urlPath.endsWith('.json')) {
        return serveInboxJson(res, urlPath);
    }
    if (urlPath === '/api/domain') {
        return send(res, 200, JSON.stringify({ domain: DOMAIN }), MIME['.json']);
    }
    if (urlPath.startsWith('/api/')) {
        return proxyApi(req, res);
    }
    serveStatic(res, urlPath);
}).listen(PORT, '127.0.0.1', () => {
    console.log(`Dev server on http://127.0.0.1:${PORT} (frontend + /api proxy, domain ${DOMAIN})`);
});
