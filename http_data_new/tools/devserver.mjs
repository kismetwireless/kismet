#!/usr/bin/env node
// Development server for the new Kismet UI.
//
// Serves the files in http_data_new/ and passes every other request (REST
// calls and websockets) through to an existing Kismet server, so the UI can be
// tested against a remote Kismet without changing its config: to the browser,
// everything comes from one origin, so the login cookie and websockets work.
//
//   node tools/devserver.mjs --target http://172.16.42.1:2501 [--port 2600] [--listen 127.0.0.1]

import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const args = { target: 'http://localhost:2501', port: 2600, listen: '127.0.0.1' };
for (let i = 2; i < process.argv.length; i += 2) {
    const key = process.argv[i].replace(/^--/, '');
    if (!(key in args) || process.argv[i + 1] === undefined) {
        console.error('usage: devserver.mjs [--target http://host:2501] [--port 2600] [--listen 127.0.0.1]');
        process.exit(1);
    }
    args[key] = process.argv[i + 1];
}

const target = new URL(args.target);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const mimeTypes = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.mjs': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.ico': 'image/x-icon',
    '.woff2': 'font/woff2',
    '.md': 'text/plain; charset=utf-8',
};

// Map a URL path to a file inside root, or null if there isn't one.  Never
// returns anything outside root.
function localFile(urlPath) {
    let rel;
    try {
        rel = decodeURIComponent(urlPath.split('?')[0]);
    } catch {
        return null;
    }
    if (rel.endsWith('/'))
        rel += 'index.html';

    const file = path.resolve(root, '.' + rel);
    if (file !== root && !file.startsWith(root + path.sep))
        return null;
    if (file.startsWith(path.join(root, 'tools') + path.sep))
        return null;

    try {
        return fs.statSync(file).isFile() ? file : null;
    } catch {
        return null;
    }
}

function proxyHeaders(headers) {
    const out = { ...headers, host: target.host };
    delete out.origin;
    delete out.referer;
    return out;
}

const server = http.createServer((req, res) => {
    const file = localFile(req.url);

    if (file && (req.method === 'GET' || req.method === 'HEAD')) {
        res.writeHead(200, {
            'Content-Type': mimeTypes[path.extname(file)] ?? 'application/octet-stream',
            'Cache-Control': 'no-cache',
        });
        if (req.method === 'HEAD')
            return res.end();
        return fs.createReadStream(file).pipe(res);
    }

    const upstream = http.request({
        host: target.hostname,
        port: target.port || 80,
        method: req.method,
        path: req.url,
        headers: proxyHeaders(req.headers),
    }, (ures) => {
        res.writeHead(ures.statusCode, ures.headers);
        ures.pipe(res);
    });

    upstream.on('error', (err) => {
        if (!res.headersSent)
            res.writeHead(502, { 'Content-Type': 'text/plain' });
        res.end(`Kismet server ${target.host} unreachable: ${err.message}\n`);
    });

    req.pipe(upstream);
});

// Websockets: replay the upgrade request upstream, then splice the two sockets.
server.on('upgrade', (req, socket, head) => {
    const upstream = net.connect(target.port || 80, target.hostname, () => {
        const headers = proxyHeaders(req.headers);
        let request = `${req.method} ${req.url} HTTP/1.1\r\n`;
        for (const [k, v] of Object.entries(headers))
            for (const value of [].concat(v))
                request += `${k}: ${value}\r\n`;
        upstream.write(request + '\r\n');
        if (head.length)
            upstream.write(head);
        upstream.pipe(socket);
        socket.pipe(upstream);
    });

    upstream.on('error', () => socket.destroy());
    socket.on('error', () => upstream.destroy());
});

server.listen(Number(args.port), args.listen, () => {
    console.log(`Kismet UI dev server: http://${args.listen}:${args.port}/  ->  ${target.origin}`);
});
