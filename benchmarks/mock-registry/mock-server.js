/**
 * mock-server.js
 * Lightweight local loopback mock npm registry for reproducible benchmarks.
 * 
 * Serves pinned tarballs and abbreviated install metadata (application/vnd.npm.install-v1+json).
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

// Parse CLI arguments
const args = process.argv.slice(2);
let port = 4873;
let host = '127.0.0.1';
let storageDir = path.resolve(__dirname, 'storage');
let portFile = null;
let pidFile = null;
let quiet = false;

for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port' && args[i + 1]) {
        port = parseInt(args[++i], 10);
    } else if (args[i] === '--host' && args[i + 1]) {
        host = args[++i];
    } else if (args[i] === '--storage' && args[i + 1]) {
        storageDir = path.resolve(args[++i]);
    } else if (args[i] === '--port-file' && args[i + 1]) {
        portFile = path.resolve(args[++i]);
    } else if (args[i] === '--pid-file' && args[i + 1]) {
        pidFile = path.resolve(args[++i]);
    } else if (args[i] === '--quiet') {
        quiet = true;
    }
}

// Request log for benchmark verification
const requestLogs = [];

function log(msg) {
    if (!quiet) {
        console.log(`[mock-registry] ${msg}`);
    }
}

// Helper to normalize package names (e.g. @scope%2fname -> @scope/name)
function normalizePkgName(raw) {
    try {
        return decodeURIComponent(raw);
    } catch {
        return raw;
    }
}

const server = http.createServer((req, res) => {
    const startTime = Date.now();
    const parsedUrl = url.parse(req.url, true);
    let pathname = parsedUrl.pathname || '/';

    const reqRecord = {
        timestamp: new Date().toISOString(),
        method: req.method,
        url: req.url,
        pathname,
        headers: req.headers,
        status: 200,
        bytes: 0
    };

    function finish(statusCode, contentType, body) {
        reqRecord.status = statusCode;
        reqRecord.durationMs = Date.now() - startTime;
        reqRecord.bytes = Buffer.isBuffer(body) ? body.length : (body ? Buffer.byteLength(body) : 0);
        requestLogs.push(reqRecord);

        res.writeHead(statusCode, {
            'Content-Type': contentType,
            'Content-Length': reqRecord.bytes,
            'Connection': 'close',
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        if (body) {
            res.end(body);
        } else {
            res.end();
        }
        log(`${req.method} ${req.url} -> ${statusCode} (${reqRecord.bytes}B, ${reqRecord.durationMs}ms)`);
    }

    // Health / API endpoints
    if (pathname === '/api/health' || pathname === '/health') {
        return finish(200, 'application/json', JSON.stringify({ status: 'ok', uptime: process.uptime() }));
    }

    if (pathname === '/api/requests') {
        return finish(200, 'application/json', JSON.stringify({
            count: requestLogs.length,
            requests: requestLogs
        }, null, 2));
    }

    if (pathname === '/api/reset' && req.method === 'POST') {
        requestLogs.length = 0;
        return finish(200, 'application/json', JSON.stringify({ status: 'cleared' }));
    }

    if (pathname === '/api/shutdown') {
        finish(200, 'application/json', JSON.stringify({ status: 'shutting_down' }));
        log('Shutdown requested via API');
        setTimeout(() => {
            cleanup();
            process.exit(0);
        }, 100);
        return;
    }

    // Status simulation endpoints for error testing
    if (pathname.startsWith('/__status/')) {
        const codeStr = pathname.replace('/__status/', '');
        const code = parseInt(codeStr, 10);
        if (code === 302) {
            res.writeHead(302, { 'Location': 'http://127.0.0.1:4873/pkg-single-a' });
            return res.end();
        }
        if (!isNaN(code)) {
            return finish(code, 'application/json', JSON.stringify({ error: `Simulated status ${code}` }));
        }
    }

    // Determine host for dynamic tarball URLs
    const requestHost = req.headers.host || `${host}:${port}`;
    const baseUrl = `http://${requestHost}`;

    // Tarball download request: /<pkg>/-/<filename> or /@<scope>/<pkg>/-/<filename>
    const tarballMatch = pathname.match(/^\/(?:(@[^/]+)\/)?([^/]+)\/-\/([^/]+)$/);
    if (tarballMatch) {
        const scope = tarballMatch[1];
        const rawName = tarballMatch[2];
        const filename = tarballMatch[3];
        const pkgName = normalizePkgName(scope ? `${scope}/${rawName}` : rawName);

        const candidatePath = path.join(storageDir, pkgName, filename);
        if (fs.existsSync(candidatePath)) {
            const data = fs.readFileSync(candidatePath);
            return finish(200, 'application/octet-stream', data);
        } else {
            return finish(404, 'application/json', JSON.stringify({ error: `Tarball not found: ${filename}` }));
        }
    }

    // Packument metadata request: /<pkg> or /@scope%2f<pkg> or /@scope/<pkg>
    // Strip leading slash
    let pkgParam = pathname.replace(/^\//, '');
    pkgParam = normalizePkgName(pkgParam);

    // Skip root or favicon
    if (!pkgParam || pkgParam === 'favicon.ico') {
        return finish(404, 'application/json', JSON.stringify({ error: 'Not found' }));
    }

    const metadataPath = path.join(storageDir, pkgParam, 'metadata.json');
    if (fs.existsSync(metadataPath)) {
        try {
            const raw = fs.readFileSync(metadataPath, 'utf8');
            const data = JSON.parse(raw);

            // Dynamically rewrite tarball URLs to match incoming request host/port
            for (const vKey of Object.keys(data.versions || {})) {
                const v = data.versions[vKey];
                if (v && v.dist && v.dist.tarball) {
                    const tarballFilename = path.basename(url.parse(v.dist.tarball).pathname);
                    v.dist.tarball = `${baseUrl}/${pkgParam}/-/${tarballFilename}`;
                }
            }

            // Check if client asked for abbreviated metadata
            const accept = req.headers['accept'] || '';
            const prefersAbbreviated = accept.includes('application/vnd.npm.install-v1+json');

            let responseBody;
            let contentType;

            if (prefersAbbreviated) {
                // Abbreviated packument
                contentType = 'application/vnd.npm.install-v1+json; charset=utf-8';
                const abbreviated = {
                    name: data.name,
                    'dist-tags': data['dist-tags'],
                    versions: {},
                    modified: data.modified || new Date().toISOString()
                };

                for (const [ver, v] of Object.entries(data.versions)) {
                    abbreviated.versions[ver] = {
                        name: v.name,
                        version: v.version,
                        dist: v.dist,
                        dependencies: v.dependencies || {},
                        devDependencies: v.devDependencies || {},
                        peerDependencies: v.peerDependencies || {},
                        bin: v.bin,
                        engines: v.engines,
                        cpu: v.cpu,
                        os: v.os,
                        hasInstallScript: v.hasInstallScript || false
                    };
                }
                responseBody = JSON.stringify(abbreviated);
            } else {
                // Standard packument
                contentType = 'application/json; charset=utf-8';
                responseBody = JSON.stringify(data);
            }

            return finish(200, contentType, responseBody);
        } catch (err) {
            return finish(500, 'application/json', JSON.stringify({ error: err.message }));
        }
    }

    return finish(404, 'application/json', JSON.stringify({ error: `Package not found: ${pkgParam}` }));
});

function cleanup() {
    if (portFile && fs.existsSync(portFile)) {
        try { fs.unlinkSync(portFile); } catch {}
    }
    if (pidFile && fs.existsSync(pidFile)) {
        try { fs.unlinkSync(pidFile); } catch {}
    }
}

process.on('SIGINT', () => { cleanup(); process.exit(0); });
process.on('SIGTERM', () => { cleanup(); process.exit(0); });
process.on('exit', cleanup);

server.listen(port, host, () => {
    const actualPort = server.address().port;
    log(`Listening on http://${host}:${actualPort} (storage: ${storageDir})`);

    if (portFile) {
        fs.writeFileSync(portFile, actualPort.toString(), 'utf8');
    }
    if (pidFile) {
        fs.writeFileSync(pidFile, process.pid.toString(), 'utf8');
    }
});
