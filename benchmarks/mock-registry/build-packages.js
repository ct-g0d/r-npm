/**
 * build-packages.js
 * Generates synthetic package tarballs and packument metadata for the mock registry.
 * Supports Tier 1 (synthetic) and Tier 2 (standard: typescript-cli, express) packages.
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');

function createTarHeader(name, size, mode = 0o644) {
    const buf = Buffer.alloc(512);
    buf.write(name, 0, 100, 'utf8');
    buf.write((mode & 0o7777).toString(8).padStart(7, '0') + '\0', 100, 8, 'ascii');
    buf.write('0000000\0', 108, 8, 'ascii');
    buf.write('0000000\0', 116, 8, 'ascii');
    buf.write(size.toString(8).padStart(11, '0') + '\0', 124, 12, 'ascii');
    // Fixed mtime for deterministic output (2026-11-01 00:00:00 UTC)
    const mtime = 1793491200;
    buf.write(mtime.toString(8).padStart(11, '0') + '\0', 136, 12, 'ascii');
    buf.fill(' ', 148, 156);
    buf.write('0', 156, 1, 'ascii');
    buf.write('ustar\0', 257, 6, 'ascii');
    buf.write('00', 263, 2, 'ascii');

    let sum = 0;
    for (let i = 0; i < 512; i++) sum += buf[i];
    buf.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
    return buf;
}

function makeTarGz(entries) {
    const chunks = [];
    for (const { path: entryPath, content, mode } of entries) {
        const data = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
        chunks.push(createTarHeader(entryPath, data.length, mode || 0o644));
        chunks.push(data);
        const pad = (512 - (data.length % 512)) % 512;
        if (pad > 0) chunks.push(Buffer.alloc(pad));
    }
    chunks.push(Buffer.alloc(1024)); // EOF blocks
    return zlib.gzipSync(Buffer.concat(chunks), { level: 9 });
}

function computeHashes(buffer) {
    const shasum = crypto.createHash('sha1').update(buffer).digest('hex');
    const sha512 = crypto.createHash('sha512').update(buffer).digest('base64');
    return {
        shasum,
        integrity: `sha512-${sha512}`
    };
}

const PACKAGES = [
    // ==========================================
    // Tier 1: Synthetic baseline packages
    // ==========================================
    {
        name: 'pkg-single-a',
        version: '1.0.0',
        description: 'Synthetic single dependency package for tier1 benchmarks',
        main: 'index.js',
        files: {
            'package/index.js': 'module.exports = { name: "pkg-single-a", version: "1.0.0" };\n'
        },
        dependencies: {}
    },
    {
        name: 'pkg-diamond-bottom',
        version: '1.0.0',
        description: 'Synthetic diamond bottom dependency package',
        main: 'index.js',
        files: {
            'package/index.js': 'module.exports = { name: "pkg-diamond-bottom", version: "1.0.0" };\n'
        },
        dependencies: {}
    },
    {
        name: 'pkg-diamond-left',
        version: '1.0.0',
        description: 'Synthetic diamond left dependency package',
        main: 'index.js',
        files: {
            'package/index.js': 'const bottom = require("pkg-diamond-bottom"); module.exports = { name: "pkg-diamond-left", version: "1.0.0", bottom };\n'
        },
        dependencies: {
            'pkg-diamond-bottom': '^1.0.0'
        }
    },
    {
        name: 'pkg-diamond-right',
        version: '1.0.0',
        description: 'Synthetic diamond right dependency package',
        main: 'index.js',
        files: {
            'package/index.js': 'const bottom = require("pkg-diamond-bottom"); module.exports = { name: "pkg-diamond-right", version: "1.0.0", bottom };\n'
        },
        dependencies: {
            'pkg-diamond-bottom': '^1.0.0'
        }
    },

    // ==========================================
    // Tier 2: TypeScript CLI packages & shims
    // ==========================================
    {
        name: 'typescript',
        version: '5.3.3',
        description: 'TypeScript compiler mock for tier 2 CLI benchmarks',
        main: 'index.js',
        bin: {
            tsc: 'bin/tsc.js',
            tsserver: 'bin/tsserver.js'
        },
        files: {
            'package/index.js': 'module.exports = { version: "5.3.3" };\n',
            'package/bin/tsc.js': [
                '#!/usr/bin/env node',
                'const args = process.argv.slice(2);',
                'if (args.includes("--version")) {',
                '    console.log("Version 5.3.3");',
                '} else {',
                '    console.log("tsc compiler ran with args: " + args.join(" "));',
                '}',
                ''
            ].join('\n'),
            'package/bin/tsserver.js': [
                '#!/usr/bin/env node',
                'console.log("TypeScript language server started (v5.3.3)");',
                ''
            ].join('\n')
        },
        dependencies: {}
    },
    {
        name: 'commander',
        version: '11.0.0',
        description: 'Command-line interface framework mock for tier 2 benchmarks v11.0.0',
        main: 'index.js',
        files: {
            'package/index.js': [
                'class Command {',
                '    constructor(name = "") { this._name = name; this._options = []; }',
                '    name(n) { this._name = n; return this; }',
                '    version(v) { this._version = v; return this; }',
                '    description(d) { this._description = d; return this; }',
                '    option(flags, desc) { this._options.push({ flags, desc }); return this; }',
                '    parse(argv) { this.parsed = true; return this; }',
                '}',
                'module.exports = { Command, program: new Command("root") };',
                ''
            ].join('\n')
        },
        dependencies: {}
    },
    {
        name: 'commander',
        version: '11.1.0',
        description: 'Command-line interface framework mock for tier 2 benchmarks',
        main: 'index.js',
        files: {
            'package/index.js': [
                'class Command {',
                '    constructor(name = "") { this._name = name; this._options = []; }',
                '    name(n) { this._name = n; return this; }',
                '    version(v) { this._version = v; return this; }',
                '    description(d) { this._description = d; return this; }',
                '    option(flags, desc) { this._options.push({ flags, desc }); return this; }',
                '    parse(argv) { this.parsed = true; return this; }',
                '}',
                'module.exports = { Command, program: new Command("root") };',
                ''
            ].join('\n')
        },
        dependencies: {}
    },
    {
        name: 'mock-cli-helper',
        version: '1.0.0',
        description: 'Mock helper with executable binary and lifecycle scripts',
        main: 'index.js',
        bin: {
            'cli-helper': 'bin/helper.js'
        },
        scripts: {
            preinstall: 'node -e "console.log(\'mock-cli-helper preinstall running\')"',
            postinstall: 'node -e "console.log(\'mock-cli-helper postinstall running\')"'
        },
        hasInstallScript: true,
        files: {
            'package/index.js': 'module.exports = { helper: true, version: "1.0.0" };\n',
            'package/bin/helper.js': [
                '#!/usr/bin/env node',
                'const args = process.argv.slice(2);',
                'console.log("cli-helper args: " + JSON.stringify(args));',
                ''
            ].join('\n')
        },
        dependencies: {}
    },

    // ==========================================
    // Tier 2: Express HTTP backend service graph
    // ==========================================
    {
        name: 'express',
        version: '4.18.2',
        description: 'Fast, unopinionated, minimalist web framework mock for tier 2 benchmarks',
        main: 'index.js',
        dependencies: {
            'accepts': '^1.3.8',
            'mime-types': '^2.1.35',
            'debug': '^4.3.4',
            'depd': '^2.0.0'
        },
        files: {
            'package/index.js': [
                'const accepts = require("accepts");',
                'const mimeTypes = require("mime-types");',
                'const debug = require("debug")("express:main");',
                'const depd = require("depd")("express");',
                '',
                'function createApplication() {',
                '    const app = {',
                '        _routes: [],',
                '        _middlewares: [],',
                '        use(fn) { app._middlewares.push(fn); return app; },',
                '        get(path, handler) { app._routes.push({ method: "GET", path, handler }); return app; },',
                '        post(path, handler) { app._routes.push({ method: "POST", path, handler }); return app; },',
                '        listen(port, cb) {',
                '            if (cb) cb();',
                '            return { close(c) { if (c) c(); } };',
                '        }',
                '    };',
                '    return app;',
                '}',
                'module.exports = createApplication;',
                ''
            ].join('\n')
        }
    },
    {
        name: 'body-parser',
        version: '1.20.2',
        description: 'Node.js body parsing middleware mock',
        main: 'index.js',
        dependencies: {
            'bytes': '^3.1.2',
            'raw-body': '^2.5.2'
        },
        files: {
            'package/index.js': [
                'const bytes = require("bytes");',
                'const rawBody = require("raw-body");',
                'module.exports = {',
                '    json: (opts) => (req, res, next) => { if (next) next(); },',
                '    urlencoded: (opts) => (req, res, next) => { if (next) next(); }',
                '};',
                ''
            ].join('\n')
        }
    },
    {
        name: 'cors',
        version: '2.8.4',
        description: 'Node.js CORS middleware mock v2.8.4',
        main: 'index.js',
        dependencies: {},
        files: {
            'package/index.js': [
                'module.exports = (opts) => (req, res, next) => { if (next) next(); };',
                ''
            ].join('\n')
        }
    },
    {
        name: 'cors',
        version: '2.8.5',
        description: 'Node.js CORS middleware mock',
        main: 'index.js',
        dependencies: {},
        files: {
            'package/index.js': [
                'module.exports = (opts) => (req, res, next) => { if (next) next(); };',
                ''
            ].join('\n')
        }
    },
    {
        name: 'cookie-parser',
        version: '1.4.6',
        description: 'Cookie parsing middleware mock',
        main: 'index.js',
        dependencies: {},
        files: {
            'package/index.js': [
                'module.exports = (secret) => (req, res, next) => { req.cookies = {}; if (next) next(); };',
                ''
            ].join('\n')
        }
    },
    {
        name: 'accepts',
        version: '1.3.8',
        description: 'Higher-level content negotiation mock',
        main: 'index.js',
        dependencies: {
            'mime-types': '^2.1.35'
        },
        files: {
            'package/index.js': [
                'const mimeTypes = require("mime-types");',
                'module.exports = (req) => ({',
                '    type: (types) => types[0] || false,',
                '    charsets: () => ["utf-8"]',
                '});',
                ''
            ].join('\n')
        }
    },
    {
        name: 'mime-types',
        version: '2.1.35',
        description: 'The ultimate javascript content-type utility mock',
        main: 'index.js',
        dependencies: {
            'mime-db': '^1.52.0'
        },
        files: {
            'package/index.js': [
                'const db = require("mime-db");',
                'module.exports = {',
                '    lookup: (path) => db["json"] || false,',
                '    contentType: (type) => "application/json; charset=utf-8"',
                '};',
                ''
            ].join('\n')
        }
    },
    {
        name: 'mime-db',
        version: '1.52.0',
        description: 'Media Type Database mock',
        main: 'index.js',
        dependencies: {},
        files: {
            'package/index.js': [
                'module.exports = {',
                '    "json": "application/json",',
                '    "html": "text/html",',
                '    "txt": "text/plain"',
                '};',
                ''
            ].join('\n')
        }
    },
    {
        name: 'debug',
        version: '4.3.4',
        description: 'Small debugging utility mock',
        main: 'index.js',
        dependencies: {},
        files: {
            'package/index.js': [
                'module.exports = (namespace) => {',
                '    const fn = (...args) => {};',
                '    fn.enabled = false;',
                '    return fn;',
                '};',
                ''
            ].join('\n')
        }
    },
    {
        name: 'depd',
        version: '2.0.0',
        description: 'Deprecate all them things mock',
        main: 'index.js',
        dependencies: {},
        files: {
            'package/index.js': [
                'module.exports = (namespace) => (msg) => {};',
                ''
            ].join('\n')
        }
    },
    {
        name: 'bytes',
        version: '3.1.2',
        description: 'Utility to parse a string bytes to bytes and vice-versa mock',
        main: 'index.js',
        dependencies: {},
        files: {
            'package/index.js': [
                'module.exports = (val) => (typeof val === "number" ? `${val}B` : 1024);',
                ''
            ].join('\n')
        }
    },
    {
        name: 'raw-body',
        version: '2.5.2',
        description: 'Get and validate the raw body of a readable stream mock',
        main: 'index.js',
        dependencies: {
            'bytes': '^3.1.2'
        },
        files: {
            'package/index.js': [
                'const bytes = require("bytes");',
                'module.exports = (stream) => Promise.resolve(Buffer.alloc(0));',
                ''
            ].join('\n')
        }
    },

    // ==========================================
    // Lifecycle & Credential Scrubbing Inspector
    // ==========================================
    {
        name: 'lifecycle-inspector',
        version: '1.0.0',
        description: 'Lifecycle hook inspector for differential environment & credential testing',
        main: 'index.js',
        scripts: {
            preinstall: 'node inspect.js preinstall',
            install: 'node inspect.js install',
            postinstall: 'node inspect.js postinstall'
        },
        hasInstallScript: true,
        files: {
            'package/index.js': 'module.exports = { name: "lifecycle-inspector" };\n',
            'package/inspect.js': [
                'const fs = require("fs");',
                'const path = require("path");',
                'const event = process.argv[2] || process.env.npm_lifecycle_event || "unknown";',
                'const targetFile = path.resolve(process.env.INIT_CWD || process.cwd(), ".lifecycle-" + event + ".json");',
                'const dump = {',
                '    event,',
                '    INIT_CWD: process.env.INIT_CWD,',
                '    NODE: process.env.NODE || process.env.npm_node_execpath,',
                '    npm_lifecycle_event: process.env.npm_lifecycle_event,',
                '    npm_package_name: process.env.npm_package_name,',
                '    npm_package_version: process.env.npm_package_version,',
                '    PATH: process.env.PATH,',
                '    envKeys: Object.keys(process.env),',
                '    fullEnv: { ...process.env }',
                '};',
                'fs.writeFileSync(targetFile, JSON.stringify(dump, null, 2), "utf8");',
                'console.log("[lifecycle-inspector] Dumped " + event + " to " + targetFile);',
                ''
            ].join('\n')
        },
        dependencies: {}
    }
];

const STORAGE_DIR = path.resolve(__dirname, 'storage');

function build() {
    if (!fs.existsSync(STORAGE_DIR)) {
        fs.mkdirSync(STORAGE_DIR, { recursive: true });
    }

    // Group by package name
    const packagesByName = {};
    for (const pkg of PACKAGES) {
        if (!packagesByName[pkg.name]) packagesByName[pkg.name] = [];
        packagesByName[pkg.name].push(pkg);
    }

    for (const [pkgName, versions] of Object.entries(packagesByName)) {
        const pkgDir = path.join(STORAGE_DIR, pkgName);
        if (!fs.existsSync(pkgDir)) fs.mkdirSync(pkgDir, { recursive: true });

        const packument = {
            _id: pkgName,
            name: pkgName,
            'dist-tags': {
                latest: versions[versions.length - 1].version
            },
            versions: {},
            modified: '2026-11-01T00:00:00.000Z'
        };

        for (const v of versions) {
            const pkgJsonContent = {
                name: v.name,
                version: v.version,
                description: v.description,
                main: v.main,
                dependencies: v.dependencies || {}
            };

            if (v.bin) pkgJsonContent.bin = v.bin;
            if (v.scripts) pkgJsonContent.scripts = v.scripts;
            if (v.devDependencies) pkgJsonContent.devDependencies = v.devDependencies;
            if (v.peerDependencies) pkgJsonContent.peerDependencies = v.peerDependencies;
            if (v.engines) pkgJsonContent.engines = v.engines;
            if (v.os) pkgJsonContent.os = v.os;
            if (v.cpu) pkgJsonContent.cpu = v.cpu;

            const entries = [
                {
                    path: 'package/package.json',
                    content: JSON.stringify(pkgJsonContent, null, 2) + '\n',
                    mode: 0o644
                }
            ];

            for (const [filePath, content] of Object.entries(v.files || {})) {
                const isExecutable = filePath.includes('/bin/') || filePath.endsWith('.sh') || filePath.endsWith('.js');
                entries.push({
                    path: filePath,
                    content,
                    mode: isExecutable ? 0o755 : 0o644
                });
            }

            const tarGz = makeTarGz(entries);
            const tarballFileName = `${v.name}-${v.version}.tgz`;
            const tarballFilePath = path.join(pkgDir, tarballFileName);
            fs.writeFileSync(tarballFilePath, tarGz);

            const { shasum, integrity } = computeHashes(tarGz);

            const hasInstallScript = Boolean(
                v.hasInstallScript ||
                (v.scripts && (v.scripts.install || v.scripts.postinstall || v.scripts.preinstall))
            );

            packument.versions[v.version] = {
                name: v.name,
                version: v.version,
                description: v.description,
                main: v.main,
                dependencies: v.dependencies || {},
                devDependencies: v.devDependencies || {},
                peerDependencies: v.peerDependencies || {},
                bin: v.bin,
                scripts: v.scripts,
                hasInstallScript,
                dist: {
                    shasum,
                    integrity,
                    tarball: `http://127.0.0.1:4873/${v.name}/-/${tarballFileName}`
                }
            };

            console.log(`[Built] ${v.name}@${v.version} -> ${tarballFileName} (sha512: ${integrity.slice(0, 20)}...)`);
        }

        const metadataPath = path.join(pkgDir, 'metadata.json');
        fs.writeFileSync(metadataPath, JSON.stringify(packument, null, 2) + '\n');
        console.log(`[Metadata] ${pkgName} -> metadata.json written`);
    }

    console.log(`Successfully built ${PACKAGES.length} packages into ${STORAGE_DIR}`);
}

build();
