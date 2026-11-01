/**
 * build-packages.js
 * Generates synthetic package tarballs and packument metadata for the mock registry.
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
    for (const { path: entryPath, content } of entries) {
        const data = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
        chunks.push(createTarHeader(entryPath, data.length));
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

            const entries = [
                {
                    path: 'package/package.json',
                    content: JSON.stringify(pkgJsonContent, null, 2) + '\n'
                }
            ];

            for (const [filePath, content] of Object.entries(v.files || {})) {
                entries.push({ path: filePath, content });
            }

            const tarGz = makeTarGz(entries);
            const tarballFileName = `${v.name}-${v.version}.tgz`;
            const tarballFilePath = path.join(pkgDir, tarballFileName);
            fs.writeFileSync(tarballFilePath, tarGz);

            const { shasum, integrity } = computeHashes(tarGz);

            packument.versions[v.version] = {
                name: v.name,
                version: v.version,
                description: v.description,
                main: v.main,
                dependencies: v.dependencies || {},
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
