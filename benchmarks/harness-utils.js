/**
 * harness-utils.js
 * Normalization, tree hashing, lockfile comparison, and statistical utilities
 * for differential testing and benchmarking.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function sha256(content) {
    return crypto.createHash('sha256').update(content).digest('hex');
}

function normalizeNewlines(content) {
    return content.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
}

function sortObjectKeys(obj) {
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
        return obj;
    }
    const sorted = {};
    for (const key of Object.keys(obj).sort()) {
        sorted[key] = sortObjectKeys(obj[key]);
    }
    return sorted;
}

function normalizeJsonContent(content) {
    try {
        const parsed = JSON.parse(content);
        const sorted = sortObjectKeys(parsed);
        return JSON.stringify(sorted, null, 2) + '\n';
    } catch {
        return content;
    }
}

/**
 * Recursively scans node_modules, normalizing files and producing a canonical tree digest.
 */
function getNormalizedTree(nodeModulesDir) {
    if (!fs.existsSync(nodeModulesDir)) {
        return {
            digest: null,
            totalBytes: 0,
            fileCount: 0,
            files: []
        };
    }

    const files = [];
    let totalBytes = 0;

    function walk(currentDir, relativePrefix) {
        const entries = fs.readdirSync(currentDir, { withFileTypes: true });
        for (const entry of entries) {
            // Ignore npm's hidden internal lockfile and temporary files
            if (entry.name === '.package-lock.json' || entry.name === '.staging' || entry.name === '.cache') {
                continue;
            }

            const fullPath = path.join(currentDir, entry.name);
            const posixRelPath = (relativePrefix ? `${relativePrefix}/` : '') + entry.name;

            if (entry.isDirectory()) {
                walk(fullPath, posixRelPath);
            } else if (entry.isSymbolicLink()) {
                try {
                    const linkTarget = fs.readlinkSync(fullPath).replace(/\\/g, '/');
                    const hash = sha256(`symlink:${linkTarget}`);
                    files.push({ path: posixRelPath, type: 'symlink', target: linkTarget, hash, size: 0 });
                } catch {
                    // Reparse point / junction fallback
                    files.push({ path: posixRelPath, type: 'junction', hash: sha256('junction'), size: 0 });
                }
            } else if (entry.isFile()) {
                const stat = fs.statSync(fullPath);
                let content = fs.readFileSync(fullPath);
                totalBytes += stat.size;

                // Normalize text files, JSON, and executable shims
                let hash;
                if (posixRelPath.startsWith('.bin/')) {
                    // Executable shims: normalize to shim name to account for generator implementation differences
                    hash = sha256(`shim:${entry.name}`);
                } else if (entry.name === 'package.json') {
                    const normalizedJson = normalizeJsonContent(content.toString('utf8'));
                    hash = sha256(Buffer.from(normalizedJson, 'utf8'));
                } else if (/\.(js|mjs|cjs|ts|json|md|txt|yml|yaml|css|html)$/i.test(entry.name)) {
                    const normalizedText = normalizeNewlines(content.toString('utf8'));
                    hash = sha256(Buffer.from(normalizedText, 'utf8'));
                } else {
                    hash = sha256(content);
                }

                files.push({
                    path: posixRelPath,
                    type: 'file',
                    size: stat.size,
                    hash
                });
            }
        }
    }

    walk(nodeModulesDir, '');
    files.sort((a, b) => a.path.localeCompare(b.path));

    const manifest = files.map(f => `${f.path}:${f.type}:${f.hash}`).join('\n');
    const masterDigest = files.length > 0 ? sha256(manifest) : null;

    return {
        digest: masterDigest,
        totalBytes,
        fileCount: files.length,
        files
    };
}

/**
 * Reads, validates, and normalizes a package-lock.json v3 file.
 */
function getNormalizedLockfile(lockfilePath) {
    if (!fs.existsSync(lockfilePath)) {
        return {
            digest: null,
            content: null,
            version: null
        };
    }

    const raw = fs.readFileSync(lockfilePath, 'utf8');
    const parsed = JSON.parse(raw);
    const sorted = sortObjectKeys(parsed);
    const canonicalString = JSON.stringify(sorted, null, 2) + '\n';
    const digest = sha256(Buffer.from(canonicalString, 'utf8'));

    return {
        digest,
        parsed: sorted,
        canonicalString,
        version: parsed.lockfileVersion
    };
}

/**
 * Compare two node_modules directories.
 */
function compareTrees(dirA, dirB) {
    const treeA = getNormalizedTree(dirA);
    const treeB = getNormalizedTree(dirB);

    const mapA = new Map(treeA.files.map(f => [f.path, f]));
    const mapB = new Map(treeB.files.map(f => [f.path, f]));

    const mismatches = [];

    for (const [p, itemA] of mapA.entries()) {
        const itemB = mapB.get(p);
        if (!itemB) {
            mismatches.push(`Missing in Target: ${p}`);
        } else if (itemA.hash !== itemB.hash) {
            mismatches.push(`Content mismatch in ${p}: ${itemA.hash.slice(0, 8)} vs ${itemB.hash.slice(0, 8)}`);
        }
    }

    for (const p of mapB.keys()) {
        if (!mapA.has(p)) {
            mismatches.push(`Extra in Target: ${p}`);
        }
    }

    return {
        match: mismatches.length === 0,
        mismatches,
        digestA: treeA.digest,
        digestB: treeB.digest,
        totalBytesA: treeA.totalBytes,
        totalBytesB: treeB.totalBytes
    };
}

/**
 * Compare two package-lock.json files.
 */
function compareLockfiles(lockPathA, lockPathB) {
    const lockA = getNormalizedLockfile(lockPathA);
    const lockB = getNormalizedLockfile(lockPathB);

    const mismatches = [];

    if (!lockA.parsed && !lockB.parsed) {
        return { match: true, mismatches: [] };
    }
    if (!lockA.parsed) {
        return { match: false, mismatches: ['Reference lockfile is missing'] };
    }
    if (!lockB.parsed) {
        return { match: false, mismatches: ['Target lockfile is missing'] };
    }

    if (lockA.version !== lockB.version) {
        mismatches.push(`Lockfile version mismatch: ${lockA.version} vs ${lockB.version}`);
    }

    const pkgsA = lockA.parsed.packages || {};
    const pkgsB = lockB.parsed.packages || {};

    const allKeys = new Set([...Object.keys(pkgsA), ...Object.keys(pkgsB)]);
    for (const key of Array.from(allKeys).sort()) {
        const a = pkgsA[key];
        const b = pkgsB[key];
        if (!a) {
            mismatches.push(`Extra package in Target lockfile: "${key}"`);
        } else if (!b) {
            mismatches.push(`Missing package in Target lockfile: "${key}"`);
        } else {
            if (a.version !== b.version) {
                mismatches.push(`Version mismatch in "${key}": ${a.version} vs ${b.version}`);
            }
            if (a.integrity !== b.integrity) {
                mismatches.push(`Integrity mismatch in "${key}": ${a.integrity} vs ${b.integrity}`);
            }
            // Check dependencies
            const depsA = JSON.stringify(a.dependencies || {});
            const depsB = JSON.stringify(b.dependencies || {});
            if (depsA !== depsB) {
                mismatches.push(`Dependencies mismatch in "${key}": ${depsA} vs ${depsB}`);
            }
        }
    }

    return {
        match: mismatches.length === 0,
        mismatches,
        digestA: lockA.digest,
        digestB: lockB.digest
    };
}

/**
 * Statistical calculations: median, min, max, iqr, mean, rsd_pct, mad.
 */
function computeStats(values) {
    if (!values || values.length === 0) {
        return { median: 0, min: 0, max: 0, iqr: 0, mean: 0, rsd_pct: 0, mad: 0 };
    }

    const sorted = [...values].sort((a, b) => a - b);
    const n = sorted.length;
    const min = sorted[0];
    const max = sorted[n - 1];

    function percentile(p) {
        const index = (n - 1) * p;
        const lower = Math.floor(index);
        const upper = Math.ceil(index);
        const weight = index - lower;
        return sorted[lower] * (1 - weight) + sorted[upper] * weight;
    }

    const median = percentile(0.5);
    const q1 = percentile(0.25);
    const q3 = percentile(0.75);
    const iqr = q3 - q1;

    const sum = sorted.reduce((acc, v) => acc + v, 0);
    const mean = sum / n;

    const variance = sorted.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) / (n > 1 ? n - 1 : 1);
    const stdDev = Math.sqrt(variance);
    const rsd_pct = mean > 0 ? (stdDev / mean) * 100 : 0;

    // Median Absolute Deviation (MAD)
    const absDevs = sorted.map(v => Math.abs(v - median)).sort((a, b) => a - b);
    const madIndex = (n - 1) * 0.5;
    const madLower = Math.floor(madIndex);
    const madUpper = Math.ceil(madIndex);
    const madWeight = madIndex - madLower;
    const mad = absDevs[madLower] * (1 - madWeight) + absDevs[madUpper] * madWeight;

    return {
        median: Math.round(median * 100) / 100,
        min: Math.round(min * 100) / 100,
        max: Math.round(max * 100) / 100,
        iqr: Math.round(iqr * 100) / 100,
        mean: Math.round(mean * 100) / 100,
        rsd_pct: Math.round(rsd_pct * 100) / 100,
        mad: Math.round(mad * 100) / 100
    };
}

// CLI handler if invoked directly
if (require.main === module) {
    const command = process.argv[2];
    const args = process.argv.slice(3);

    if (command === 'digest-tree') {
        const res = getNormalizedTree(path.resolve(args[0]));
        console.log(JSON.stringify(res, null, 2));
    } else if (command === 'digest-lockfile') {
        const res = getNormalizedLockfile(path.resolve(args[0]));
        console.log(JSON.stringify({
            digest: res.digest,
            version: res.version,
            packageCount: res.parsed && res.parsed.packages ? Object.keys(res.parsed.packages).length : 0
        }, null, 2));
    } else if (command === 'compare-trees') {
        const res = compareTrees(path.resolve(args[0]), path.resolve(args[1]));
        console.log(JSON.stringify(res, null, 2));
    } else if (command === 'compare-lockfiles') {
        const res = compareLockfiles(path.resolve(args[0]), path.resolve(args[1]));
        console.log(JSON.stringify(res, null, 2));
    } else if (command === 'stats') {
        const nums = args.map(Number);
        console.log(JSON.stringify(computeStats(nums), null, 2));
    } else {
        console.error('Unknown command. Available: digest-tree, digest-lockfile, compare-trees, compare-lockfiles, stats');
        process.exit(1);
    }
}

module.exports = {
    getNormalizedTree,
    getNormalizedLockfile,
    compareTrees,
    compareLockfiles,
    computeStats,
    sha256,
    normalizeNewlines,
    sortObjectKeys
};
