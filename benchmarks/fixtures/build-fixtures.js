const fs = require('fs');
const path = require('path');

const repoRoot = path.resolve(__dirname, '../..');
const fixturesRoot = path.join(repoRoot, 'benchmarks', 'fixtures');

function pad(num) {
  return num < 10 ? '0' + num : '' + num;
}

// ==========================================
// 1. Extreme Monorepo 50
// ==========================================
const extremeRoot = path.join(fixturesRoot, 'extreme-monorepo-50');
const extremePackages = path.join(extremeRoot, 'packages');

// Clean fixture if exists
if (fs.existsSync(extremeRoot)) {
  fs.rmSync(extremeRoot, { recursive: true, force: true });
}
fs.mkdirSync(extremePackages, { recursive: true });

// Root package.json
const rootPkg = {
  name: 'extreme-monorepo-50',
  version: '1.0.0',
  description: 'Extreme 52-package workspace monorepo fixture with multi-tier DAG, hoisting contention, and cross-package artifact pipelines',
  private: true,
  workspaces: [
    'packages/*'
  ],
  devDependencies: {
    typescript: '^5.3.3',
    prettier: '^3.2.5'
  }
};

fs.writeFileSync(path.join(extremeRoot, 'package.json'), JSON.stringify(rootPkg, null, 2) + '\n');
fs.writeFileSync(path.join(extremeRoot, 'README.md'), '# Extreme Monorepo 50\n\nA 52-package workspace fixture testing multi-tier DAG resolution, hoisting contention, and chained lifecycle scripts.\n');

// 52 workspace packages: pkg-01 to pkg-52
for (let i = 1; i <= 52; i++) {
  const name = 'pkg-' + pad(i);
  const pkgDir = path.join(extremePackages, name);
  fs.mkdirSync(pkgDir, { recursive: true });

  let tier = 0;
  if (i >= 1 && i <= 10) tier = 0;
  else if (i >= 11 && i <= 25) tier = 1;
  else if (i >= 26 && i <= 40) tier = 2;
  else if (i >= 41 && i <= 48) tier = 3;
  else if (i >= 49 && i <= 51) tier = 4;
  else if (i === 52) tier = 5;

  const pkgJson = {
    name: name,
    version: '1.0.0',
    description: `${name} (Tier ${tier}) workspace package`,
    main: 'index.js',
    dependencies: {},
    scripts: {}
  };

  // Tier-specific dependencies
  if (tier === 0) {
    // Core base libraries
    if (i === 1) {
      pkgJson.dependencies['bytes'] = '^3.1.2';
      const buildJs = [
        "const fs = require('fs');",
        "const path = require('path');",
        "fs.mkdirSync('dist', { recursive: true });",
        "const rootDist = path.resolve(__dirname, '../../dist');",
        "fs.mkdirSync(rootDist, { recursive: true });",
        "const data = JSON.stringify({ name: 'pkg-01', sequence: 1, timestamp: Date.now() }, null, 2) + '\\n';",
        "fs.writeFileSync('dist/pkg-01-artifact.json', data);",
        "fs.writeFileSync(path.join(rootDist, 'pkg-01-artifact.json'), data);",
        "console.log('pkg-01 artifact created');"
      ].join('\n') + '\n';
      fs.writeFileSync(path.join(pkgDir, 'build.js'), buildJs);
      pkgJson.scripts = {
        postinstall: 'node build.js',
        prepare: 'node build.js'
      };
    } else if (i === 2) {
      pkgJson.dependencies['chalk'] = '^4.1.2';
    } else if (i === 3) {
      pkgJson.dependencies['mime-types'] = '^2.1.35';
    } else if (i === 4) {
      pkgJson.dependencies['supports-color'] = '^7.2.0';
    } else if (i === 5) {
      pkgJson.dependencies['raw-body'] = '^2.5.2';
    }
  } else if (tier === 1) {
    // Utils & middleware: depends on Tier 0 via semver ranges
    const protos = ['^1.0.0', '~1.0.0', '*'];
    const p1 = ((i - 11) % 10) + 1;
    const p2 = ((i - 10) % 10) + 1;
    pkgJson.dependencies['pkg-' + pad(p1)] = protos[i % 3];
    pkgJson.dependencies['pkg-' + pad(p2)] = protos[(i + 1) % 3];

    // Hoisting of commander
    if (i === 11 || i === 12) {
      pkgJson.dependencies['commander'] = '^11.1.0';
    }

    if (i === 15) {
      // Must depend on pkg-01
      pkgJson.dependencies['pkg-01'] = '^1.0.0';
      const buildJs = [
        "const fs = require('fs');",
        "const path = require('path');",
        "const candidates = [",
        "  path.resolve(__dirname, '../pkg-01/dist/pkg-01-artifact.json'),",
        "  path.resolve(__dirname, '../../packages/pkg-01/dist/pkg-01-artifact.json'),",
        "  path.resolve(__dirname, '../../dist/pkg-01-artifact.json')",
        "];",
        "const found = candidates.find(function(c) { return fs.existsSync(c); });",
        "if (!found) { throw new Error('pkg-01-artifact.json not found in ' + candidates.join(', ')); }",
        "fs.mkdirSync('dist', { recursive: true });",
        "const rootDist = path.resolve(__dirname, '../../dist');",
        "fs.mkdirSync(rootDist, { recursive: true });",
        "const data = JSON.stringify({ name: 'pkg-15', sequence: 15, verifiedFrom: found, timestamp: Date.now() }, null, 2) + '\\n';",
        "fs.writeFileSync('dist/pkg-15-artifact.json', data);",
        "fs.writeFileSync(path.join(rootDist, 'pkg-15-artifact.json'), data);",
        "console.log('pkg-15 artifact created');"
      ].join('\n') + '\n';
      fs.writeFileSync(path.join(pkgDir, 'build.js'), buildJs);
      pkgJson.scripts = {
        postinstall: 'node build.js',
        prepare: 'node build.js'
      };
    }
  } else if (tier === 2) {
    // Services & components: diamond dependencies on Tier 0 and Tier 1
    const protos = ['^1.0.0', '~1.0.0', '*'];
    const t1_a = 11 + ((i - 26) % 15);
    const t1_b = 11 + ((i - 25) % 15);
    pkgJson.dependencies['pkg-' + pad(t1_a)] = protos[i % 3];
    pkgJson.dependencies['pkg-' + pad(t1_b)] = protos[(i + 1) % 3];

    // Also direct Tier 0 dep to form diamond dependency
    const t0 = ((i - 26) % 10) + 1;
    pkgJson.dependencies['pkg-' + pad(t0)] = protos[(i + 2) % 3];

    // Hoisting of lodash
    if (i === 26 || i === 27) {
      pkgJson.dependencies['lodash'] = '^4.17.21';
    } else if (i === 35) {
      pkgJson.dependencies['express'] = '^4.18.2';
    }
  } else if (tier === 3) {
    // Feature modules: depending on Tier 1 and Tier 2
    const protos = ['^1.0.0', '~1.0.0', '*'];
    const t1 = 11 + ((i - 41) % 15);
    const t2 = 26 + ((i - 41) % 15);
    pkgJson.dependencies['pkg-' + pad(t1)] = protos[i % 3];
    pkgJson.dependencies['pkg-' + pad(t2)] = protos[(i + 1) % 3];

    // Hoisting of cors
    if (i === 41) {
      pkgJson.dependencies['pkg-15'] = '^1.0.0';
      pkgJson.dependencies['cors'] = '^2.8.5';
    } else if (i === 42) {
      pkgJson.dependencies['cors'] = '^2.8.5';
    }
  } else if (tier === 4) {
    // Applications & CLI
    const binDir = path.join(pkgDir, 'bin');
    fs.mkdirSync(binDir, { recursive: true });
    fs.writeFileSync(path.join(binDir, 'cli.js'), '#!/usr/bin/env node\nconsole.log("' + name + '-cli running successfully");\n');

    pkgJson.bin = {};
    pkgJson.bin[name + '-cli'] = './bin/cli.js';

    if (i === 49) {
      pkgJson.dependencies['pkg-01'] = '^1.0.0';
      pkgJson.dependencies['pkg-15'] = '^1.0.0';
      pkgJson.dependencies['pkg-41'] = '^1.0.0';
      pkgJson.dependencies['commander'] = '^11.1.0';
      pkgJson.dependencies['chalk'] = '^4.1.2';
      const buildJs = [
        "const fs = require('fs');",
        "const path = require('path');",
        "const candidates01 = [",
        "  path.resolve(__dirname, '../pkg-01/dist/pkg-01-artifact.json'),",
        "  path.resolve(__dirname, '../../packages/pkg-01/dist/pkg-01-artifact.json'),",
        "  path.resolve(__dirname, '../../dist/pkg-01-artifact.json')",
        "];",
        "const found01 = candidates01.find(function(c) { return fs.existsSync(c); });",
        "const candidates15 = [",
        "  path.resolve(__dirname, '../pkg-15/dist/pkg-15-artifact.json'),",
        "  path.resolve(__dirname, '../../packages/pkg-15/dist/pkg-15-artifact.json'),",
        "  path.resolve(__dirname, '../../dist/pkg-15-artifact.json')",
        "];",
        "const found15 = candidates15.find(function(c) { return fs.existsSync(c); });",
        "if (!found01 || !found15) { throw new Error('Missing required artifacts: pkg-01=' + found01 + ', pkg-15=' + found15); }",
        "fs.mkdirSync('dist', { recursive: true });",
        "const rootDist = path.resolve(__dirname, '../../dist');",
        "fs.mkdirSync(rootDist, { recursive: true });",
        "const data = JSON.stringify({ name: 'pkg-49', sequence: 49, verified01: found01, verified15: found15, timestamp: Date.now() }, null, 2) + '\\n';",
        "fs.writeFileSync('dist/pkg-49-artifact.json', data);",
        "fs.writeFileSync(path.join(rootDist, 'pkg-49-artifact.json'), data);",
        "console.log('pkg-49 artifact created');"
      ].join('\n') + '\n';
      fs.writeFileSync(path.join(pkgDir, 'build.js'), buildJs);
      pkgJson.scripts = {
        postinstall: 'node build.js',
        prepare: 'node build.js'
      };
    } else if (i === 50) {
      pkgJson.dependencies['pkg-42'] = '^1.0.0';
      pkgJson.dependencies['pkg-43'] = '^1.0.0';
      pkgJson.dependencies['pkg-26'] = '~1.0.0';
      pkgJson.dependencies['commander'] = '^11.1.0';
    } else if (i === 51) {
      pkgJson.dependencies['pkg-44'] = '~1.0.0';
      pkgJson.dependencies['pkg-45'] = '^1.0.0';
      pkgJson.dependencies['pkg-30'] = '^1.0.0';
      pkgJson.dependencies['commander'] = '^11.1.0';
    }
  } else if (tier === 5) {
    // Integration suite
    pkgJson.dependencies['pkg-01'] = '^1.0.0';
    pkgJson.dependencies['pkg-15'] = '^1.0.0';
    pkgJson.dependencies['pkg-26'] = '^1.0.0';
    pkgJson.dependencies['pkg-41'] = '^1.0.0';
    pkgJson.dependencies['pkg-49'] = '^1.0.0';
    pkgJson.dependencies['pkg-50'] = '^1.0.0';
    pkgJson.dependencies['pkg-51'] = '^1.0.0';
    pkgJson.scripts = {
      test: 'node -e "console.log(\'pkg-52 integration test suite running\')"'
    };
  }

  // Write package.json
  fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify(pkgJson, null, 2) + '\n');

  // Write index.js
  const indexContent = 'module.exports = {\n  name: "' + name + '",\n  tier: ' + tier + ',\n  version: "1.0.0"\n};\n';
  fs.writeFileSync(path.join(pkgDir, 'index.js'), indexContent);

  // Write README.md
  fs.writeFileSync(path.join(pkgDir, 'README.md'), '# ' + name + '\n\nTier ' + tier + ' workspace package.\n');
}

// ==========================================
// 2. Extreme Circular Monorepo
// ==========================================
const circularRoot = path.join(fixturesRoot, 'extreme-circular-monorepo');
const circularPackages = path.join(circularRoot, 'packages');
const circADir = path.join(circularPackages, 'circ-a');
const circBDir = path.join(circularPackages, 'circ-b');

if (fs.existsSync(circularRoot)) {
  fs.rmSync(circularRoot, { recursive: true, force: true });
}
fs.mkdirSync(circADir, { recursive: true });
fs.mkdirSync(circBDir, { recursive: true });

// Root package.json
const circularRootPkg = {
  name: 'extreme-circular-monorepo',
  version: '1.0.0',
  description: 'Circular workspace dependency fixture with mutual workspace:* links',
  private: true,
  workspaces: [
    'packages/*'
  ]
};
fs.writeFileSync(path.join(circularRoot, 'package.json'), JSON.stringify(circularRootPkg, null, 2) + '\n');
fs.writeFileSync(path.join(circularRoot, 'README.md'), '# Extreme Circular Monorepo\n\nA fixture containing circular workspace dependencies between circ-a and circ-b.\n');

// circ-a package.json
const circAPkg = {
  name: 'circ-a',
  version: '1.0.0',
  description: 'Circular workspace dependency participant A',
  main: 'index.js',
  dependencies: {
    'circ-b': 'workspace:*'
  }
};
fs.writeFileSync(path.join(circADir, 'package.json'), JSON.stringify(circAPkg, null, 2) + '\n');
fs.writeFileSync(path.join(circADir, 'index.js'), 'module.exports = { name: "circ-a", peer: "circ-b" };\n');

// circ-b package.json
const circBPkg = {
  name: 'circ-b',
  version: '1.0.0',
  description: 'Circular workspace dependency participant B',
  main: 'index.js',
  dependencies: {
    'circ-a': 'workspace:*'
  }
};
fs.writeFileSync(path.join(circBDir, 'package.json'), JSON.stringify(circBPkg, null, 2) + '\n');
fs.writeFileSync(path.join(circBDir, 'index.js'), 'module.exports = { name: "circ-b", peer: "circ-a" };\n');

console.log('All fixtures created successfully!');
