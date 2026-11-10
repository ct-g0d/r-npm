const fs = require('fs');

const baseline = require('./baseline_results.json');

let md = `# npm Command Coverage Analysis (npm 11.20 / Node 26 Parity)

## Overview

This document tracks command parity between \`rnpm\` (master baseline) and \`npm\` 11.20.0 running on Windows with Node v26.13.0.
Every command in \`npm help\` / \`npm <cmd> --help\` as well as deprecated/legacy commands (e.g. \`set-script\`, \`bin\`) was evaluated by executing both tools against identical fixtures in fresh temporary directories, comparing stdout, stderr, process exit code, and filesystem mutations.

## Command Parity Matrix (Master Baseline)

| Command | Aliases | Status | What Differs | How Checked |
| :--- | :--- | :--- | :--- | :--- |
`;

for (const item of baseline) {
  const aliases = item.aliases ? `\`${item.aliases}\`` : '-';
  const diffs = item.diffs.replace(/\|/g, '\\|').replace(/\n/g, ' ');
  md += `| \`${item.command}\` | ${aliases} | **${item.status}** | ${diffs} | ${item.checkMethod} |\n`;
}

md += `
## Summary Statistics (Master Baseline)

- **Total Commands Evaluated**: ${baseline.length}
- **Matching**: ${baseline.filter(b => b.status === 'matching').length}
- **Partial**: ${baseline.filter(b => b.status === 'partial').length}
- **Missing**: ${baseline.filter(b => b.status === 'missing').length}

## Next Steps

1. Implement missing commands and subcommands:
   - \`cache\` (\`add\`, \`ls\`)
   - Re-architect commands into isolated modules under \`crates/rnpm-cli/src/commands/<name>.rs\` with one-line dispatch entries in \`main.rs\`.
2. Align priority local dev and CI workflows (\`cache\`, \`config\`, \`pkg\`, \`outdated\`, \`update\`, \`version\`, \`pack\`, \`prune\`, \`dedupe\`, \`rebuild\`, \`link\`, \`init -y\`, \`query\`, \`install-test\`, \`shrinkwrap\`, \`sbom\`).
3. Align registry-read commands (\`view\`, \`search\`, \`dist-tag\`, \`owner\`, \`ping\`, \`whoami\`).
4. Align registry-write commands with safety guards (\`publish\`, \`deprecate\`, \`access\`, \`token\`, \`star\`).
`;

fs.writeFileSync('docs/npm-command-coverage.md', md, 'utf8');
console.log('docs/npm-command-coverage.md generated successfully.');
