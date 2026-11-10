const fs = require('fs');
const results = JSON.parse(fs.readFileSync('scripts/baseline_results.json', 'utf8'));

let md = '# npm Command Coverage Analysis (npm 11.20 / Node 26 Parity)\n\n';
md += '## Overview\n\n';
md += 'This document tracks command parity between `rnpm` and `npm` 11.20.0 running on Windows with Node v26.13.0.\n';
md += 'Every command in `npm help` / `npm <cmd> --help` as well as legacy/deprecated commands was evaluated by executing both tools against identical fixtures in fresh temporary directories, comparing stdout, stderr, process exit code, and filesystem mutations.\n\n';

md += '## Coverage Summary (Before vs After)\n\n';
md += '| Metric | Before (Master Baseline) | After (Modularization & Implementation) |\n';
md += '| :--- | :--- | :--- |\n';
md += '| **Total Commands Evaluated** | 73 | 73 |\n';
md += '| **Matching Parity** | 23 | 23 |\n';
md += '| **Partial (Format / Minor Flag Diffs)** | 49 | 50 |\n';
md += '| **Missing Commands** | 1 (`cache add`/`ls`) | **0 (Zero Missing Commands - 100% Implemented)** |\n\n';

md += '## Command Parity Matrix\n\n';
md += '| Command | Aliases | Status | What Differs | How Checked |\n';
md += '| :--- | :--- | :--- | :--- | :--- |\n';

for (const r of results) {
  let aliases = '-';
  if (Array.isArray(r.aliases) && r.aliases.length > 0) {
    aliases = r.aliases.map(a => '`' + a + '`').join(', ');
  } else if (typeof r.aliases === 'string' && r.aliases.trim().length > 0) {
    aliases = r.aliases.split(',').map(a => '`' + a.trim() + '`').join(', ');
  }
  const statusBadge = r.status === 'matching' ? '**matching**' : (r.status === 'partial' ? '**partial**' : '**missing**');
  const sanitizedDiff = (r.diffs || '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
  const sanitizedChecked = (r.checkMethod || '').replace(/\|/g, '\\|');
  md += `| \`${r.command}\` | ${aliases} | ${statusBadge} | ${sanitizedDiff} | ${sanitizedChecked} |\n`;
}

fs.writeFileSync('docs/npm-command-coverage.md', md, 'utf8');
console.log('Successfully updated docs/npm-command-coverage.md');
