const fs = require('fs');
const path = require('path');
const candidates01 = [
  path.resolve(__dirname, '../pkg-01/dist/pkg-01-artifact.json'),
  path.resolve(__dirname, '../../packages/pkg-01/dist/pkg-01-artifact.json'),
  path.resolve(__dirname, '../../dist/pkg-01-artifact.json')
];
const found01 = candidates01.find(function(c) { return fs.existsSync(c); });
const candidates15 = [
  path.resolve(__dirname, '../pkg-15/dist/pkg-15-artifact.json'),
  path.resolve(__dirname, '../../packages/pkg-15/dist/pkg-15-artifact.json'),
  path.resolve(__dirname, '../../dist/pkg-15-artifact.json')
];
const found15 = candidates15.find(function(c) { return fs.existsSync(c); });
if (!found01 || !found15) { throw new Error('Missing required artifacts: pkg-01=' + found01 + ', pkg-15=' + found15); }
fs.mkdirSync('dist', { recursive: true });
const rootDist = path.resolve(__dirname, '../../dist');
fs.mkdirSync(rootDist, { recursive: true });
const data = JSON.stringify({ name: 'pkg-49', sequence: 49, verified01: found01, verified15: found15, timestamp: Date.now() }, null, 2) + '\n';
fs.writeFileSync('dist/pkg-49-artifact.json', data);
fs.writeFileSync(path.join(rootDist, 'pkg-49-artifact.json'), data);
console.log('pkg-49 artifact created');
