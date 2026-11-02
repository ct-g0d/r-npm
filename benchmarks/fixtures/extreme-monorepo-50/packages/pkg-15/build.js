const fs = require('fs');
const path = require('path');
const candidates = [
  path.resolve(__dirname, '../pkg-01/dist/pkg-01-artifact.json'),
  path.resolve(__dirname, '../../packages/pkg-01/dist/pkg-01-artifact.json'),
  path.resolve(__dirname, '../../dist/pkg-01-artifact.json')
];
const found = candidates.find(function(c) { return fs.existsSync(c); });
if (!found) { throw new Error('pkg-01-artifact.json not found in ' + candidates.join(', ')); }
fs.mkdirSync('dist', { recursive: true });
const rootDist = path.resolve(__dirname, '../../dist');
fs.mkdirSync(rootDist, { recursive: true });
const data = JSON.stringify({ name: 'pkg-15', sequence: 15, verifiedFrom: found, timestamp: Date.now() }, null, 2) + '\n';
fs.writeFileSync('dist/pkg-15-artifact.json', data);
fs.writeFileSync(path.join(rootDist, 'pkg-15-artifact.json'), data);
console.log('pkg-15 artifact created');
