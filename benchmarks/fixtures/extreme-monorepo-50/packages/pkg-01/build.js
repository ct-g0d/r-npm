const fs = require('fs');
const path = require('path');
fs.mkdirSync('dist', { recursive: true });
const rootDist = path.resolve(__dirname, '../../dist');
fs.mkdirSync(rootDist, { recursive: true });
const data = JSON.stringify({ name: 'pkg-01', sequence: 1, timestamp: Date.now() }, null, 2) + '\n';
fs.writeFileSync('dist/pkg-01-artifact.json', data);
fs.writeFileSync(path.join(rootDist, 'pkg-01-artifact.json'), data);
console.log('pkg-01 artifact created');
