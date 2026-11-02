const fs = require('fs');
const path = require('path');

const distDir = path.resolve(__dirname, 'dist');
fs.mkdirSync(distDir, { recursive: true });

fs.writeFileSync(
    path.join(distDir, 'postinstall-ok.txt'),
    `Postinstall completed at ${new Date().toISOString()}\n`,
    'utf8'
);

console.log('Real-world ecosystem postinstall hook completed.');
