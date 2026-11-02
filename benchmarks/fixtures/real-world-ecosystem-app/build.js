const fs = require('fs');
const path = require('path');

const distDir = path.resolve(__dirname, 'dist');
fs.mkdirSync(distDir, { recursive: true });

const manifest = {
    app: 'real-world-ecosystem-app',
    builtAt: new Date().toISOString(),
    artifacts: ['bundle.js', 'styles.css']
};

fs.writeFileSync(
    path.join(distDir, 'build-manifest.json'),
    JSON.stringify(manifest, null, 2) + '\n',
    'utf8'
);

console.log('Build pipeline completed successfully.');
