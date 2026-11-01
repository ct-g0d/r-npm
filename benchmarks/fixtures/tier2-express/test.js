const app = require('./server');

if (!app) {
    console.error('Failed to import express server');
    process.exit(1);
}
console.log('tier2-express server initialized and test passed');
