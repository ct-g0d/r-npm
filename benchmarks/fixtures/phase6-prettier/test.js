const prettier = require('prettier');
if (typeof prettier.format !== 'function') {
    console.error('prettier export failure');
    process.exit(1);
}
console.log('phase6-prettier test passed (Prettier v' + prettier.version + ')');
