const ts = require('typescript');
const { program } = require('commander');
const { helper } = require('mock-cli-helper');

if (!ts.version || !program || !helper) {
    console.error('Failed to load dependencies');
    process.exit(1);
}
console.log('tier2-typescript-cli test passed');
