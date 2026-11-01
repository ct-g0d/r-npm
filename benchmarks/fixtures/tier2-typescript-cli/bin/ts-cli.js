#!/usr/bin/env node
const { program } = require('commander');
const ts = require('typescript');
const { helper } = require('mock-cli-helper');

const args = process.argv.slice(2);
console.log('ts-cli executed successfully');
console.log('typescript version: ' + ts.version);
console.log('helper loaded: ' + helper);
console.log('args received: ' + JSON.stringify(args));
