const assert = require('assert');
const express = require('express');
const React = require('react');
const ReactDOM = require('react-dom');
const chalk = require('chalk');
const _ = require('lodash');

assert(typeof express === 'function', 'express must export a factory function');
assert(typeof React.createElement === 'function', 'React must export createElement');
assert(typeof ReactDOM.render === 'function', 'ReactDOM must export render');
assert(typeof chalk.green === 'function', 'chalk must export green');
assert(_.isArray([1, 2, 3]), 'lodash.isArray must work');
assert.strictEqual(_.version, '4.17.21', 'lodash version must match 4.17.21');

console.log('All real-world ecosystem tests passed.');
