// Real-world application entrypoint
const express = require('express');
const React = require('react');
const ReactDOM = require('react-dom');
const chalk = require('chalk');
const _ = require('lodash');

const app = express();
const port = 3000;

app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        version: React.version,
        isArray: _.isArray([1, 2, 3])
    });
});

if (require.main === module) {
    console.log(chalk.green('Real-world ecosystem application loaded successfully'));
}

module.exports = app;
