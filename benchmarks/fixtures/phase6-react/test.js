const React = require('react');
const ReactDOM = require('react-dom');
if (typeof React.createElement !== 'function' || typeof ReactDOM.render !== 'function') {
    console.error('react / react-dom export failure');
    process.exit(1);
}
console.log('phase6-react test passed (React v' + React.version + ')');
