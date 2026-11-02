const _ = require('lodash');
if (!_.isArray([1, 2, 3])) {
    console.error('lodash.isArray failed');
    process.exit(1);
}
console.log('phase6-lodash test passed with version', _.version);
