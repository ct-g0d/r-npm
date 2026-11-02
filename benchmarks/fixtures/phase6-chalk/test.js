const chalk = require('chalk');
const styled = chalk.red('Hello Chalk');
if (!styled.includes('Hello Chalk')) {
    console.error('chalk output mismatch');
    process.exit(1);
}
console.log('phase6-chalk test passed');
