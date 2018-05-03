const mkdir = require('mkdirp');
const rm = require('rimraf');

rm.sync('../output');
mkdir.sync('../output');
