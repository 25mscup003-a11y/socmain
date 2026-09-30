'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('dashboard errors are stored in MongoDB and never in a server log file', () => {
  const source = fs.readFileSync(path.join(__dirname, '../src/routes/dashboard.routes.js'), 'utf8');
  assert.doesNotMatch(source, /error_log\.txt/);
  assert.doesNotMatch(source, /writeFileSync\([^)]*\.log/);
  assert.match(source, /message: 'Dashboard alert detail query failed'/);
  assert.match(source, /await Log\.create\(/);
});
