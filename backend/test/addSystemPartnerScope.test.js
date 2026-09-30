const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('add-system payment handlers bind populated partner before recording revenue', () => {
  const source = fs.readFileSync(
    path.join(__dirname, '..', 'src', 'routes', 'add-system.routes.js'),
    'utf8',
  );
  const bindings = source.match(/const partner\s*=\s*company\?\.partnerId \|\| null;/g) || [];
  assert.equal(bindings.length, 2, 'confirm and renew-confirm must both bind partner');
});
