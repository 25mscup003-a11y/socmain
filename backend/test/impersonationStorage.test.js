const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function storage() {
  const values = new Map();
  return { getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, String(value)), removeItem: key => values.delete(key) };
}

function load(app, href, localStorage, sessionStorage) {
  const source = fs.readFileSync(path.join(__dirname, `../../${app}/src/api/authStorage.js`), 'utf8');
  const window = { location: { href }, history: { state: { idx: 0 }, replaceState(state, title, url) { window.location.href = new URL(url, href).href; } } };
  const context = { URL, URLSearchParams, window, localStorage, sessionStorage };
  // Execute the browser storage module with isolated storage for each tab.
  const selected = vm.runInNewContext(source.replaceAll('export const ', 'const ') + '\nauthStorage;', context);
  return { selected, href: window.location.href };
}

for (const [app, prefix] of [['company', 'co'], ['superadmin', 'sa']]) {
  test(`${app}: handoff, refresh and logout never overwrite the original login or another tab`, () => {
    const local = storage();
    local.setItem(`${prefix}_token`, 'original');
    local.setItem(`${prefix}_user`, 'original user');
    const firstTab = storage();
    const secondTab = storage();
    const first = load(app, 'http://localhost/?keep=yes#impersonationToken=first', local, firstTab);
    const second = load(app, 'http://localhost/?impersonationToken=second&keep=yes', local, secondTab);
    assert.equal(first.selected.getItem(`${prefix}_token`), 'first');
    assert.equal(second.selected.getItem(`${prefix}_token`), 'second');
    assert.equal(first.href, 'http://localhost/?keep=yes');
    assert.equal(second.href, 'http://localhost/?keep=yes');
    assert.equal(local.getItem(`${prefix}_token`), 'original');
    const refreshed = load(app, first.href, local, firstTab);
    assert.equal(refreshed.selected.getItem(`${prefix}_token`), 'first');
    refreshed.selected.removeItem(`${prefix}_token`);
    const ended = load(app, first.href, local, firstTab);
    assert.equal(ended.selected.getItem(`${prefix}_token`), null);
    assert.equal(local.getItem(`${prefix}_token`), 'original');
    assert.equal(second.selected.getItem(`${prefix}_token`), 'second');
    assert.equal(load(app, 'http://localhost/', local, storage()).selected.getItem(`${prefix}_token`), 'original');
  });
}
