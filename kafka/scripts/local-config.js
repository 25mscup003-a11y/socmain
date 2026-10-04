const fs = require('node:fs');
const path = require('node:path');
const dotenv = require('../../backend/node_modules/dotenv');

function localConfig() {
  const root = path.resolve(__dirname, '..');
  // Runtime defaults stay available if the setup example was moved or removed.
  const defaults = require('./local-defaults.json');
  const filename = path.join(root, '.env');
  const saved = fs.existsSync(filename) ? dotenv.parse(fs.readFileSync(filename)) : {};
  return Object.fromEntries(Object.entries(defaults).map(([key, fallback]) => {
    const value = process.env[key] ?? saved[key] ?? fallback;
    if (!value || /[\r\n]/.test(value)) throw new Error(`${key} must be a non-empty, single-line value`);
    return [key, value];
  }));
}

if (require.main === module) {
  for (const [key, value] of Object.entries(localConfig())) console.log(`${key}=${value}`);
}

module.exports = { localConfig };
