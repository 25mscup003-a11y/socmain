'use strict';

const fs = require('node:fs');
const path = require('node:path');

// Direct CLI builds do not pass through server.js, so load signing settings
// before importing the package builder.
require('dotenv').config({ path: path.resolve(__dirname, '..', '.env') });

const { buildExe, buildMsi } = require('../src/services/packageBuilder.service');

const [configArg, outputArg] = process.argv.slice(2);
if (!configArg || !outputArg) {
  console.error('Usage: node scripts/build-windows-installers.js <company_config.json> <output-directory>');
  process.exit(2);
}

const configPath = path.resolve(configArg);
const outputDir = path.resolve(outputArg);
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
const system = {
  _id: config.system_id,
  name: config.system_name || 'Windows',
};
const company = {
  _id: config.company_id,
  name: config.company_name || 'AJNAT',
};

if (!system._id || !company._id || !config.agent_key || !config.integration_secret) {
  throw new Error('Config is missing company, system, or enrollment credentials');
}

fs.mkdirSync(outputDir, { recursive: true });
const exePath = path.join(outputDir, 'ajnat-agent-windows.exe');
const msiPath = path.join(outputDir, 'ajnat-agent-windows.msi');
fs.writeFileSync(exePath, buildExe(system, company, config));
fs.writeFileSync(msiPath, buildMsi(system, company, config));

for (const output of [exePath, msiPath]) {
  const stat = fs.statSync(output);
  console.log(`${path.basename(output)} ${stat.size} bytes`);
}
