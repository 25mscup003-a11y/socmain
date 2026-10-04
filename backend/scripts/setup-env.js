const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const backendRoot = path.resolve(__dirname, '..');
const envPath = path.join(backendRoot, '.env');

if (fs.existsSync(envPath)) {
  console.log('backend/.env already exists; existing settings and secrets were preserved.');
} else {
  const template = fs.readFileSync(path.join(backendRoot, '.env.example'), 'utf8');
  const contents = template.replace(
    /^(JWT_SECRET|AGENT_STORAGE_MASTER_KEY)=$/gm,
    (_, name) => `${name}=${crypto.randomBytes(32).toString('hex')}`,
  );
  fs.writeFileSync(envPath, contents, { flag: 'wx', mode: 0o600 });
  console.log('Created backend/.env with random secrets and local development settings.');
  console.log('Check MONGO_URI in backend/.env, then run npm run dev.');
}
