'use strict';

// Repairs the local SOC agent's server identity without disabling or changing
// the secure storage-key exchange. Run as root on the machine hosting both
// the backend and the agent.

const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

const backendRoot = path.resolve(__dirname, '..');
dotenv.config({ path: path.join(backendRoot, '.env') });

const configPath = '/opt/soc-agent/config/company_config.json';
const serverUrl = process.env.LOCAL_AGENT_SERVER_URL || 'http://10.139.209.104:5000';
const systemName = process.env.LOCAL_AGENT_SYSTEM_NAME || 'linux1';
const hostname = process.env.LOCAL_AGENT_HOSTNAME || 'CHAUDHARY';
const mongoUri = process.env.MONGO_URI || process.env.MONGODB_URI
  || process.env.MONGO_URI_LOCAL || process.env.MONGO_URI_CLOUD;

async function main() {
  if (process.getuid?.() !== 0) throw new Error('Run this script with sudo.');
  if (!mongoUri) throw new Error('MongoDB connection string is not configured.');

  await mongoose.connect(mongoUri, { serverSelectionTimeoutMS: 10_000 });
  const system = await mongoose.connection.db.collection('systems').findOne({
    name: systemName,
    hostname,
  });
  if (!system?.agentKey) throw new Error(`Registered system ${systemName}/${hostname} was not found.`);

  const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  const url = new URL(serverUrl);
  config.system_id = String(system._id);
  config.system_name = system.name;
  config.company_id = String(system.companyId);
  config.agent_key = system.agentKey;
  config.server_url = url.href.replace(/\/$/, '');
  config.server_ip = url.hostname;
  config.server_port = Number(url.port || (url.protocol === 'https:' ? 443 : 80));

  const temporaryPath = `${configPath}.new`;
  fs.writeFileSync(temporaryPath, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(temporaryPath, configPath);
  console.log(`Agent identity updated for ${system.name}; secure storage-key remains enabled.`);
}

main().catch((error) => {
  console.error(`Repair failed: ${error.message}`);
  process.exitCode = 1;
}).finally(async () => {
  await mongoose.disconnect().catch(() => {});
});
