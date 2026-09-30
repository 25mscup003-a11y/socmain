const test = require('node:test');
const assert = require('node:assert/strict');

function restore(name, value) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

test('Stytch simulation requires explicit opt-in', async () => {
  const previousProjectId = process.env.STYTCH_PROJECT_ID;
  const previousSecret = process.env.STYTCH_SECRET;
  const previousSimulation = process.env.STYTCH_SIMULATION_MODE;
  delete process.env.STYTCH_PROJECT_ID;
  delete process.env.STYTCH_SECRET;
  process.env.STYTCH_SIMULATION_MODE = 'false';

  const configPath = require.resolve('../src/config/stytch.config');
  const servicePath = require.resolve('../src/services/stytch.service');
  delete require.cache[configPath];
  delete require.cache[servicePath];
  const { lookupTelemetry } = require('../src/services/stytch.service');

  await assert.rejects(
    lookupTelemetry('telemetry-test', '203.0.113.10'),
    error => error.code === 'STYTCH_UNAVAILABLE',
  );

  restore('STYTCH_PROJECT_ID', previousProjectId);
  restore('STYTCH_SECRET', previousSecret);
  restore('STYTCH_SIMULATION_MODE', previousSimulation);
  delete require.cache[configPath];
  delete require.cache[servicePath];
});

test('explicit Stytch simulation remains available for test environments', async () => {
  const previousSimulation = process.env.STYTCH_SIMULATION_MODE;
  process.env.STYTCH_SIMULATION_MODE = 'true';
  const configPath = require.resolve('../src/config/stytch.config');
  const servicePath = require.resolve('../src/services/stytch.service');
  delete require.cache[configPath];
  delete require.cache[servicePath];
  const { lookupTelemetry } = require('../src/services/stytch.service');
  const telemetry = await lookupTelemetry('telemetry-test', '203.0.113.10');
  assert.equal(telemetry.simulated, true);

  restore('STYTCH_SIMULATION_MODE', previousSimulation);
  delete require.cache[configPath];
  delete require.cache[servicePath];
});
