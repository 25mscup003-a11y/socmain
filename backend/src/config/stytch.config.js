/**
 * Stytch Configuration
 * Loads Stytch credentials from environment.
 * If STYTCH_PROJECT_ID is absent, SIMULATION_MODE activates —
 * the pipeline runs identically but with generated telemetry data.
 */

const config = {
  projectId:   process.env.STYTCH_PROJECT_ID   || null,
  secret:      process.env.STYTCH_SECRET        || null,
  publicToken: process.env.STYTCH_PUBLIC_TOKEN  || null,
  fraudEnabled:process.env.FRAUD_ENABLED !== 'false', // default enabled

  // Stytch telemetry API endpoint
  lookupUrl: 'https://telemetry.stytch.com/v1/fingerprint/lookup',

  // Simulation is test/demo-only and must be explicitly enabled. Missing or
  // invalid production credentials must never generate fabricated risk data.
  get simulationMode() {
    return process.env.STYTCH_SIMULATION_MODE === 'true';
  },

  // Risk score thresholds
  thresholds: {
    low:      30,
    medium:   55,
    high:     75,
    critical: 90,
  },
};

module.exports = config;
