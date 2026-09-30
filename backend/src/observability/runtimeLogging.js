const LEVELS = Object.freeze({ debug: 10, info: 20, warn: 30, error: 40, silent: 100 });

function configuredLevel(env = process.env) {
  const fallback = env.NODE_ENV === 'production' ? 'info' : 'warn';
  const selected = String(env.LOG_LEVEL || fallback).toLowerCase();
  return Object.prototype.hasOwnProperty.call(LEVELS, selected) ? selected : fallback;
}

function isLevelEnabled(level, env = process.env) {
  const selected = configuredLevel(env);
  return LEVELS[level] >= LEVELS[selected];
}

function accessLogsEnabled(env = process.env) {
  if (env.HTTP_ACCESS_LOGS === 'true') return true;
  if (env.HTTP_ACCESS_LOGS === 'false') return false;
  return env.NODE_ENV === 'production';
}

function installConsolePolicy() {
  if (global.__socConsolePolicyInstalled) return;
  global.__socConsolePolicyInstalled = true;
  const originalLog = console.log.bind(console);
  const originalInfo = console.info.bind(console);
  console.log = (...args) => {
    if (isLevelEnabled('info')) originalLog(...args);
  };
  console.info = (...args) => {
    if (isLevelEnabled('info')) originalInfo(...args);
  };
}

module.exports = { configuredLevel, isLevelEnabled, accessLogsEnabled, installConsolePolicy };
