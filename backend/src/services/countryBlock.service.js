const crypto = require('crypto');
const net = require('net');
const axios = require('axios');
const CountryBlockRule = require('../models/CountryBlockRule.model');
const CountryNetwork = require('../models/CountryNetwork.model');
const countries = require('../constants/countries.json');
const { systemConnectionState } = require('../utils/systemPresence');
const countryCodes = new Set(countries.map(country => country.code));
const inflight = new Map();
const DAY = 86400000;

function policyForSystem(rules, system) {
  const companyId = String(system.companyId?._id || system.companyId);
  const selected = rules.filter(rule => rule.enabled
    && String(rule.companyId) === companyId
    && (rule.scope === 'company' || (rule.scope === 'department'
      ? String(rule.departmentId) === String(system.departmentId)
      : rule.scope === 'system' && String(rule.systemId) === String(system._id))))
    .map(rule => ({ id: String(rule._id), countryCode: rule.countryCode, direction: rule.direction }))
    .sort((a, b) => a.id.localeCompare(b.id));
  const revision = crypto.createHash('sha256').update(JSON.stringify(selected)).digest('hex');
  return { revision, rules: selected };
}

async function getPolicy(system) {
  const rules = await CountryBlockRule.find({
    companyId: system.companyId?._id || system.companyId, enabled: true,
    $or: [{ scope: 'company' }, { scope: 'department', departmentId: system.departmentId }, { scope: 'system', systemId: system._id }],
  }).lean();
  return policyForSystem(rules, system);
}

function parseNetworks(text, family) {
  if (typeof text !== 'string' || text.length > 8 * 1024 * 1024) throw new Error('Invalid country IP feed');
  const lines = [...new Set(text.trim().split(/\s+/).filter(Boolean))];
  if (!lines.length || lines.length > 100000) throw new Error('Country IP feed is empty or too large');
  for (const line of lines) {
    const [address, prefix, extra] = line.split('/');
    if (extra !== undefined || net.isIP(address) !== family || !/^\d+$/.test(prefix || '')
      || Number(prefix) < 1 || Number(prefix) > (family === 4 ? 32 : 128)) {
      throw new Error('Country IP feed contains an invalid network');
    }
  }
  return lines;
}

async function countryNetworks(countryCode) {
  if (!countryCodes.has(countryCode)) throw new Error('Invalid country code');
  if (inflight.has(countryCode)) return inflight.get(countryCode);
  const pending = (async () => {
    const cached = await CountryNetwork.findOne({ countryCode }).lean();
    if (cached && Date.now() - new Date(cached.fetchedAt).getTime() < DAY) return cached;
    const code = countryCode.toLowerCase();
    const urls = [
      `https://www.ipdeny.com/ipblocks/data/aggregated/${code}-aggregated.zone`,
      `https://www.ipdeny.com/ipv6/ipaddresses/aggregated/${code}-aggregated.zone`,
    ];
    const results = await Promise.allSettled(urls.map(async (url, index) => {
      const { data } = await axios.get(url, { timeout: 20000, responseType: 'text', maxContentLength: 8 * 1024 * 1024, maxRedirects: 0 });
      return parseNetworks(data, index === 0 ? 4 : 6);
    }));
    const failed = results.find(result => result.status === 'rejected');
    if (failed) throw new Error(`Country IP ranges unavailable for ${countryCode}; existing firewall rules were retained`);
    const record = { countryCode, ipv4: results[0].value, ipv6: results[1].value, fetchedAt: new Date() };
    await CountryNetwork.updateOne({ countryCode }, { $set: record }, { upsert: true });
    return record;
  })().finally(() => inflight.delete(countryCode));
  inflight.set(countryCode, pending);
  return pending;
}

async function enforcementPolicy(system) {
  const policy = await getPolicy(system);
  const networks = {};
  // Limit simultaneous upstream downloads for policies covering many countries.
  for (const code of new Set(policy.rules.map(rule => rule.countryCode))) {
    const data = await countryNetworks(code);
    networks[code] = { ipv4: data.ipv4, ipv6: data.ipv6, fetchedAt: data.fetchedAt };
  }
  return { ...policy, networks };
}

function enforcementStatus(system, expected, now = Date.now()) {
  const report = system.countryBlockStatus || {};
  if (system.agentType === 'phone' || /android|ios|solaris/i.test(system.osType || '')) return 'unsupported';
  const connection = systemConnectionState(system, now);
  if (connection === 'offline') return 'offline';
  if (connection === 'not_connected') return 'pending';
  const reportAge = report.checkedAt ? now - new Date(report.checkedAt).getTime() : NaN;
  if (!Number.isFinite(reportAge) || reportAge < 0 || reportAge > 180000) return 'pending';
  if (report.desiredRevision === expected.revision && report.state === 'error') return 'failed';
  if (report.appliedRevision === expected.revision && report.state === 'applied') return 'applied';
  return 'pending';
}

function sanitizeReport(report) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) return null;
  const revision = value => /^[a-f0-9]{64}$/.test(value || '') ? value : '';
  return {
    supported: report.supported === true,
    state: ['pending', 'applied', 'error'].includes(report.state) ? report.state : 'pending',
    desiredRevision: revision(report.desiredRevision), appliedRevision: revision(report.appliedRevision),
    error: String(report.error || '').slice(0, 500),
    rangeCount: Math.max(0, Math.min(1000000, Number(report.rangeCount) || 0)),
    checkedAt: new Date(),
  };
}

module.exports = { countries, countryCodes, policyForSystem, getPolicy, enforcementPolicy, enforcementStatus, sanitizeReport, parseNetworks };
