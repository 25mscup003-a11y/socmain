const crypto = require('crypto');
const axios = require('axios');
const SoarConnector = require('../models/SoarConnector.model');
const SoarCredential = require('../models/SoarCredential.model');
const { encryptValue, decryptValue } = require('./tenantKms.service');

function vaultKey() {
  if (!process.env.SOAR_VAULT_SECRET) {
    throw new Error('SOAR_VAULT_SECRET is required; refusing to use an insecure default vault key');
  }
  return crypto.createHash('sha256').update(process.env.SOAR_VAULT_SECRET).digest();
}

/**
 * Encrypt a plaintext secret string using AES-256-GCM
 */
function encryptSecret(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', vaultKey(), iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return {
    encryptedValue: encrypted,
    iv: iv.toString('hex'),
    authTag: authTag,
  };
}

/**
 * Decrypt an encrypted secret using AES-256-GCM
 */
function decryptSecret(encryptedValue, ivHex, authTagHex) {
  try {
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', vaultKey(), iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encryptedValue, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    throw new Error('Credential vault decryption failed: invalid key or corrupted payload');
  }
}

async function encryptTenantSecret(plaintext, credential) {
  return encryptValue({
    tenantId: credential.tenantId,
    companyId: credential.companyId || null,
    purpose: 'soar-connector-credential',
    recordId: credential._id,
    value: String(plaintext),
    actorId: credential.createdBy || null,
  });
}

async function decryptCredential(credential) {
  if (credential.encrypted?.ciphertext) {
    return decryptValue({
      tenantId: credential.tenantId,
      companyId: credential.companyId || null,
      purpose: 'soar-connector-credential',
      recordId: credential._id,
      envelope: credential.encrypted,
    });
  }
  // Legacy records remain readable until the dedicated migration rewrites them.
  return decryptSecret(credential.encryptedValue, credential.iv, credential.authTag);
}

/**
 * Validates URL to prevent SSRF against internal/cloud metadata networks
 */
function isSafeUrl(urlString) {
  try {
    const parsed = new URL(urlString);
    const host = parsed.hostname.toLowerCase();

    // Prevent cloud metadata IPs and internal loopback
    if (
      host === '169.254.169.254' ||
      host === 'metadata.google.internal' ||
      host === '127.0.0.1' ||
      host === 'localhost' ||
      host === '::1' ||
      host.endsWith('.internal')
    ) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Execute a request through a configured SOAR connector
 */
async function executeConnectorAction(connectorId, actionType, payload = {}) {
  const connector = await SoarConnector.findById(connectorId);
  if (!connector) throw new Error(`Connector ${connectorId} not found`);
  if (connector.status === 'disabled') throw new Error(`Connector ${connector.name} is disabled`);

  // Resolve Credentials if attached
  let authHeaders = {};
  let resolvedSecret = '';
  if (connector.credentialId) {
    const cred = await SoarCredential.findById(connector.credentialId).select('+encryptedValue +iv +authTag +encrypted');
    if (cred && (cred.encrypted?.ciphertext || cred.encryptedValue)) {
      const secret = await decryptCredential(cred);
      resolvedSecret = secret;
      if (connector.authType === 'bearer') {
        authHeaders['Authorization'] = `Bearer ${secret}`;
      } else if (connector.authType === 'api_key') {
        authHeaders['X-API-Key'] = secret;
      } else if (connector.authType === 'basic') {
        authHeaders['Authorization'] = `Basic ${Buffer.from(secret).toString('base64')}`;
      }
      cred.lastUsedAt = new Date();
      await cred.save().catch(() => {});
    }
  }

  // Construct target URL
  const targetUrl = payload.url || (connector.baseUrl ? `${connector.baseUrl.replace(/\/$/, '')}/${(payload.endpoint || '').replace(/^\//, '')}` : '');
  if (targetUrl && !isSafeUrl(targetUrl)) {
    throw new Error(`SSRF Prevention: Access to forbidden target URL ${targetUrl} is blocked`);
  }

  const method = payload.method || 'POST';
  const headers = { ...(connector.headers || {}), ...authHeaders, ...(payload.headers || {}) };

  try {
    let responseData;

    if (connector.type === 'slack') {
      const webhookUrl = targetUrl || connector.baseUrl;
      const slackText = payload.message || payload.text || `[SOAR Alert] ${payload.title || 'Security Notification'}`;
      await axios.post(webhookUrl, { text: slackText, blocks: payload.blocks }, { timeout: connector.timeoutMs });
      responseData = { message: 'Slack notification dispatched' };
    } else if (connector.type === 'teams') {
      const webhookUrl = targetUrl || connector.baseUrl;
      await axios.post(webhookUrl, { text: payload.message || 'SOAR Notification' }, { timeout: connector.timeoutMs });
      responseData = { message: 'Teams notification dispatched' };
    } else if (connector.type === 'ip_reputation' || connector.type === 'threat_intel') {
      const indicator = String(payload.ip || payload.domain || payload.hash || '').trim();
      if (!indicator) throw new Error('A real IP, domain, or hash indicator is required');
      const base = connector.baseUrl.replace(/\/$/, '');
      const isAbuseIpDb = /abuseipdb/i.test(`${connector.name} ${base}`);
      const isVirusTotal = /virustotal/i.test(`${connector.name} ${base}`);
      if (!isAbuseIpDb && !isVirusTotal) {
        throw new Error('Threat-intelligence connector provider is not recognized; configure a VirusTotal or AbuseIPDB base URL');
      }

      if (isAbuseIpDb) {
        const key = process.env.ABUSEIPDB_KEY || resolvedSecret;
        if (!key) throw new Error('AbuseIPDB API key is not configured');
        const res = await axios.get(`${base}/check`, {
          params: { ipAddress: indicator, maxAgeInDays: Number(payload.maxAgeInDays || 30), verbose: true },
          headers: { ...headers, Key: key, Accept: 'application/json' },
          timeout: connector.timeoutMs || 10000,
        });
        const data = res.data?.data || {};
        responseData = {
          provider: 'AbuseIPDB',
          indicator,
          abuseScore: Number(data.abuseConfidenceScore || 0),
          totalReports: Number(data.totalReports || 0),
          countryCode: data.countryCode || '',
          isp: data.isp || '',
          lastReportedAt: data.lastReportedAt || null,
          raw: data,
        };
      } else {
        const key = process.env.VIRUSTOTAL_API_KEY || resolvedSecret;
        if (!key) throw new Error('VirusTotal API key is not configured');
        const indicatorType = payload.hash ? 'files' : (payload.domain ? 'domains' : 'ip_addresses');
        const res = await axios.get(`${base}/${indicatorType}/${encodeURIComponent(indicator)}`, {
          headers: { ...headers, 'x-apikey': key },
          timeout: connector.timeoutMs || 10000,
        });
        const stats = res.data?.data?.attributes?.last_analysis_stats || {};
        responseData = {
          provider: 'VirusTotal',
          indicator,
          maliciousCount: Number(stats.malicious || 0),
          suspiciousCount: Number(stats.suspicious || 0),
          harmlessCount: Number(stats.harmless || 0),
          undetectedCount: Number(stats.undetected || 0),
          reputation: Number(res.data?.data?.attributes?.reputation || 0),
          raw: res.data?.data || {},
        };
      }
    } else {
      // Default REST / Webhook
      const res = await axios({
        method,
        url: targetUrl,
        headers,
        data: payload.data || payload.body || payload,
        timeout: connector.timeoutMs || 10000,
      });
      responseData = res.data;
    }

    connector.lastSuccessAt = new Date();
    connector.status = 'enabled';
    connector.lastError = '';
    await connector.save().catch(() => {});

    return responseData;
  } catch (err) {
    connector.lastError = err.message;
    connector.status = 'unhealthy';
    await connector.save().catch(() => {});
    throw new Error(`Connector ${connector.name} execution failed: ${err.message}`);
  }
}

/**
 * Health check test for a connector
 */
async function testConnectorHealth(connectorId) {
  const connector = await SoarConnector.findById(connectorId);
  if (!connector) throw new Error('Connector not found');

  connector.lastHealthCheck = new Date();
  try {
    if (connector.type === 'ip_reputation') {
      await executeConnectorAction(connectorId, 'health_check', { ip: '8.8.8.8' });
    } else if (connector.type === 'threat_intel') {
      await executeConnectorAction(connectorId, 'health_check', { ip: '8.8.8.8' });
    } else if (connector.baseUrl && isSafeUrl(connector.baseUrl)) {
      await axios.get(connector.baseUrl, { timeout: connector.timeoutMs || 5000 });
    } else {
      throw new Error('Connector base URL is missing or unsafe');
    }
    connector.status = 'enabled';
    connector.lastSuccessAt = new Date();
    connector.lastError = '';
    await connector.save();
    return { status: 'healthy', message: 'Connector reaches target endpoint successfully' };
  } catch (err) {
    connector.status = 'unhealthy';
    connector.lastError = err.message;
    await connector.save();
    return { status: 'unhealthy', message: `Health check failed: ${err.message}` };
  }
}

module.exports = {
  encryptSecret,
  decryptSecret,
  encryptTenantSecret,
  decryptCredential,
  isSafeUrl,
  executeConnectorAction,
  testConnectorHealth,
};
