const http = require('http');
const https = require('https');

function verifyAutomaticBlock({ ip, company }) {
  const secret = process.env.IPS_WEBHOOK_SECRET;
  if (!secret || !company || !ip) return Promise.resolve({ allowed: false, reason: 'Automatic IP block requires company and backend verification' });
  return new Promise(resolve => {
    let url;
    try { url = new URL('/api/ips/verify-automatic', process.env.SOC_BACKEND_URL || 'http://127.0.0.1:5000'); }
    catch { resolve({ allowed: false, reason: 'Invalid SOC_BACKEND_URL' }); return; }
    const body = JSON.stringify({ ip });
    const request = (url.protocol === 'https:' ? https : http).request(url, { method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body),
        'X-Webhook-Secret': secret, 'X-Company-ID': String(company) } }, response => {
      let data = '';
      response.on('data', chunk => { data += chunk; if (data.length > 65536) request.destroy(new Error('Verification response too large')); });
      response.on('end', () => {
        try {
          const result = JSON.parse(data);
          const proof = result.verification;
          const providers = ['ipinfo', 'abuseipdb', 'otx', 'virustotal'];
          const valid = response.statusCode === 200 && result.allowed === true && proof?.version === 2 && proof.policy === 'two-of-four'
            && proof.ip === ip && String(proof.companyId) === String(company) && proof.action === 'block_ip'
            && Array.isArray(proof.matchedProviders) && proof.matchedProviders.length >= 2
            && new Set(proof.matchedProviders).size === proof.matchedProviders.length
            && proof.matchedProviders.every(provider => providers.includes(provider))
            && Date.parse(proof.checkedAt) <= Date.now() && Date.parse(proof.expiresAt) > Date.now()
            && Date.parse(proof.expiresAt) - Date.parse(proof.checkedAt) <= 60000;
          resolve(valid ? result : { allowed: false, reason: result.reason || 'Required threat checks did not authorize IP blocking' });
        } catch { resolve({ allowed: false, reason: 'Invalid backend verification response' }); }
      });
      response.on('error', () => resolve({ allowed: false, reason: 'Backend verification unavailable' }));
    });
    request.setTimeout(45000, () => request.destroy(new Error('Verification timed out')));
    request.on('error', () => resolve({ allowed: false, reason: 'Backend verification unavailable' }));
    request.end(body);
  });
}

module.exports = { verifyAutomaticBlock };
