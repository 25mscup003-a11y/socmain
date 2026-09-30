function normalizeIpAddress(value) {
  const first = Array.isArray(value) ? value[0] : String(value || '').split(',')[0];
  let ip = String(first || '').trim().replace(/^"|"$/g, '');
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (ip === '::1' || ip === '0:0:0:0:0:0:0:1') return '127.0.0.1';
  return ip;
}

function isLoopback(value) {
  const ip = normalizeIpAddress(value);
  return ip === '127.0.0.1' || ip.startsWith('127.');
}

function getClientIp(req) {
  const directIp = normalizeIpAddress(req?.socket?.remoteAddress || req?.connection?.remoteAddress || req?.ip);
  const forwardedIp = normalizeIpAddress(req?.headers?.['x-forwarded-for'] || req?.headers?.['x-real-ip']);

  // Forwarded headers are accepted only from a local reverse proxy. Direct
  // requests cannot spoof the IP stored in the authentication audit trail.
  if (forwardedIp && isLoopback(directIp)) return forwardedIp;
  return normalizeIpAddress(req?.ip) || directIp || 'unknown';
}

module.exports = { getClientIp, normalizeIpAddress };
