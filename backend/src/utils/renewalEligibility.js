function hasExpired(expiresAt, now = new Date()) {
  if (expiresAt == null || expiresAt === '') return false;
  const expiry = new Date(expiresAt).getTime();
  return Number.isFinite(expiry) && expiry <= +now;
}

module.exports = { hasExpired };
