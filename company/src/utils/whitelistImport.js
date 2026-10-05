export const MAX_WHITELIST_IMPORT = 200;

function normalizeIp(value) {
  if (/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(value)
    && value.split('.').every(part => Number(part) <= 255)) return { value, version: 4 };
  if (!value.includes(':') || !/^[a-f\d:.]+$/i.test(value)) return null;
  try {
    const host = new URL(`http://[${value}]/`).hostname;
    return host.startsWith('[') ? { value: host.slice(1, -1), version: 6 } : null;
  } catch { return null; }
}

export function normalizeWhitelistValue(input) {
  const value = input.trim();
  const ip = normalizeIp(value);
  if (ip) return { value: ip.value, type: 'ip' };
  if (value.includes('/')) {
    const [address, prefix, extra] = value.split('/');
    const network = normalizeIp(address);
    if (network && extra === undefined && /^\d{1,3}$/.test(prefix)
      && Number(prefix) <= (network.version === 4 ? 32 : 128)) {
      return { value: `${network.value}/${Number(prefix)}`, type: 'cidr' };
    }
    return { value, error: 'Invalid CIDR. Use an IP with /0–32 for IPv4 or /0–128 for IPv6.' };
  }
  const domain = value.toLowerCase().replace(/\.$/, '');
  if (domain.length <= 253 && /^(?:\*\.)?(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\.)+[a-z](?:[a-z\d-]{0,61}[a-z\d])?$/.test(domain)) {
    return { value: domain, type: 'domain' };
  }
  return { value, error: 'Enter a valid IP, CIDR range or domain name without a URL or port.' };
}

export function parseWhitelistImport(text, existing = []) {
  const values = text.split(/[\r\n,]+/).map(value => value.trim()).filter(Boolean);
  const known = new Set(existing.map(entry => normalizeWhitelistValue(String(entry.value || '')).value));
  const seen = new Set();
  const rows = values.slice(0, MAX_WHITELIST_IMPORT).map((value, index) => {
    const entry = normalizeWhitelistValue(value);
    const duplicate = seen.has(entry.value);
    seen.add(entry.value);
    return { ...entry, id: index, status: entry.error ? 'invalid' : duplicate ? 'duplicate' : known.has(entry.value) ? 'existing' : 'ready' };
  });
  return { rows, tooMany: values.length > MAX_WHITELIST_IMPORT };
}
