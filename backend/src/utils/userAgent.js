function parseUserAgent(value = '') {
  const userAgent = String(value || '').slice(0, 1000);

  const browserMatchers = [
    [/Edg\/([\d.]+)/, 'Microsoft Edge'],
    [/OPR\/([\d.]+)/, 'Opera'],
    [/Chrome\/([\d.]+)/, 'Google Chrome'],
    [/Firefox\/([\d.]+)/, 'Mozilla Firefox'],
    [/Version\/([\d.]+).*Safari\//, 'Safari'],
  ];
  const browserMatch = browserMatchers.find(([pattern]) => pattern.test(userAgent));
  const browserResult = browserMatch ? userAgent.match(browserMatch[0]) : null;
  const browser = browserMatch
    ? `${browserMatch[1]}${browserResult?.[1] ? ` ${browserResult[1]}` : ''}`
    : (userAgent ? 'Other browser' : 'Unknown');

  let os = 'Unknown';
  if (/Windows NT 10\.0/.test(userAgent)) os = 'Windows 10/11';
  else if (/Windows NT 6\.3/.test(userAgent)) os = 'Windows 8.1';
  else if (/Windows NT 6\.1/.test(userAgent)) os = 'Windows 7';
  else if (/Android ([\d.]+)/.test(userAgent)) os = `Android ${userAgent.match(/Android ([\d.]+)/)?.[1] || ''}`.trim();
  else if (/iPhone OS ([\d_]+)/.test(userAgent)) os = `iOS ${userAgent.match(/iPhone OS ([\d_]+)/)?.[1]?.replaceAll('_', '.') || ''}`.trim();
  else if (/iPad.*OS ([\d_]+)/.test(userAgent)) os = `iPadOS ${userAgent.match(/OS ([\d_]+)/)?.[1]?.replaceAll('_', '.') || ''}`.trim();
  else if (/Mac OS X ([\d_]+)/.test(userAgent)) os = `macOS ${userAgent.match(/Mac OS X ([\d_]+)/)?.[1]?.replaceAll('_', '.') || ''}`.trim();
  else if (/Linux/.test(userAgent)) os = 'Linux';

  let device = 'Desktop';
  if (/iPad|Tablet/i.test(userAgent)) device = 'Tablet';
  else if (/Mobile|Android|iPhone/i.test(userAgent)) device = 'Mobile';
  else if (!userAgent) device = 'Unknown';

  return { browser, os, device };
}

module.exports = { parseUserAgent };
