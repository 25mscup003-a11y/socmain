function labelsFromStructuredString(value) {
  const text = String(value || '').trim();
  if (!text || !/^[\[{]/.test(text)) return null;
  try {
    return JSON.parse(text);
  } catch {
    const displayNames = [...text.matchAll(/display_name\s*:\s*['"]([^'"]+)['"]/gi)].map(match => match[1]);
    if (displayNames.length) return displayNames;
    const names = [...text.matchAll(/(?:^|[,\s{])(?:name|family)\s*:\s*['"]([^'"]+)['"]/gi)].map(match => match[1]);
    if (names.length) return names;
    const ids = [...text.matchAll(/(?:^|[,\s{])id\s*:\s*['"]([^'"]+)['"]/gi)].map(match => match[1]);
    return ids;
  }
}

/**
 * OTX has returned malware_families as strings, objects, arrays of objects and
 * stringified object arrays across API versions. Normalize every variant before
 * it reaches a Mongoose [String] field or a Socket.IO payload.
 */
function normalizeThreatLabels(value, { limit = 10, maxLength = 200 } = {}) {
  const labels = [];
  const visit = item => {
    if (item === undefined || item === null || item === false) return;
    if (Array.isArray(item)) {
      item.forEach(visit);
      return;
    }
    if (typeof item === 'object') {
      visit(item.display_name ?? item.displayName ?? item.name ?? item.family ?? item.id ?? item.value);
      return;
    }
    const text = String(item).trim();
    if (!text || text === '[object Object]') return;
    const structured = labelsFromStructuredString(text);
    if (structured !== null) {
      visit(structured);
      return;
    }
    labels.push(text.slice(0, maxLength));
  };
  visit(value);

  const seen = new Set();
  return labels.filter(label => {
    const key = label.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, limit);
}

module.exports = { labelsFromStructuredString, normalizeThreatLabels };
