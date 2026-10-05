const MAX_BODY_BYTES = 1024 * 1024;

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let chunks = [];
    let bytes = 0;
    let settled = false;
    const fail = (message, statusCode = 400) => {
      if (settled) return;
      settled = true;
      chunks = [];
      reject(Object.assign(new Error(message), { statusCode }));
    };
    req.on('data', chunk => {
      if (settled) return; // Drain oversized bodies without retaining them.
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      bytes += buffer.length;
      if (bytes > MAX_BODY_BYTES) return fail('Payload too large', 413);
      chunks.push(buffer);
    });
    req.on('end', () => {
      if (settled) return;
      try {
        const body = bytes ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
        if (!body || typeof body !== 'object' || Array.isArray(body)) return fail('JSON body must be an object');
        settled = true;
        chunks = [];
        resolve(body);
      } catch { fail('Invalid JSON'); }
    });
    req.on('aborted', () => fail('Request aborted'));
    req.on('error', () => fail('Unable to read request body'));
    req.on('close', () => { if (!req.complete) fail('Request closed before body completed'); });
  });
}

module.exports = { parseBody, MAX_BODY_BYTES };
