/**
 * Body Parser Middleware
 * Parses incoming request bodies
 */

const parseBody = (req) => {
  return new Promise((resolve, reject) => {
    let body = '';
    
    req.on('data', chunk => {
      body += chunk;
      // Prevent large payload attacks
      if (body.length > 1e6) { // 1MB limit
        reject(new Error('Payload too large'));
      }
    });

    req.on('end', () => {
      try {
        const data = body ? JSON.parse(body) : {};
        resolve(data);
      } catch (err) {
        reject(new Error('Invalid JSON'));
      }
    });

    req.on('error', reject);
  });
};

module.exports = {
  parseBody,
};
