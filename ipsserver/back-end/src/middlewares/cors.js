/**
 * CORS Middleware
 * Handles cross-origin requests
 */

const corsMiddleware = (req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Webhook-Secret, X-Company, X-Company-ID');
  res.setHeader('Access-Control-Max-Age', '3600');

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  return next();
};

module.exports = corsMiddleware;
