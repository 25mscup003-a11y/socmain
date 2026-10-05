/**
 * Application Configuration
 * Main Express-like configuration setup
 */

const http = require('http');
const logger = require('./utils/logger');
const corsMiddleware = require('./middlewares/cors');
const authMiddleware = require('./middlewares/auth');
const { handleRoute } = require('./routes');
const { sendError } = require('./utils/response');

/**
 * The core request handler (middleware chain → router)
 */
async function requestHandler(req, res) {
  try {
    await corsMiddleware(req, res, () => {
      return authMiddleware(req, res, () => handleRoute(req, res));
    });
  } catch (error) {
    logger.error(`[HTTP] Request failed: ${error.message}`);
    if (!res.headersSent && !res.destroyed) sendError(res, 'Internal server error', 500);
    else if (!res.writableEnded) res.end();
  }
}

/**
 * Create and configure HTTP server
 */
function createServer() {
  return http.createServer(requestHandler);
}

/**
 * Simple middleware chain executor
 * Used for sequential middleware execution
 */
function applyMiddleware(req, res, middlewares, finalHandler) {
  let index = 0;

  const next = () => {
    if (index < middlewares.length) {
      const middleware = middlewares[index++];
      middleware(req, res, next);
    } else {
      finalHandler(req, res);
    }
  };

  next();
}

module.exports = {
  createServer,
  requestHandler,
};
