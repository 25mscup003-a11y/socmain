/**
 * Application Configuration
 * Main Express-like configuration setup
 */

const http = require('http');
const logger = require('./utils/logger');
const corsMiddleware = require('./middlewares/cors');
const authMiddleware = require('./middlewares/auth');
const { handleRoute } = require('./routes');

/**
 * The core request handler (middleware chain → router)
 */
function requestHandler(req, res) {
  corsMiddleware(req, res, () => {
    authMiddleware(req, res, () => {
      handleRoute(req, res);
    });
  });
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
