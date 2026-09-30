/**
 * Response Formatter Utility
 * Standardizes API responses
 */

const sendSuccess = (res, data = {}, statusCode = 200) => {
  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    ok: true,
    ...data,
  }));
};

const sendError = (res, error, statusCode = 400) => {
  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    ok: false,
    error: typeof error === 'string' ? error : error.message,
  }));
};

module.exports = {
  sendSuccess,
  sendError,
};
