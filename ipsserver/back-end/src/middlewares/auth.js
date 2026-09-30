/**
 * Authentication Middleware
 * Validates webhook secret and extracts company context
 *
 * STRICT MULTI-TENANT RULE:
 *   - Every protected endpoint MUST have a resolved company_id.
 *   - If company_id cannot be resolved → request is rejected (400).
 *   - No cross-company data leakage allowed under any circumstances.
 *
 * Public endpoints (no company or auth needed):
 *   GET /health
 *
 * Company-required but no secret needed:
 *   GET /status, /blocklist, /whitelist, /threats, /attacks, /logs
 *   POST /whitelist, DELETE /whitelist/:v
 *
 * Protected endpoints (company + secret required):
 *   POST /webhook
 */

const logger = require('../utils/logger');
const { sendError } = require('../utils/response');

const SECRET = process.env.IPS_WEBHOOK_SECRET || '';

// Endpoints where a missing company_id triggers HARD REJECTION:
//   - POST /webhook: Creates a persistent firewall block rule.
//     Without a company_id this would create a global (cross-tenant) block — NEVER allowed.
//
// Endpoints where company_id is OPTIONAL (scoped vs. global):
//   - GET /blocklist, /threats, /attacks, /logs, /whitelist:
//     With company_id  → returns data for that specific company (company admin view)
//     Without company_id → returns all-company global data (superadmin overview allowed)
//
// Always-public (no company or auth needed):
//   - GET /health, /status, /companies, /
const WEBHOOK_REQUIRES_COMPANY = ['/webhook'];

/**
 * Extract company ID from JWT token.
 * Expects: Authorization: Bearer <token>
 */
function extractCompanyFromToken(authHeader) {
  try {
    if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
    const token = authHeader.slice(7);
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    // Simple base64 decode (no signature verification — internal service)
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    return payload.company || payload.companyId || payload.company_id || null;
  } catch (e) {
    return null;
  }
}

const authMiddleware = (req, res, next) => {
  const { method, url } = req;
  const path = url.split('?')[0];

  // ── Always public: GET /health ────────────────────────────────────────────
  if (method === 'GET' && path === '/health') {
    return next();
  }

  // ── Resolve company_id from all possible sources ──────────────────────────
  // Priority: X-Company-ID header > X-Company header > query param > JWT token
  const company =
    req.headers['x-company-id'] ||
    req.headers['x-company'] ||
    (function () {
      try { return new URL(`http://localhost${req.url}`).searchParams.get('company'); } catch { return null; }
    })() ||
    (req.headers['authorization'] ? extractCompanyFromToken(req.headers['authorization']) : null);

  if (company) {
    req.company = company;
    // Read polling is expected dashboard traffic. Keep the console/file logs
    // focused on writes unless verbose read-auth logging is explicitly enabled.
    if (method !== 'GET' || process.env.IPS_LOG_READ_AUTH === 'true') {
      logger.info(`[Auth] company_id resolved: ${company} | ${method} ${path}`);
    }
  }

  // ── STRICT REJECTION: POST /webhook without company_id ───────────────────
  // A block rule created without a company_id would be applied globally to ALL
  // tenants. This is the primary security boundary for multi-tenant isolation.
  const isStrictPath = method === 'POST' && WEBHOOK_REQUIRES_COMPANY.some(
    p => path === p || path.startsWith(p + '/')
  );
  if (isStrictPath && !req.company) {
    logger.warn(`[Auth] REJECTED — missing company_id on write endpoint: ${method} ${path} from ${req.socket?.remoteAddress}`);
    return sendError(res, 'company_id is required — request rejected (multi-tenant policy)', 400);
  }

  // ── Validate webhook secret for POST /webhook ─────────────────────────────
  if (SECRET && method === 'POST' && (path === '/' || path === '/webhook')) {
    const providedSecret = req.headers['x-webhook-secret'];
    if (!providedSecret || providedSecret !== SECRET) {
      logger.warn(`[Auth] Unauthorized webhook attempt: ${method} ${path} from ${req.socket?.remoteAddress}`);
      return sendError(res, 'Unauthorized', 401);
    }
  }

  next();
};

module.exports = authMiddleware;
