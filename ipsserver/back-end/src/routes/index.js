/**
 * Route Dispatcher — SOC4 IPS Server v4.0
 * =========================================
 *
 * Endpoints:
 *   POST   /webhook              Block/unblock (IP, MAC, domain, port, app, protocol)
 *   GET    /                     Server status + blocklist + threat summary
 *   GET    /status               Same as /
 *   GET    /health               Liveness probe
 *   GET    /blocklist            Blocked IPs, MACs, attack logs (Blockment Overview)
 *   GET    /network              Active traffic, suspicious activity, allowed connections
 *   GET    /ip-status            Active vs blocked IP panel
 *   GET    /threats              Threat intelligence stats (?hours=24)
 *   GET    /attacks              Recent attack events (?limit=100)
 *   GET    /logs                 Recent server logs (?limit=200&level=BLOCK)
 *   GET    /audit-logs           Audit/consent/admin logs (Super Admin)
 *   GET    /whitelist            Whitelisted IPs/domains
 *   POST   /whitelist            Add to whitelist { value, type, reason }
 *   DELETE /whitelist/:value     Remove from whitelist
 *   POST   /analyze              Analyze payload for threats (no blocking)
 *   GET    /companies            Get all registered companies
 *   GET    /stats                Aggregate dashboard KPIs
 *   GET    /incidents            Active IPS Engine incidents (auto-block tracking)
 *   POST   /simulate             Simulate attack for testing IDS→IPS flow
 *   POST   /isolate              Manually isolate a system/server
 *   POST   /unisolate            Manually unisolate (requires consentId)
 *   POST   /consent              Submit consent form for manual override
 */

const ctrl    = require('../controllers/webhookController');
const wafCtrl = require('../controllers/wafController');
const { sendError } = require('../utils/response');

async function handleRoute(req, res) {
  const url    = req.url || '/';
  const path   = url.split('?')[0];
  const method = req.method || 'GET';

  // ── GET /health ──────────────────────────────────────────────────────────
  if (method === 'GET' && path === '/health') return ctrl.getHealth(req, res);

  // ── GET /status | GET / ──────────────────────────────────────────────────
  if (method === 'GET' && (path === '/' || path === '/status')) return ctrl.getStatus(req, res);

  // ── GET /blocklist | GET /blocks — Blockment Overview ──────────────────
  if (method === 'GET' && (path === '/blocklist' || path === '/blocks')) return ctrl.getBlocklist(req, res);

  // ── GET /network — Network Overview ─────────────────────────────────────
  if (method === 'GET' && path === '/network') return ctrl.getNetworkOverview(req, res);

  // ── GET /ip-status — IP Status Panel ────────────────────────────────────
  if (method === 'GET' && path === '/ip-status') return ctrl.getIPStatus(req, res);

  // ── GET /threats ─────────────────────────────────────────────────────────
  if (method === 'GET' && path === '/threats') return ctrl.getThreats(req, res);

  // ── GET /attacks ─────────────────────────────────────────────────────────
  if (method === 'GET' && path === '/attacks') return ctrl.getAttacks(req, res);

  // ── GET /logs ─────────────────────────────────────────────────────────────
  if (method === 'GET' && path === '/logs') return ctrl.getLogs(req, res);

  // ── GET /audit-logs ────────────────────────────────────────────────────────
  if (method === 'GET' && path === '/audit-logs') return ctrl.getAuditLogs(req, res);

  // ── GET /whitelist ────────────────────────────────────────────────────────
  if (method === 'GET' && path === '/whitelist') return ctrl.getWhitelistHandler(req, res);

  // ── POST /whitelist ───────────────────────────────────────────────────────
  if (method === 'POST' && path === '/whitelist') return ctrl.addWhitelist(req, res);

  // ── DELETE /whitelist/:value ──────────────────────────────────────────────
  if (method === 'DELETE' && path.startsWith('/whitelist/')) {
    const value = path.slice('/whitelist/'.length);
    return ctrl.removeWhitelist(req, res, value);
  }

  // ── POST /webhook ─────────────────────────────────────────────────────────
  if (method === 'POST' && (path === '/' || path === '/webhook')) return ctrl.handleWebhook(req, res);

  // ── POST /analyze ─────────────────────────────────────────────────────────
  if (method === 'POST' && path === '/analyze') return ctrl.analyzePayload(req, res);

  // ── POST /register-company ─────────────────────────────────────────────────
  if (method === 'POST' && path === '/register-company') return ctrl.registerCompany(req, res);

  // ── GET /incidents ──────────────────────────────────────────────────────────
  if (method === 'GET' && path === '/incidents') return ctrl.getIncidents(req, res);

  // ── GET /stats ────────────────────────────────────────────────────────────────
  if (method === 'GET' && path === '/stats') return ctrl.getStats(req, res);

  // ── POST /simulate ─────────────────────────────────────────────────────────
  if (method === 'POST' && path === '/simulate') return ctrl.simulateAttack(req, res);

  // ── GET /companies ──────────────────────────────────────────────────────────
  if (method === 'GET' && path === '/companies') return ctrl.getCompanies(req, res);

  // ── POST /isolate — Isolate a system ───────────────────────────────────────
  if (method === 'POST' && path === '/isolate') return ctrl.isolateSystem(req, res);

  // ── POST /unisolate — Unisolate (requires consent) ─────────────────────────
  if (method === 'POST' && path === '/unisolate') return ctrl.unisolateSystem(req, res);

  // ── POST /consent — Submit consent form ────────────────────────────────────
  if (method === 'POST' && path === '/consent') return ctrl.submitConsent(req, res);

  // ── WAF endpoints — Agent reports + Dashboard queries ──────────────────────
  if (method === 'POST' && path === '/waf/report')  return wafCtrl.reportWAFEvent(req, res);
  if (method === 'GET'  && path === '/waf/status')  return wafCtrl.getWAFStatus(req, res);
  if (method === 'GET'  && path === '/waf/attacks') return wafCtrl.getWAFAttacks(req, res);

  // ── 404 ───────────────────────────────────────────────────────────────────
  return sendError(res,
    'Not found. Available endpoints:\n' +
    '  POST   /webhook         — block/unblock\n' +
    '  POST   /analyze         — analyze payload (no blocking)\n' +
    '  GET    /status          — server status + blocklist\n' +
    '  GET    /health          — liveness probe\n' +
    '  GET    /blocklist       — blocked IPs/MACs/attack-logs (Blockment Overview)\n' +
    '  GET    /network         — network overview (traffic, suspicious, allowed)\n' +
    '  GET    /ip-status       — active vs blocked IP panel\n' +
    '  GET    /threats         — threat intelligence (?hours=24)\n' +
    '  GET    /attacks         — recent attack events (?limit=100)\n' +
    '  GET    /logs            — server logs (?limit=200&level=BLOCK)\n' +
    '  GET    /audit-logs      — audit/admin/consent logs (Super Admin)\n' +
    '  GET    /whitelist       — whitelist\n' +
    '  POST   /whitelist       — add to whitelist\n' +
    '  DELETE /whitelist/:v    — remove from whitelist\n' +
    '  GET    /companies       — get all companies\n' +
    '  GET    /stats           — dashboard KPIs\n' +
    '  GET    /incidents       — active incidents\n' +
    '  POST   /simulate        — simulate attack\n' +
    '  POST   /isolate         — isolate system\n' +
    '  POST   /unisolate       — unisolate (requires consentId)\n' +
    '  POST   /consent         — submit consent form for override',
    404
  );
}

module.exports = { handleRoute };
