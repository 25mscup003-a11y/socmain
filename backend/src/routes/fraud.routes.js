/**
 * Fraud Routes
 * All endpoints protected by authenticate middleware.
 * Superadmin has global access; company_admin scoped to their company.
 */
const router = require('express').Router();
const { authenticate, requireAnalyst } = require('../middleware/auth.middleware');
const ctrl = require('../controllers/fraud.controller');

// All fraud routes require authentication
router.use(authenticate, requireAnalyst);

// ── Dashboard & Analytics ─────────────────────────────────────────────────────
router.get('/dashboard',   ctrl.getDashboard);
router.get('/events',      ctrl.getEvents);
router.get('/live',        ctrl.getLive);
router.get('/history',     ctrl.getHistory);
router.get('/accounts',    ctrl.getAccounts);
router.get('/account/:id', ctrl.getAccountById);

// ── Alerts ────────────────────────────────────────────────────────────────────
router.get('/alerts',      ctrl.getAlerts);

// ── Devices ───────────────────────────────────────────────────────────────────
router.get('/devices',     ctrl.getDevices);
router.get('/device/:id',  ctrl.getDeviceById);

// ── Rules Engine CRUD ─────────────────────────────────────────────────────────
router.get('/rules',        ctrl.getRules);
router.post('/rule',        ctrl.createRule);
router.put('/rule/:id',     ctrl.updateRule);
router.delete('/rule/:id',  ctrl.deleteRule);

// ── Manual Check ──────────────────────────────────────────────────────────────
router.post('/login-check', ctrl.manualLoginCheck);

module.exports = router;
