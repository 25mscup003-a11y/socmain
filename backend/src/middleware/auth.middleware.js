const jwt = require('jsonwebtoken');

const authenticate = (req, res, next) => {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer '))
    return res.status(401).json({ message: 'No token provided' });
  try {
    req.user = jwt.verify(header.split(' ')[1], process.env.JWT_SECRET);
    const targetCompanyId = req.headers['x-company-id'] || req.query.companyId;
    if (targetCompanyId && ['superadmin', 'partner_admin'].includes(req.user.role)) {
      req.user.companyId = targetCompanyId;
    }
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};

// superadmin only
const requireSuperAdmin = (req, res, next) => {
  if (req.user?.role !== 'superadmin')
    return res.status(403).json({ message: 'Superadmin only' });
  next();
};

const requirePartnerAdmin = (req, res, next) => {
  if (!['superadmin', 'partner_admin'].includes(req.user?.role))
    return res.status(403).json({ message: 'Partner admin access required' });
  next();
};

// company_admin only (+ superadmin)
const requireCompanyAdmin = (req, res, next) => {
  if (!['superadmin', 'partner_admin', 'company_admin'].includes(req.user?.role))
    return res.status(403).json({ message: 'Company admin access required' });
  next();
};

// elevated company/tenant users (+ superadmin)
const requireManager = (req, res, next) => {
  if (!['superadmin', 'partner_admin', 'company_admin', 'department_admin', 'soc_manager'].includes(req.user?.role))
    return res.status(403).json({ message: 'Manager access required' });
  next();
};

// Any authenticated user — includes superadmin for cross-company access
const requireAnalyst = (req, res, next) => {
  if (![
    'superadmin', 'partner_admin', 'company_admin', 'department_admin', 'analyst',
    'soc_manager', 'l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst',
  ].includes(req.user?.role))
    return res.status(403).json({ message: 'Company user access required' });
  next();
};

// Aliases
const requireDeptAdmin   = requireManager;
const requireCompanyUser = requireAnalyst;

const requireSameCompany = (req, res, next) => {
  if (req.user.role === 'superadmin') return next();
  const id = req.params.companyId || req.body.companyId || req.query.companyId;
  if (id && req.user.companyId?.toString() !== id.toString())
    return res.status(403).json({ message: 'Access denied to this company' });
  next();
};

module.exports = {
  authenticate,
  requireSuperAdmin,
  requirePartnerAdmin,
  requireCompanyAdmin,
  requireManager,
  requireAnalyst,
  requireDeptAdmin,
  requireCompanyUser,
  requireSameCompany,
};
