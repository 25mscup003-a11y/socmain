const Tenant = require('../models/Tenant.model');
const { ROOT_DOMAIN } = require('../utils/tenant');

async function tenantResolver(req, _res, next) {
  try {
    const host = (req.hostname || '').split(':')[0].toLowerCase();
    const root = ROOT_DOMAIN.toLowerCase();
    let subdomain = null;

    if (host.endsWith(`.${root}`)) {
      subdomain = host.slice(0, -(root.length + 1)).split('.').pop();
    } else if (host.endsWith('.localhost')) {
      subdomain = host.split('.')[0];
    }

    if (subdomain && !['www', 'api'].includes(subdomain)) {
      req.tenant = await Tenant.findOne({ subdomain, status: 'active' });
    }

    next();
  } catch (err) {
    next(err);
  }
}

function enforceTenantAccess(req, res, next) {
  const user = req.user;
  if (!user || user.role === 'superadmin') return next();

  if (req.tenant && user.tenantId && String(req.tenant._id) !== String(user.tenantId)) {
    return res.status(403).json({ message: 'Invalid tenant access' });
  }

  next();
}

module.exports = { tenantResolver, enforceTenantAccess };
