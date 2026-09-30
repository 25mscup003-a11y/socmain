const router     = require('express').Router();
const Department = require('../models/Department.model');
const User       = require('../models/User.model');
const System     = require('../models/System.model');
const Company    = require('../models/Company.model');
const mongoose   = require('mongoose');
const { authenticate, requireCompanyAdmin, requireManager, requireAnalyst } = require('../middleware/auth.middleware');
const { validateDeptName, validateEmail, validatePassword, firstError } = require('../utils/validate');

router.use(authenticate);

function countValue(value) {
  const num = Number(value);
  if (!Number.isFinite(num) || num < 0) return null;
  return Math.floor(num);
}

async function validateDepartmentAllocation(companyId, counts, excludeDepartmentId = null) {
  const company = await Company.findById(companyId).select('plan').lean();
  const plan = company?.plan || {};
  const limits = {
    assignedSystemCount: Number(plan.systemCount) || 0,
    assignedPhoneCount: Number(plan.phoneCount) || 0,
    assignedServerCount: Number(plan.serverCount) || 0,
  };
  const categoryLabels = {
    assignedSystemCount: 'system',
    assignedPhoneCount: 'phone',
    assignedServerCount: 'server',
  };

  const filter = { companyId };
  if (excludeDepartmentId) filter._id = { $ne: excludeDepartmentId };

  const departments = await Department.find(filter)
    .select('assignedSystemCount assignedPhoneCount assignedServerCount')
    .lean();
  const used = departments.reduce((acc, dept) => ({
    assignedSystemCount: acc.assignedSystemCount + (Number(dept.assignedSystemCount) || 0),
    assignedPhoneCount: acc.assignedPhoneCount + (Number(dept.assignedPhoneCount) || 0),
    assignedServerCount: acc.assignedServerCount + (Number(dept.assignedServerCount) || 0),
  }), { assignedSystemCount: 0, assignedPhoneCount: 0, assignedServerCount: 0 });

  for (const key of Object.keys(limits)) {
    const nextTotal = (Number(used[key]) || 0) + (Number(counts[key]) || 0);
    if (limits[key] > 0 && nextTotal > limits[key]) {
      const purchased = limits[key];
      const category = categoryLabels[key];
      return {
        valid: false,
        message: `Your company has purchased only ${purchased} ${category} license${purchased === 1 ? '' : 's'}. To add a new license, please purchase an additional license first.`,
      };
    }
  }

  return { valid: true };
}

// POST /api/department
router.post('/', requireCompanyAdmin, async (req, res) => {
  const targetCompanyId = req.headers['x-company-id'] || req.body.companyId || req.user.companyId;
  if (!targetCompanyId) return res.status(400).json({ message: 'Company ID is required' });
  const { name, description, adminEmail, adminName, adminPassword } = req.body;
  const assignedSystemCount = countValue(req.body.assignedSystemCount || 0);
  const assignedPhoneCount = countValue(req.body.assignedPhoneCount || 0);
  const assignedServerCount = countValue(req.body.assignedServerCount || 0);

  const check = firstError([
    validateDeptName(name),
    adminEmail ? validateEmail(adminEmail)       : null,
    adminEmail ? validatePassword(adminPassword) : null,
  ]);
  if (!check.valid) return res.status(400).json({ message: check.message });
  if ([assignedSystemCount, assignedPhoneCount, assignedServerCount].some(v => v === null)) {
    return res.status(400).json({ message: 'Assigned system, phone, and server counts must be 0 or more.' });
  }

  try {
    // Check duplicate dept name in same company
    const dup = await Department.findOne({ name: name.trim(), companyId: targetCompanyId });
    if (dup) return res.status(400).json({ message: `Department "${name}" already exists` });

    const allocation = await validateDepartmentAllocation(targetCompanyId, {
      assignedSystemCount,
      assignedPhoneCount,
      assignedServerCount,
    });
    if (!allocation.valid) return res.status(400).json({ message: allocation.message });

    const dept = await Department.create({
      name: name.trim(),
      description: description?.trim() || '',
      companyId: targetCompanyId,
      assignedSystemCount,
      assignedPhoneCount,
      assignedServerCount,
    });

    let deptAdmin = null;
    if (adminEmail && adminPassword) {
      const existing = await User.findOne({ email: adminEmail.trim().toLowerCase() });
      if (existing) {
        await Department.findByIdAndDelete(dept._id);
        return res.status(400).json({ message: `Email ${adminEmail} already registered` });
      }
      deptAdmin = await User.create({
        name:         adminName?.trim() || name + ' Admin',
        email:        adminEmail.trim().toLowerCase(),
        password:     adminPassword,
        role:         'department_admin',
        companyId:    targetCompanyId,
        departmentId: dept._id,
      });
      await Department.findByIdAndUpdate(dept._id, { adminId: deptAdmin._id });
    }

    res.status(201).json({ department: dept, admin: deptAdmin });
  } catch (err) { res.status(400).json({ message: err.message }); }
});

// GET /api/department
router.get('/', requireAnalyst, async (req, res) => {
  try {
    const requestedCompanyId = req.headers['x-company-id'] || req.query.companyId || req.user.companyId;
    if (!requestedCompanyId) return res.json([]);
    if (req.user.role === 'partner_admin') {
      const ownership = [
        ...(req.user.partnerId ? [{ partnerId: req.user.partnerId }] : []),
        ...(req.user.tenantId ? [{ tenantId: req.user.tenantId }] : []),
      ];
      if (!ownership.length) return res.status(403).json({ message: 'Access denied to this company' });
      const company = await Company.findOne({ _id: requestedCompanyId, $or: ownership }).select('_id').lean();
      if (!company) return res.status(403).json({ message: 'Access denied to this company' });
    }
    let filter = { companyId: requestedCompanyId };
    if (req.user.role === 'department_admin') {
      filter._id = req.user.departmentId;
    } else if (req.user.role === 'analyst') {
      // Analyst sees only their assigned departments
      const u = await User.findById(req.user.id).select('departmentIds departmentId');
      const ids = u?.departmentIds?.length ? u.departmentIds : (u?.departmentId ? [u.departmentId] : []);
      if (ids.length) filter._id = { $in: ids };
    }
    const depts = await Department.find(filter)
      .populate('adminId', 'name email').sort({ createdAt: -1 });
    const usage = await System.aggregate([
      {
        $match: {
          companyId: new mongoose.Types.ObjectId(requestedCompanyId.toString()),
          isActive: true,
          departmentId: { $in: depts.map(d => d._id) },
        },
      },
      {
        $group: {
          _id: { departmentId: '$departmentId', agentType: { $ifNull: ['$agentType', 'system'] } },
          count: { $sum: 1 },
        },
      },
    ]);
    const usageByDept = usage.reduce((acc, row) => {
      const deptId = String(row._id.departmentId);
      const type = row._id.agentType || 'system';
      acc[deptId] = acc[deptId] || { system: 0, server: 0, phone: 0 };
      acc[deptId][type] = row.count;
      return acc;
    }, {});
    res.json(depts.map(dept => {
      const obj = dept.toObject();
      const counts = usageByDept[String(dept._id)] || {};
      obj.systemUsedCount = counts.system || 0;
      obj.serverUsedCount = counts.server || 0;
      obj.phoneUsedCount = counts.phone || 0;
      return obj;
    }));
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/department/:id
router.get('/:id', requireManager, async (req, res) => {
  try {
    const dept = await Department.findOne({ _id: req.params.id, companyId: req.user.companyId })
      .populate('adminId', 'name email');
    if (!dept) return res.status(404).json({ message: 'Department not found' });
    res.json(dept);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// PATCH /api/department/:id
router.patch('/:id', requireCompanyAdmin, async (req, res) => {
  const { name } = req.body;
  if (name) {
    const check = firstError([validateDeptName(name)]);
    if (!check.valid) return res.status(400).json({ message: check.message });
  }
  try {
    const update = { ...req.body };
    for (const key of ['assignedSystemCount', 'assignedPhoneCount', 'assignedServerCount']) {
      if (key in update) {
        const value = countValue(update[key]);
        if (value === null) return res.status(400).json({ message: 'Assigned system, phone, and server counts must be 0 or more.' });
        update[key] = value;
      }
    }

    if (['assignedSystemCount', 'assignedPhoneCount', 'assignedServerCount'].some(key => key in update)) {
      const current = await Department.findOne({ _id: req.params.id, companyId: req.user.companyId }).lean();
      if (!current) return res.status(404).json({ message: 'Department not found' });
      const allocation = await validateDepartmentAllocation(req.user.companyId, {
        assignedSystemCount: 'assignedSystemCount' in update ? update.assignedSystemCount : current.assignedSystemCount,
        assignedPhoneCount: 'assignedPhoneCount' in update ? update.assignedPhoneCount : current.assignedPhoneCount,
        assignedServerCount: 'assignedServerCount' in update ? update.assignedServerCount : current.assignedServerCount,
      }, req.params.id);
      if (!allocation.valid) return res.status(400).json({ message: allocation.message });
    }

    const dept = await Department.findOneAndUpdate(
      { _id: req.params.id, companyId: req.user.companyId },
      update, { new: true }
    );
    if (!dept) return res.status(404).json({ message: 'Department not found' });
    res.json(dept);
  } catch (err) { res.status(400).json({ message: err.message }); }
});

// DELETE /api/department/:id
router.delete('/:id', requireCompanyAdmin, async (req, res) => {
  try {
    const count = await System.countDocuments({ departmentId: req.params.id, isActive: true });
    if (count > 0)
      return res.status(400).json({
        message: `Cannot delete: ${count} active system(s) still in this department.`,
      });
    await Department.findOneAndDelete({ _id: req.params.id, companyId: req.user.companyId });
    res.json({ message: 'Department deleted' });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

module.exports = router;
