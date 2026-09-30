const Company = require('../models/Company.model');
const Department = require('../models/Department.model');
const User = require('../models/User.model');
const SocCompanyAssignment = require('../models/SocCompanyAssignment.model');
const SocDepartmentAssignment = require('../models/SocDepartmentAssignment.model');
const SocShift = require('../models/SocShift.model');

const ANALYST_ROLES = ['l1_analyst', 'l2_analyst', 'l3_analyst'];

function zonedClock(now, timezone) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: timezone || 'Asia/Kolkata',
    weekday: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
  }).formatToParts(now).reduce((result, part) => {
    result[part.type] = part.value;
    return result;
  }, {});
  const weekday = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].indexOf(parts.weekday);
  return { weekday, minutes: (Number(parts.hour) * 60) + Number(parts.minute) };
}

function isShiftActiveAt(shift, now = new Date()) {
  try {
    const { weekday, minutes } = zonedClock(now, shift.timezone);
    const [startHour, startMinute] = shift.startTime.split(':').map(Number);
    const [endHour, endMinute] = shift.endTime.split(':').map(Number);
    const start = (startHour * 60) + startMinute;
    const end = (endHour * 60) + endMinute;
    const weekdays = Array.isArray(shift.weekdays) && shift.weekdays.length
      ? shift.weekdays.map(Number)
      : [0, 1, 2, 3, 4, 5, 6];

    if (start === end) return weekdays.includes(weekday);
    if (start < end) return weekdays.includes(weekday) && minutes >= start && minutes < end;
    if (minutes >= start) return weekdays.includes(weekday);
    return minutes < end && weekdays.includes((weekday + 6) % 7);
  } catch (_) {
    return false;
  }
}

function validEmail(value) {
  const email = String(value || '').trim().toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : null;
}

async function resolveSoarEmailRecipients(alert, now = new Date()) {
  if (!alert?.companyId) throw new Error('SOAR email routing requires alert.companyId');

  const companyId = alert.companyId;
  const departmentId = alert.departmentId || null;
  const [company, department, companyAssignments, shifts] = await Promise.all([
    Company.findById(companyId).select('email').lean(),
    departmentId
      ? Department.findOne({ _id: departmentId, companyId }).select('adminId').lean()
      : null,
    SocCompanyAssignment.find({ companyId, active: true }).select('userId').lean(),
    SocShift.find({ companyId, active: true }).select('timezone startTime endTime weekdays analystIds').lean(),
  ]);

  if (!company) throw new Error('SOAR email routing company was not found');

  const assignedUserIds = new Set(companyAssignments.map(item => String(item.userId)));
  const activeShiftAnalystIds = new Set(
    shifts.filter(shift => isShiftActiveAt(shift, now))
      .flatMap(shift => shift.analystIds || []).map(String),
  );
  const candidateIds = new Set([...assignedUserIds, ...activeShiftAnalystIds]);
  if (department?.adminId) candidateIds.add(String(department.adminId));
  if (alert.assignedTo) candidateIds.add(String(alert.assignedTo));

  const [users, departmentAssignments, companyAdmins, departmentAdmins] = await Promise.all([
    candidateIds.size
      ? User.find({ _id: { $in: [...candidateIds] }, isActive: true, accountStatus: 'active' })
        .select('_id email role companyId departmentId departmentIds').lean()
      : [],
    departmentId
      ? SocDepartmentAssignment.find({ companyId, departmentId, active: true }).select('userId').lean()
      : [],
    User.find({ companyId, role: 'company_admin', isActive: true, accountStatus: 'active' }).select('email').lean(),
    departmentId
      ? User.find({
        companyId, role: 'department_admin', isActive: true, accountStatus: 'active',
        $or: [{ departmentId }, { departmentIds: departmentId }],
      }).select('email').lean()
      : [],
  ]);

  const departmentUserIds = new Set(departmentAssignments.map(item => String(item.userId)));
  const recipients = new Set();
  const add = value => { const email = validEmail(value); if (email) recipients.add(email); };
  add(company.email);
  companyAdmins.forEach(user => add(user.email));
  departmentAdmins.forEach(user => add(user.email));

  users.forEach(user => {
    const id = String(user._id);
    const companyScopedManager = user.role === 'soc_manager'
      && assignedUserIds.has(id) && activeShiftAnalystIds.has(id);
    const isAssignedAnalyst = ANALYST_ROLES.includes(user.role)
      && String(alert.assignedTo || '') === id
      && (assignedUserIds.has(id) || String(user.companyId || '') === String(companyId));
    const departmentScoped = !departmentId
      || departmentUserIds.has(id)
      || String(user.departmentId || '') === String(departmentId)
      || (user.departmentIds || []).some(item => String(item) === String(departmentId));
    const isOnShiftAnalyst = ANALYST_ROLES.includes(user.role)
      && activeShiftAnalystIds.has(id) && departmentScoped;
    const isDepartmentAdmin = department?.adminId && String(department.adminId) === id;
    if (companyScopedManager || isAssignedAnalyst || isOnShiftAnalyst || isDepartmentAdmin) add(user.email);
  });

  return [...recipients];
}

module.exports = { resolveSoarEmailRecipients, isShiftActiveAt };
