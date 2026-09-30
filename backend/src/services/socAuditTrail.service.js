const LOGIN_LABELS = {
  login_success: 'Signed in successfully',
  session_resumed: 'Existing session resumed',
  screen_locked: 'Screen locked after 10 minutes of inactivity',
  screen_unlocked: 'Locked screen resumed',
  auto_logout: 'Automatically signed out after 30 minutes of inactivity',
  login_failed: 'Sign-in attempt failed',
  logout: 'Signed out',
  otp_verified: 'Two-step verification completed',
  otp_failed: 'Two-step verification failed',
  otp_required: 'Two-step verification requested',
  password_reset: 'Password reset requested',
  password_changed: 'Password changed',
};

const SOC_ACTION_LABELS = {
  'incident.acknowledge': 'Threat intelligence incident acknowledged',
  'incident.investigate': 'Threat intelligence investigation started',
  'incident.note': 'Investigation note added',
  'incident.resolve': 'Threat intelligence incident resolved',
  'incident.false_positive': 'Incident marked as false positive',
  'incident.audit_approve': 'Incident closure audit approved',
  'incident.audit_request_changes': 'Incident closure changes requested',
  'alert.acknowledge': 'Alert acknowledged',
  'alert.investigate': 'Alert investigation started',
  'alert.note': 'Alert note added',
  'alert.resolve': 'Alert resolved',
  'alert.false_positive': 'Alert marked as false positive',
  'escalation.accepted': 'Escalation accepted',
  'escalation.rejected': 'Escalation rejected',
  'escalation.resolved': 'Escalation resolved',
};

function humanizeAction(action) {
  return String(action || 'account_activity')
    .replace(/[._-]+/g, ' ')
    .replace(/\b\w/g, character => character.toUpperCase());
}

function actorDetails(value, fallbackEmail = '') {
  if (value && typeof value === 'object') {
    return {
      id: value._id || value.id || null,
      name: value.name || '',
      email: value.email || fallbackEmail,
      role: value.role || '',
    };
  }
  return { id: value || null, name: '', email: fallbackEmail, role: '' };
}

function companyDetails(value) {
  if (value && typeof value === 'object') return { id: value._id || value.id || null, name: value.name || '' };
  return value ? { id: value, name: '' } : null;
}

function normalizeSocEvent(event) {
  const action = String(event.action || 'account_activity');
  const targetSuffix = event.targetId ? ` • ${event.targetType || 'Record'} #${String(event.targetId).slice(-8)}` : '';
  const note = String(event.metadata?.note || '').trim();
  return {
    _id: `soc:${event._id}`,
    rawId: event._id,
    source: 'soc',
    category: 'SOC operation',
    action,
    label: SOC_ACTION_LABELS[action] || humanizeAction(action),
    details: `${SOC_ACTION_LABELS[action] || humanizeAction(action)}${targetSuffix}${note ? ` • ${note}` : ''}`,
    status: 'success',
    actor: actorDetails(event.actorId),
    company: companyDetails(event.companyId),
    targetType: event.targetType || '',
    targetId: event.targetId || '',
    metadata: event.metadata || {},
    ipAddress: event.ipAddress || '',
    device: '',
    createdAt: event.createdAt,
  };
}

function loginIdentity(event) {
  return String(event.userId?._id || event.userId || event.email || '');
}

function normalizeLoginEvents(events) {
  const successfulLogins = events.filter(event => event.action === 'login_success');
  const mfaLoginIds = new Set();
  const pairedOtpIds = new Set();

  for (const otpEvent of events.filter(event => event.action === 'otp_verified')) {
    const otpAt = new Date(otpEvent.createdAt || 0).getTime();
    const match = successfulLogins
      .filter(login => loginIdentity(login) === loginIdentity(otpEvent))
      .map(login => ({ login, distance: Math.abs(new Date(login.createdAt || 0).getTime() - otpAt) }))
      .filter(item => item.distance <= 15000)
      .sort((left, right) => left.distance - right.distance)[0];
    if (match) {
      pairedOtpIds.add(String(otpEvent._id));
      mfaLoginIds.add(String(match.login._id));
    }
  }

  return events
    .filter(event => !pairedOtpIds.has(String(event._id)))
    .map(event => {
      const action = String(event.action || 'account_activity');
      const mfa = mfaLoginIds.has(String(event._id));
      const baseLabel = LOGIN_LABELS[action] || humanizeAction(action);
      const label = action === 'login_success' && mfa ? 'Signed in successfully with two-step verification' : baseLabel;
      const failed = event.success === false || action.endsWith('_failed');
      const device = [event.browser, event.os, event.device].filter(Boolean).join(' • ');
      const failure = event.failReason ? ` • Reason: ${humanizeAction(event.failReason)}` : '';
      return {
        _id: `auth:${event._id}`,
        rawId: event._id,
        source: 'authentication',
        category: 'Authentication',
        action,
        label,
        details: `${label}${failure}`,
        status: failed ? 'failed' : 'success',
        actor: actorDetails(event.userId, event.email),
        company: companyDetails(event.companyId),
        targetType: 'Session',
        targetId: '',
        metadata: { mfa, failReason: event.failReason || '' },
        ipAddress: event.ipAddress || '',
        device,
        createdAt: event.createdAt,
      };
    });
}

function buildPersonalAuditTrail({ socEvents = [], loginEvents = [], limit = 500 } = {}) {
  return [
    ...socEvents.map(normalizeSocEvent),
    ...normalizeLoginEvents(loginEvents),
  ]
    .sort((left, right) => new Date(right.createdAt || 0) - new Date(left.createdAt || 0))
    .slice(0, limit);
}

module.exports = { humanizeAction, normalizeSocEvent, normalizeLoginEvents, buildPersonalAuditTrail };
