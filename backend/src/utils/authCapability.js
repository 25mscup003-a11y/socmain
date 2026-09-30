const AUTH_RULE_PATTERN = /^(AUTH_|LOGIN_|LOGON_|MFA_|SSH_|SUDO_|ACCOUNT_|USER_(LOGIN|LOGOUT|CREATED|DELETED|MODIFIED)|.*BRUTE[_ -]?FORCE)/i;
const AUTH_ACTION_PATTERN = /^(auth|authentication|login|logout|logon|login_failed|failed_login|successful_login|auth_success|auth_failure|mfa|mfa_|otp|remote_login|web_login|web_signup|account_lockout|password_change|password_reset|privilege_escalation)/i;
const AUTH_DESCRIPTION_PATTERN = /\b(authentication|authenticated|login|logout|logon|failed password|invalid password|account lockout|mfa|two[- ]factor|otp|sudo command|ssh session|remote access authentication|web login|signup)\b/i;

function authCapabilityFilter() {
  return {
    $and: [
      {
        $or: [
          { capabilityId: 4 },
          { capabilityIds: 4 },
          { ruleId: AUTH_RULE_PATTERN },
          { type: AUTH_RULE_PATTERN },
          { userAction: AUTH_ACTION_PATTERN },
          { eventType: AUTH_ACTION_PATTERN },
          { category: /^(auth|authentication|identity|iam)$/i },
          { subCategory: /^(auth|authentication|login|mfa|identity|account)$/i },
          { description: AUTH_DESCRIPTION_PATTERN },
        ],
      },
      {
        $nor: [
          { 'rawEvent.raw_log': /\bCRON\[[^\]]+\].*pam_unix\(cron:session\)/i },
          { full_log: /\bCRON\[[^\]]+\].*pam_unix\(cron:session\)/i },
          {
            $and: [
              { $or: [{ source: 'file_watch' }, { eventCategory: 'file' }, { ruleId: /^(?:FILE_|FIM_)/i }] },
              { capabilityId: { $ne: 4 } },
              { capabilityIds: { $ne: 4 } },
            ],
          },
        ],
      },
    ],
  };
}

function isAuthCapabilityTelemetry(body = {}, raw = {}) {
  const rule = String(body.rule_id || body.ruleId || body.type || raw.rule_id || raw.ruleId || '');
  const action = String(body.user_action || body.userAction || body.event_type || body.eventType || raw.user_action || raw.userAction || raw.event_type || raw.eventType || '');
  const category = String(body.category || body.subCategory || body.sub_category || raw.category || raw.subCategory || raw.sub_category || '');
  const description = String(body.description || raw.description || '');
  return AUTH_RULE_PATTERN.test(rule)
    || AUTH_ACTION_PATTERN.test(action)
    || /^(auth|authentication|identity|iam)$/i.test(category)
    || AUTH_DESCRIPTION_PATTERN.test(description);
}

module.exports = {
  AUTH_RULE_PATTERN,
  AUTH_ACTION_PATTERN,
  AUTH_DESCRIPTION_PATTERN,
  authCapabilityFilter,
  isAuthCapabilityTelemetry,
};
