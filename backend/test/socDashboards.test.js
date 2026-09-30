const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const User = require('../src/models/User.model');
const Alert = require('../src/models/Alert.model');
const SocEscalation = require('../src/models/SocEscalation.model');
const EdrIncident = require('../src/models/EdrIncident.model');
const SocNotification = require('../src/models/SocNotification.model');
const SocIncidentAuditReview = require('../src/models/SocIncidentAuditReview.model');
const LoginActivity = require('../src/models/LoginActivity.model');
const { SOC_ROLES, ANALYST_ROLES, ROUTINE_QUEUE_RULES, requiredSocRoleForWorkItem, socWorkItemFilter, allowedCompanyIds, getUserDataFilter } = require('../src/services/socAccess.service');
const { buildPersonalAuditTrail } = require('../src/services/socAuditTrail.service');
const { ROLE_MENUS, DASHBOARD_ROUTES } = require('../../company/src/config/menuConfig');

test('SOC roles schema and hierarchy assertions', () => {
  const enumRoles = User.schema.path('role').enumValues;
  for (const r of ['soc_manager', 'l1_analyst', 'l2_analyst', 'l3_analyst', 'company_admin', 'department_admin', 'partner_admin', 'superadmin']) {
    assert.ok(enumRoles.includes(r), `Role ${r} must exist in User schema enum`);
  }
  assert.deepEqual(SOC_ROLES, ['soc_manager', 'l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst']);
  assert.deepEqual(ANALYST_ROLES, ['l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst']);
});

test('Role menus matrix provides complete menu mapping for all SOC and administrative roles', () => {
  const roles = ['soc_manager', 'l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst', 'company_admin', 'department_admin', 'partner_admin', 'superadmin'];
  for (const role of roles) {
    assert.ok(Array.isArray(ROLE_MENUS[role]), `Menu for ${role} must be defined`);
    assert.ok(ROLE_MENUS[role].length > 0, `Menu for ${role} cannot be empty`);
    assert.ok(DASHBOARD_ROUTES[role], `Dashboard route for ${role} must be defined`);
  }
  assert.equal(DASHBOARD_ROUTES.soc_manager, '/soc-manager/dashboard');
  assert.equal(DASHBOARD_ROUTES.l1_analyst, '/l1/dashboard');
  assert.equal(DASHBOARD_ROUTES.l2_analyst, '/l2/dashboard');
  assert.equal(DASHBOARD_ROUTES.l3_analyst, '/l3/dashboard');
  assert.equal(DASHBOARD_ROUTES.l4_analyst, '/l4/dashboard');
  assert.ok(
    ROLE_MENUS.soc_manager.some(item => item.to === '/soc-manager/queue' && item.label === 'Assignment Queue'),
    'soc_manager requires an Assignment Queue menu',
  );
  for (const role of ['l1_analyst', 'l2_analyst', 'l3_analyst']) {
    assert.ok(!ROLE_MENUS[role].some(item => item.label === 'Assignment Queue'), `${role} sidebar must not expose Assignment Queue`);
  }
  assert.ok(ROLE_MENUS.l3_analyst.some(item => item.to === '/l3/incidents' && item.label === 'Incident'));
  assert.ok(ROLE_MENUS.l3_analyst.some(item => item.to === '/l3/tickets' && item.label === 'My Tickets'));
  assert.ok(ROLE_MENUS.l1_analyst.some(item => item.to === '/l1/incidents' && item.label === 'Incidents'));
  assert.ok(ROLE_MENUS.l4_analyst.some(item => item.to === '/l4/tickets' && item.label === 'Tickets'));
  for (const [role, prefix] of [['l1_analyst', 'l1'], ['l2_analyst', 'l2'], ['l3_analyst', 'l3'], ['l4_analyst', 'l4']]) {
    assert.ok(
      ROLE_MENUS[role].some(item => item.to === `/${prefix}/contact-support` && item.label === 'Contact Support'),
      `${role} requires Contact Support chat in the sidebar`,
    );
    assert.ok(ROLE_MENUS[role].some(item => item.to === `/${prefix}/audit` && item.label === 'Audit'));
  }
  assert.ok(ROLE_MENUS.soc_manager.some(item => item.to === '/soc-manager/audit' && item.label === 'Audit'));
  assert.ok(ROLE_MENUS.soc_manager.some(item => item.to === '/soc-manager/threat-audit' && item.label === 'Threat Audit'));
  const managerSoarIndex = ROLE_MENUS.soc_manager.findIndex(item => item.to === '/soc-manager/soar');
  assert.equal(ROLE_MENUS.soc_manager[managerSoarIndex + 1]?.to, '/soc-manager/correlation');
  const l3SoarIndex = ROLE_MENUS.l3_analyst.findIndex(item => item.to === '/l3/soar');
  assert.equal(ROLE_MENUS.l3_analyst[l3SoarIndex + 1]?.to, '/l3/correlation');
  const l2Incoming = ROLE_MENUS.l2_analyst.find(item => item.label === 'Escalated Alerts');
  const l2Outgoing = ROLE_MENUS.l2_analyst.find(item => item.label === 'Escalate to L3');
  assert.equal(l2Incoming?.to, '/l2/escalations?direction=incoming');
  assert.equal(l2Outgoing?.to, '/l2/escalate-to-l3');
  assert.notEqual(l2Incoming?.to, l2Outgoing?.to, 'L2 incoming and outgoing escalation workflows require distinct pages');
  assert.ok(ROLE_MENUS.l3_analyst.some(item => item.to === '/l3/escalate' && item.label === 'Escalate'));
});

test('getUserDataFilter constructs tenant-isolated filters for roles', async () => {
  const mockUser = { id: '507f1f77bcf86cd799439011', companyId: '507f1f77bcf86cd799439011', role: 'l1_analyst' };
  const { filter } = await getUserDataFilter(mockUser, { personal: true });
  assert.ok(filter.companyId);
  assert.equal(filter.assignedTo, '507f1f77bcf86cd799439011');
});

test('SOC workflow supports alert and correlated incident work items', () => {
  assert.ok(SocEscalation.schema.path('alertId'));
  assert.ok(SocEscalation.schema.path('incidentId'));
  assert.ok(SocEscalation.schema.path('resourceType').enumValues.includes('incident'));
  assert.ok(EdrIncident.schema.path('assignedTo'));
  assert.ok(EdrIncident.schema.path('correlationId'));
  assert.ok(Alert.schema.path('ticketOpenedAt'));
  assert.ok(Alert.schema.path('ticketOpenedBy'));
  assert.deepEqual(Alert.schema.path('socCaseType').enumValues, ['ticket', 'incident', null]);
  const nonTicketAlert = new Alert({ ticketSource: null });
  assert.equal(nonTicketAlert.validateSync()?.errors?.ticketSource, undefined);
});

test('SOC ticket notifications are user-scoped and deduplicated', () => {
  assert.equal(SocNotification.schema.path('userId').instance, 'ObjectId');
  assert.equal(SocNotification.schema.path('ticketId').instance, 'ObjectId');
  assert.ok(SocNotification.schema.path('type').enumValues.includes('ticket_queued'));
  assert.ok(SocNotification.schema.path('type').enumValues.includes('ticket_assigned'));
  assert.ok(SocNotification.schema.path('type').enumValues.includes('admin_change'));
  assert.ok(SocNotification.schema.path('type').enumValues.includes('chat_message'));
  assert.notEqual(SocNotification.schema.path('ticketId').isRequired, true);
  assert.ok(SocNotification.schema.path('chatThreadId'));
  assert.ok(SocNotification.schema.path('actorId'));
  assert.ok(SocNotification.schema.path('link'));
  const uniqueIndex = SocNotification.schema.indexes().find(([fields, options]) => (
    fields.userId === 1 && fields.ticketId === 1 && fields.type === 1 && options.unique
  ));
  assert.ok(uniqueIndex);
  assert.deepEqual(uniqueIndex[1].partialFilterExpression, { ticketId: { $type: 'objectId' } });
  const sourceIndex = SocNotification.schema.indexes().find(([fields, options]) => (
    fields.userId === 1 && fields.dedupeKey === 1 && options.unique
  ));
  assert.ok(sourceIndex, 'general notifications require a source-level deduplication index');
});

test('SOC settings notifications include audited admin changes and chat read synchronization', () => {
  const auditModelSource = fs.readFileSync(path.join(__dirname, '../src/models/SocAuditEvent.model.js'), 'utf8');
  const notificationServiceSource = fs.readFileSync(path.join(__dirname, '../src/services/socNotification.service.js'), 'utf8');
  const chatRouteSource = fs.readFileSync(path.join(__dirname, '../src/routes/soc-chat.routes.js'), 'utf8');
  const settingsSource = fs.readFileSync(path.join(__dirname, '../../company/src/pages/SettingsPage.jsx'), 'utf8');
  assert.match(auditModelSource, /notifyAuditEvent/);
  assert.match(notificationServiceSource, /ADMIN_ROLES\s*=\s*\['superadmin',\s*'soc_manager'\]/);
  assert.match(notificationServiceSource, /type:\s*'admin_change'/);
  assert.match(notificationServiceSource, /type:\s*'chat_message'/);
  assert.match(chatRouteSource, /notifyChatMessage/);
  assert.match(chatRouteSource, /markChatThreadRead/);
  assert.match(settingsSource, /Tickets, Super Admin\/SOC Manager changes and chat messages/);
  assert.match(settingsSource, /soc:notification/);
  assert.match(settingsSource, /soc:notifications:read/);
});

test('personal audit trail combines MFA login records and preserves SOC action context', () => {
  const at = new Date('2026-08-12T16:34:01.112Z');
  const items = buildPersonalAuditTrail({
    loginEvents: [
      { _id: 'login-1', userId: { _id: 'l4-1', name: 'L4 Analyst', email: 'l4@example.com', role: 'l4_analyst' }, action: 'login_success', success: true, ipAddress: '127.0.0.1', createdAt: at },
      { _id: 'otp-1', userId: { _id: 'l4-1', name: 'L4 Analyst', email: 'l4@example.com', role: 'l4_analyst' }, action: 'otp_verified', success: true, ipAddress: '127.0.0.1', createdAt: at },
    ],
    socEvents: [
      { _id: 'audit-1', actorId: { _id: 'l4-1', name: 'L4 Analyst', email: 'l4@example.com', role: 'l4_analyst' }, action: 'incident.resolve', targetType: 'EdrIncident', targetId: '1234567890abcdef', metadata: { note: 'IOC contained' }, createdAt: new Date(at.getTime() + 1000) },
    ],
  });
  assert.equal(items.length, 2, 'OTP verification and successful login should render as one audit event');
  assert.equal(items[0].label, 'Threat intelligence incident resolved');
  assert.match(items[0].details, /IOC contained/);
  assert.equal(items[1].label, 'Signed in successfully with two-step verification');
  assert.equal(items[1].actor.role, 'l4_analyst');
});

test('restored authenticated sessions are valid audit events', () => {
  assert.ok(LoginActivity.schema.path('action').enumValues.includes('session_resumed'));
  const [item] = buildPersonalAuditTrail({
    loginEvents: [{
      _id: 'resume-1', userId: { _id: 'l4-1', role: 'l4_analyst' },
      action: 'session_resumed', success: true, createdAt: new Date(),
    }],
  });
  assert.equal(item.label, 'Existing session resumed');
  assert.equal(item.source, 'authentication');
});

test('ticket queues contain only SOAR-created alert tickets', () => {
  const source = fs.readFileSync(path.join(__dirname, '../src/routes/soc-dashboard.routes.js'), 'utf8');
  const ticketRoute = source.slice(source.indexOf("router.get('/tickets'"), source.indexOf("router.get('/queue'"));
  assert.match(ticketRoute, /Alert\.find\(filter\)/);
  assert.match(ticketRoute, /ticketOpenedAt:\s*\{\s*\$ne:\s*null\s*\}/);
  assert.match(ticketRoute, /ticketSource:\s*'soar'/);
  assert.match(ticketRoute, /\.\.\.socWorkItemFilter\(\)/);
  assert.match(ticketRoute, /populate\('ticketOpenedBy',\s*'name email role'\)/);
  assert.doesNotMatch(ticketRoute, /EdrIncident\.find/);
  assert.doesNotMatch(ticketRoute, /resourceType:\s*'incident'/);
  assert.match(ticketRoute, /sharedL4View/);
  assert.match(ticketRoute, /idsIpsFirewallTicketFilter/);
  assert.match(ticketRoute, /router\.get\('\/tickets\/:id'/);
  assert.match(ticketRoute, /resourceType:\s*'ticket'/);
  assert.match(ticketRoute, /networkEvidence:/);
  assert.match(ticketRoute, /Cache-Control',\s*'no-store'/);
  assert.match(ticketRoute, /networkSecurityTicketFilter\(req\.query\.networkSource\)/);

  const managerSource = fs.readFileSync(path.join(__dirname, '../src/routes/soc-manager.routes.js'), 'utf8');
  const managerTicketRoute = managerSource.slice(
    managerSource.indexOf("router.get('/tickets'"),
    managerSource.indexOf("router.get('/incidents'"),
  );
  assert.match(managerTicketRoute, /ticketSource:\s*'soar'/);
  const genericAssignment = managerSource.slice(
    managerSource.indexOf('async function runAutoAssignment'),
    managerSource.indexOf('async function threatIntelligenceCorrelationIds'),
  );
  assert.doesNotMatch(genericAssignment, /ticketOpenedAt/, 'generic alert assignment must not promote logs into tickets');

  const ticketAssignmentSource = fs.readFileSync(path.join(__dirname, '../src/services/socTicketAssignment.service.js'), 'utf8');
  assert.match(ticketAssignmentSource, /ticket\.ticketSource\s*=\s*'soar'/);

  const workspaceSource = fs.readFileSync(
    path.join(__dirname, '../../company/src/pages/analyst/soc/SocWorkspacePage.jsx'),
    'utf8',
  );
  assert.match(workspaceSource, /SOAR promotes an actionable alert into a ticket/);
  assert.match(workspaceSource, /SOAR Assignment/);
  assert.match(workspaceSource, /Only tickets created by SOAR are shown here/);
  assert.match(workspaceSource, /IDS, IPS and Firewall tickets go only to an on-shift SOC Manager or L4 analyst/);
  assert.match(workspaceSource, /Age \/ Retention/);
  assert.match(workspaceSource, /retention left/);

  const appSource = fs.readFileSync(path.join(__dirname, '../../company/src/App.jsx'), 'utf8');
  assert.match(appSource, /soc-manager\/tickets\/:id[^\n]+IncidentDetailPage resourceType="ticket"/);
  assert.match(appSource, /l4\/tickets\/:id[^\n]+IncidentDetailPage resourceType="ticket"/);

  const forensicSource = fs.readFileSync(
    path.join(__dirname, '../../company/src/pages/analyst/soc/IncidentDetailPage.jsx'),
    'utf8',
  );
  assert.match(forensicSource, /SOAR Ticket Forensic Investigation/);
  assert.match(forensicSource, /incident\?\.resourceType === 'ticket' \? \{\} : \{ incidentId:/);

  const dashboardSource = fs.readFileSync(
    path.join(__dirname, '../../company/src/pages/analyst/soc/RoleDashboardPage.jsx'),
    'utf8',
  );
  assert.match(source, /idsTicketsActive/);
  assert.match(source, /ipsTicketsActive/);
  assert.match(source, /firewallTicketsActive/);
  assert.match(source, /securityConfiguration/);
  assert.match(source, /IdsIpsPolicy\.aggregate/);
  assert.match(source, /Firewall\.aggregate/);
  assert.match(source, /closedTickets:/);
  assert.match(dashboardSource, /Live IDS \/ IPS \/ Firewall Ticket Summary/);
  assert.match(dashboardSource, /Live IDS \/ IPS \/ Firewall Rules & Policies/);
  assert.match(dashboardSource, /Closed Tickets/);
  assert.match(dashboardSource, /skipCache:\s*true/);
});

test('Threat Intelligence work items are reserved for L4 assignment', () => {
  assert.equal(requiredSocRoleForWorkItem({ incidentSource: 'threat_intelligence', severity: 'low' }), 'l4_analyst');
  assert.equal(requiredSocRoleForWorkItem({ sourceType: 'THREAT_FEED', severity: 'low' }), 'l4_analyst');
  assert.equal(requiredSocRoleForWorkItem({ iocMatched: true, severity: 'critical' }), 'l4_analyst');
  assert.equal(requiredSocRoleForWorkItem({ incidentSource: 'edr', severity: 'critical' }), 'l3_analyst');
  assert.equal(requiredSocRoleForWorkItem({ incidentSource: 'edr', severity: 'high' }), 'l2_analyst');
  assert.equal(requiredSocRoleForWorkItem({ incidentSource: 'edr', severity: 'medium' }), 'l1_analyst');
});

test('assignment queue filter rejects routine log telemetry and requires actionable signals', () => {
  const filter = socWorkItemFilter();
  assert.ok(ROUTINE_QUEUE_RULES.includes('FILE_CREATED'));
  assert.ok(ROUTINE_QUEUE_RULES.includes('PROC_INVENTORY_SUMMARY'));
  assert.ok(ROUTINE_QUEUE_RULES.includes('NET_CONNECTION_SUMMARY'));
  assert.deepEqual(filter.$and[0].ruleId.$nin, ROUTINE_QUEUE_RULES);
  assert.ok(filter.$and[1].$or.some(condition => condition.actionable === true));
  assert.ok(filter.$and[1].$or.some(condition => condition.severity?.$in?.includes('critical')));
});

test('SOC tabs use distinct lifecycle markers', () => {
  assert.equal(Alert.schema.path('ticketOpenedAt').instance, 'Date');
  assert.equal(EdrIncident.schema.path('correlationId').instance, 'ObjectId');
  const alertFilter = socWorkItemFilter();
  assert.ok(alertFilter.$and[0].ruleId.$nin.includes('NET_CONNECTION_SUMMARY'));
});

test('L1 dashboard separates incident, ticket, and count-only log metrics', () => {
  const backendSource = fs.readFileSync(path.join(__dirname, '../src/routes/l1.routes.js'), 'utf8');
  const dashboardSource = fs.readFileSync(
    path.join(__dirname, '../../company/src/pages/analyst/soc/RoleDashboardPage.jsx'),
    'utf8',
  );
  assert.match(backendSource, /solved:\s*\[\{\s*\$match:\s*\{\s*status:\s*'resolved'/);
  assert.match(backendSource, /solvedIncidents/);
  assert.match(backendSource, /newIncidentsInRange/);
  assert.match(backendSource, /closedIncidentsInRange/);
  assert.match(backendSource, /pendingIncidents/);
  assert.match(backendSource, /newTicketsInRange/);
  assert.match(backendSource, /closedTicketsInRange/);
  assert.match(backendSource, /pendingTickets/);
  assert.match(backendSource, /logsInRange/);
  assert.match(backendSource, /ticketStatus/);
  assert.match(backendSource, /ticketSeverity/);
  assert.match(backendSource, /resourceType:\s*'ticket'/);
  assert.match(backendSource, /totalAssignedWork/);
  assert.match(backendSource, /pendingWork/);
  assert.match(backendSource, /completedWork/);
  assert.match(backendSource, /completionRate/);
  assert.match(backendSource, /SocShift\.find/);
  assert.match(backendSource, /Cache-Control',\s*'no-store'/);
  assert.match(dashboardSource, /L1WorkSummary/);
  assert.match(dashboardSource, /'edr:incident:new'/);
  assert.match(dashboardSource, /Incidents Received/);
  assert.match(dashboardSource, /Incidents Closed/);
  assert.match(dashboardSource, /Incidents Pending/);
  assert.match(dashboardSource, /My Tickets Received/);
  assert.match(dashboardSource, /My Tickets Closed/);
  assert.match(dashboardSource, /My Tickets Pending/);
  assert.match(dashboardSource, /Logs Received/);
  assert.match(dashboardSource, /Ticket & Incident Severity/);
  assert.doesNotMatch(dashboardSource, /label="Assigned Alerts"/);
});

test('incident detail resolves missing endpoint IDs before forensic collection', () => {
  const backendSource = fs.readFileSync(path.join(__dirname, '../src/routes/soc-dashboard.routes.js'), 'utf8');
  const correlationSource = fs.readFileSync(path.join(__dirname, '../src/services/correlation.service.js'), 'utf8');
  const detailSource = fs.readFileSync(
    path.join(__dirname, '../../company/src/pages/analyst/soc/IncidentDetailPage.jsx'),
    'utf8',
  );
  assert.match(backendSource, /if \(!incident\.systemId\)/);
  assert.match(backendSource, /incident\.affectedEndpoint/);
  assert.match(backendSource, /evidenceAgentIds/);
  assert.match(backendSource, /agentVersion:\s*\{\s*\$nin:\s*\[null,\s*''\]\s*\}/);
  assert.match(backendSource, /activeEndpoints\.length === 1/);
  assert.match(backendSource, /\^\(IPS Server\|SOC IPS Engine\|IDS\|IPS\)\$/);
  assert.match(backendSource, /sort\(\{ isActive: -1, lastSeen: -1, updatedAt: -1 \}\)/);
  assert.match(backendSource, /\$set: \{ systemId: resolvedSystem\._id \}/);
  assert.match(backendSource, /CorrelationEvent\.updateOne/);
  assert.match(correlationSource, /const endpointIdentity =/);
  assert.doesNotMatch(correlationSource, /systemId:\s*correlation\.systemId\s*\|\|\s*null/);
  assert.match(detailSource, /!systemId \|\| !\/\^\[a-f\\d\]\{24\}\$\/i\.test/);
  assert.match(detailSource, /not mapped to a valid endpoint yet/);
});

test('incident closure audits persist reviewer tier and threat separation', () => {
  assert.deepEqual(SocIncidentAuditReview.schema.path('auditType').enumValues, ['standard', 'threat']);
  assert.deepEqual(SocIncidentAuditReview.schema.path('status').enumValues, ['pending', 'approved', 'changes_requested']);
  assert.ok(SocIncidentAuditReview.schema.path('incidentId').options.unique);
  const routeSource = fs.readFileSync(path.join(__dirname, '../src/routes/soc-dashboard.routes.js'), 'utf8');
  assert.match(routeSource, /l1_analyst:\s*\{\s*reviewerRole:\s*'l2_analyst'/);
  assert.match(routeSource, /l2_analyst:\s*\{\s*reviewerRole:\s*'l3_analyst'/);
  assert.match(routeSource, /l3_analyst:\s*\{\s*reviewerRole:\s*'soc_manager'/);
  assert.match(routeSource, /l4_analyst:\s*\{\s*reviewerRole:\s*'soc_manager',\s*auditType:\s*'threat'/);
});
