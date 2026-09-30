const test = require('node:test');
const assert = require('node:assert/strict');

const SocCompanyAssignment = require('../src/models/SocCompanyAssignment.model');
const SocDepartmentAssignment = require('../src/models/SocDepartmentAssignment.model');
const User = require('../src/models/User.model');
const EdrIncident = require('../src/models/EdrIncident.model');
const CorrelationEvent = require('../src/models/CorrelationEvent.model');
const { assignThreatIntelligenceIncident } = require('../src/services/correlation.service');

test('Threat Intelligence incidents fall back to a company L4 and sync the correlation owner', async t => {
  const originals = {
    companyFind: SocCompanyAssignment.find,
    departmentFind: SocDepartmentAssignment.find,
    userFind: User.find,
    aggregate: EdrIncident.aggregate,
    correlationUpdate: CorrelationEvent.updateOne,
  };
  t.after(() => {
    SocCompanyAssignment.find = originals.companyFind;
    SocDepartmentAssignment.find = originals.departmentFind;
    User.find = originals.userFind;
    EdrIncident.aggregate = originals.aggregate;
    CorrelationEvent.updateOne = originals.correlationUpdate;
  });

  const analystId = '507f1f77bcf86cd799439011';
  SocCompanyAssignment.find = () => ({ distinct: async () => [analystId] });
  SocDepartmentAssignment.find = () => ({ distinct: async () => [] });
  User.find = () => ({ select: () => ({ lean: async () => [{ _id: analystId }] }) });
  EdrIncident.aggregate = async () => [];

  let correlationUpdate = null;
  CorrelationEvent.updateOne = async (filter, update) => {
    correlationUpdate = { filter, update };
    return { modifiedCount: 1 };
  };

  let saved = false;
  const incident = {
    _id: '507f191e810c19729de860ea',
    companyId: '507f191e810c19729de860eb',
    departmentId: '507f191e810c19729de860ec',
    correlationId: '507f191e810c19729de860ed',
    incidentSource: 'threat_intelligence',
    assignedTo: null,
    status: 'open',
    actionsLog: [],
    isModified: field => field === 'status',
    save: async () => { saved = true; },
  };

  await assignThreatIntelligenceIncident(incident);

  assert.equal(String(incident.assignedTo), analystId);
  assert.equal(incident.status, 'investigating');
  assert.equal(incident.actionsLog[0]?.action, 'auto_assign_l4');
  assert.equal(saved, true);
  assert.equal(String(correlationUpdate?.update?.$set?.assignedTo), analystId);
  assert.equal(correlationUpdate?.update?.$set?.status, 'investigating');
});
