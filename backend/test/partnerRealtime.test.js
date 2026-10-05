const test = require('node:test');
const assert = require('node:assert/strict');
const Company = require('../src/models/Company.model');
const { emitPartnerUpdate, emitCompanyPartnerUpdate } = require('../src/utils/partnerRealtime');

function socket() {
  const rooms = [];
  const events = [];
  const io = { to(room) { rooms.push(room); return io; }, emit(name, event) { events.push({ name, event }); } };
  return { io, rooms, events };
}

test('partner updates reach only their partner room and superadmin with no account payload', () => {
  const { io, rooms, events } = socket();
  emitPartnerUpdate(io, 'partner-one', 'agent_status', 'company-one');
  assert.deepEqual(rooms, ['partner:partner-one', 'superadmin']);
  assert.equal(events[0].name, 'partner:update');
  assert.equal(events[0].event.partnerId, 'partner-one');
  assert.equal(events[0].event.companyId, 'company-one');
  assert.deepEqual(Object.keys(events[0].event).sort(), ['companyId', 'partnerId', 'ts', 'type']);
});

test('agent updates resolve current company ownership instead of trusting legacy agent partner IDs', async t => {
  const { io, rooms } = socket();
  t.mock.method(Company, 'findById', id => {
    assert.equal(id, 'company-one');
    return { select: () => ({ lean: async () => ({ partnerId: 'current-partner' }) }) };
  });
  await emitCompanyPartnerUpdate(io, 'company-one', 'agent_status');
  assert.deepEqual(rooms, ['partner:current-partner', 'superadmin']);
});

test('direct companies do not send partner dashboard events', async t => {
  const { io, events } = socket();
  t.mock.method(Company, 'findById', () => ({ select: () => ({ lean: async () => ({ partnerId: null }) }) }));
  await emitCompanyPartnerUpdate(io, 'direct-company', 'agent_status');
  assert.deepEqual(events, []);
});
