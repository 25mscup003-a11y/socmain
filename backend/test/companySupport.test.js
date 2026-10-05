const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const Company = require('../src/models/Company.model');
const Partner = require('../src/models/Partner.model');
const Ticket = require('../src/models/CompanySupportTicket.model');
const adminRouter = require('../src/routes/superadmin.routes');
const companyRouter = require('../src/routes/company.routes');
const partnerRouter = require('../src/routes/partner.routes');
const { isDirectSupportCompany } = require('../src/utils/companySupport');
const ids = { direct:'600000000000000000000001', managed:'600000000000000000000002', partner:'600000000000000000000003', ticket:'600000000000000000000004', actor:'600000000000000000000005', other:'600000000000000000000006' };
const direct = { _id:ids.direct, name:'Direct Company', email:'direct@example.test', partnerId:null, source:'public', company_type:'DIRECT', tenantId:{ type:'main' } };
const managed = { ...direct, _id:ids.managed, name:'Partner Company', partnerId:ids.partner, source:'partner_referral', company_type:'PARTNER_MANAGED', tenantId:{ type:'partner' } };
function query(value, operations = []) {
  const q = {};
  for (const name of ['select', 'populate', 'sort', 'skip', 'limit']) q[name] = arg => { operations.push([name,arg]); return q; };
  q.lean = async () => value;
  q.then = (resolve,reject) => Promise.resolve(value).then(resolve,reject);
  return q;
}
function setup(t, company = direct, status = 'Open') {
  const oldSecret = process.env.JWT_SECRET;
  process.env.JWT_SECRET = 'support-test-only-secret';
  t.after(() => { if (oldSecret === undefined) delete process.env.JWT_SECRET; else process.env.JWT_SECRET = oldSecret; });
  const calls = { reads:[], companyQueries:[], operations:[], writes:[], events:[] };
  const ticket = { _id:ids.ticket, ticketId:'SOC-EXAMPLE', companyId:company._id, subject:'Agent connection', description:'Need help', messages:[], status,
    save:async function () { calls.writes.push({ status:this.status, messages:[...this.messages] }); return this; } };
  t.mock.method(Company, 'findById', id => query(String(id) === company._id ? company : null));
  t.mock.method(Company, 'find', filter => {
    calls.companyQueries.push(filter);
    return query(filter.partnerId === ids.partner ? [managed] : [direct, {...direct, _id:ids.managed, tenantId:{ type:'partner' }}]);
  });
  t.mock.method(Company, 'findOne', filter => query(filter._id === ids.managed && filter.partnerId === ids.partner ? managed : null));
  t.mock.method(Partner, 'findById', () => query({ status:'active', plan:{ paymentStatus:'paid', isActive:true } }));
  t.mock.method(Ticket, 'find', filter => { calls.reads.push(filter); return query([ticket],calls.operations); });
  t.mock.method(Ticket, 'countDocuments', async filter => { calls.reads.push(filter); return 1; });
  t.mock.method(Ticket, 'findOne', filter => { calls.reads.push(filter); return query(filter._id === ids.ticket && String(filter.companyId) === ticket.companyId ? ticket : null); });
  t.mock.method(Ticket, 'findById', id => query(id === ids.ticket ? ticket : null));
  t.mock.method(Ticket, 'create', async doc => { calls.writes.push(doc); return { _id:ids.ticket,...doc }; });
  const io = { to:room => ({ emit:(event,payload) => calls.events.push({room,event,payload}) }) };
  return {calls,ticket,io};
}
function request(router, {method='GET',url='/company-support-tickets',role='superadmin',companyId=ids.direct,query={},body={},headers={},io} = {}) {
  const token = role ? jwt.sign({ id:ids.actor,name:'Test Actor',role,companyId,partnerId:role === 'partner_admin' ? ids.partner : null },process.env.JWT_SECRET) : null;
  return new Promise((resolve,reject) => {
    const req = { method,url,query,body,headers:{...(token ? {authorization:`Bearer ${token}`} : {}),...headers},app:{get:key => key === 'io' ? io : null} };
    const res = {statusCode:200,status(code) { this.statusCode=code; return this; },json(body) {resolve({status:this.statusCode,body:JSON.parse(JSON.stringify(body))});}};
    router.handle(req,res,error => reject(error || new Error('Route did not match')));
  });
}
const path = (companyId=ids.direct,suffix='') => `/companies/${companyId}/support-tickets${suffix}`;

test('direct eligibility includes public/admin registrations and excludes every partner ownership marker', () => {
  assert.equal(isDirectSupportCompany(direct),true);
  assert.equal(isDirectSupportCompany({...direct,source:'admin_created'}),true);
  assert.equal(isDirectSupportCompany({_id:ids.direct}),true);
  for (const patch of [{partnerId:ids.partner},{source:'partner_referral'},{company_type:'PARTNER_MANAGED'},{tenantId:{type:'partner'}}]) assert.equal(isDirectSupportCompany({...direct,...patch}),false);
  assert.equal(isDirectSupportCompany(null),false);
});
test('inbox and mutation routes require authenticated superadmin', async t => {
  const {calls} = setup(t);
  for (const role of [null,'partner_admin','company_admin','analyst']) {
    assert.equal((await request(adminRouter,{role})).status,role ? 403 : 401);
    assert.equal((await request(adminRouter,{role,method:'POST',url:path(ids.direct,`/${ids.ticket}/messages`),body:{message:'Hi'}})).status,role ? 403 : 401);
  }
  assert.equal(calls.reads.length,0); assert.equal(calls.writes.length,0);
});
test('inbox scopes list/count to direct companies, escapes searches and paginates without message bodies', async t => {
  const {calls} = setup(t);
  const result = await request(adminRouter,{query:{page:'2',status:'Open',search:'a.*b'}});
  assert.equal(result.status,200);
  assert.deepEqual(result.body.companies.map(c=>c._id),[ids.direct]);
  assert.deepEqual(calls.companyQueries[0],{partnerId:null,source:{$ne:'partner_referral'},company_type:{$ne:'PARTNER_MANAGED'}});
  for (const q of calls.reads) { assert.deepEqual(q.companyId,{$in:[ids.direct]}); assert.equal(q.status,'Open'); assert.equal(q.$or[0].subject.test('axyzb'),false); assert.equal(q.$or[0].subject.test('a.*b'),true); }
  for (const operation of [['select','-messages -description'],['skip',20],['limit',20]]) assert.ok(calls.operations.some(op=>JSON.stringify(op)===JSON.stringify(operation)));
});
test('partner filters and malformed inbox queries cannot bypass direct ownership', async t => {
  const {calls} = setup(t);
  assert.equal((await request(adminRouter,{query:{companyId:ids.managed}})).status,403);
  for (const query of [{companyId:'bad'},{companyId:{$ne:null}},{status:'bad'},{search:{$ne:null}},{search:'x'.repeat(201)}]) assert.equal((await request(adminRouter,{query})).status,400);
  assert.equal(calls.reads.length,0);
});
for (const [label,company] of [['partnerId',managed],['source',{...direct,source:'partner_referral'}],['type',{...direct,company_type:'PARTNER_MANAGED'}],['tenant',{...direct,tenantId:{type:'partner'}}]]) {
  test(`all direct support routes reject partner ownership via ${label}`,async t => {
    const {calls} = setup(t,company);
    for (const [method,suffix,body] of [['GET','',{}],['GET',`/${ids.ticket}`,{}],['POST',`/${ids.ticket}/messages`,{message:'Reply'}],['PATCH',`/${ids.ticket}/status`,{status:'Closed'}]]) assert.equal((await request(adminRouter,{method,url:path(company._id,suffix),body})).status,403);
    assert.equal(calls.reads.length,0); assert.equal(calls.writes.length,0);
  });
}
test('company and ticket IDs are validated and conversations are company-scoped', async t => {
  const {calls} = setup(t);
  assert.equal((await request(adminRouter,{url:path('bad')})).status,400);
  assert.equal((await request(adminRouter,{url:path(ids.managed)})).status,404);
  assert.equal((await request(adminRouter,{url:path(ids.direct,'/bad')})).status,400);
  assert.equal((await request(adminRouter,{url:path(ids.direct,`/${ids.other}`)})).status,404);
  assert.equal((await request(adminRouter,{url:path(ids.direct,`/${ids.ticket}`)})).status,200);
  calls.reads.forEach(q=>assert.equal(q.companyId,ids.direct));
});
test('superadmin reply uses authenticated identity and only direct-company rooms', async t => {
  const {ticket,calls,io} = setup(t);
  const result=await request(adminRouter,{method:'POST',url:path(ids.direct,`/${ids.ticket}/messages`),io,body:{message:'  We can help.  ',companyId:ids.managed,senderRole:'company_admin',senderId:ids.managed}});
  assert.equal(result.status,200); assert.equal(ticket.status,'In Progress');
  assert.deepEqual(ticket.messages[0],{senderId:ids.actor,senderName:'Test Actor',senderRole:'superadmin',message:'We can help.'});
  assert.deepEqual(calls.events.map(e=>e.room).sort(),[`company:${ids.direct}`,'superadmin']);
  assert.ok(calls.events.every(e=>e.payload.companyId===ids.direct && e.event==='support:message_new'));
});
test('invalid messages and statuses do not write', async t => {
  const {calls}=setup(t);
  for(const message of ['', ' ', {}, ['Hi'],5,'x'.repeat(10001)]) assert.equal((await request(adminRouter,{method:'POST',url:path(ids.direct,`/${ids.ticket}/messages`),body:{message}})).status,400);
  assert.equal((await request(adminRouter,{method:'PATCH',url:path(ids.direct,`/${ids.ticket}/status`),body:{status:'bad'}})).status,400);
  assert.equal(calls.writes.length,0);
});
test('closed tickets reject replies until explicitly reopened', async t => {
  const {calls,ticket,io}=setup(t,direct,'Closed');
  assert.equal((await request(adminRouter,{method:'POST',url:path(ids.direct,`/${ids.ticket}/messages`),body:{message:'Hi'}})).status,409);
  assert.equal((await request(companyRouter,{role:'company_admin',method:'POST',url:`/support-tickets/${ids.ticket}/messages`,body:{message:'Hi'}})).status,409);
  assert.equal(calls.writes.length,0);
  assert.equal((await request(adminRouter,{method:'PATCH',url:path(ids.direct,`/${ids.ticket}/status`),body:{status:'Open'},io})).status,200);
  assert.equal(ticket.status,'Open'); assert.ok(calls.events.every(e=>e.event==='support:ticket_updated'));
});
for(const company of [direct,managed]) test(`company tickets/replies go to actual owner: ${company.name}`,async t=>{
  const {calls,io}=setup(t,company);
  const result=await request(companyRouter,{method:'POST',url:'/support-tickets',role:'company_admin',companyId:company._id,io,headers:{'x-company-id':ids.other},body:{subject:' Need help ',message:' Hello ',companyId:ids.other,senderRole:'superadmin'}});
  assert.equal(result.status,201); assert.equal(result.body.companyId,company._id); assert.equal(result.body.subject,'Need help'); assert.equal(result.body.messages[0].senderRole,'company_admin'); assert.match(result.body.ticketId,/^SOC-[A-F\d]{12}$/);
  const rooms=[`company:${company._id}`,company.partnerId ? `partner:${ids.partner}` : 'superadmin'].sort();
  assert.deepEqual(calls.events.map(e=>e.room).sort(),rooms); calls.events.length=0;
  assert.equal((await request(companyRouter,{method:'POST',url:`/support-tickets/${ids.ticket}/messages`,role:'company_admin',companyId:company._id,body:{message:'More details'},io})).status,200);
  assert.deepEqual(calls.events.map(e=>e.room).sort(),rooms);
});
test('company endpoints reject missing scope, another company ticket and partner header impersonation',async t=>{
  const {calls}=setup(t);
  assert.equal((await request(companyRouter,{url:'/support-tickets',role:'company_admin',companyId:null})).status,403);
  assert.equal((await request(companyRouter,{method:'POST',url:`/support-tickets/${ids.other}/messages`,role:'company_admin',body:{message:'Hi'}})).status,404);
  assert.equal((await request(companyRouter,{url:'/support-tickets',role:'partner_admin',headers:{'x-company-id':ids.direct}})).status,403);
  assert.equal(calls.writes.length,0);
});
test('superadmin cannot bypass ownership using company endpoints',async t=>{
  const {calls}=setup(t,managed);
  assert.equal((await request(companyRouter,{url:'/support-tickets',headers:{'x-company-id':ids.managed}})).status,403); assert.equal(calls.reads.length,0);
});
test('partner companyId query cannot read direct-company tickets',async t=>{
  const {calls}=setup(t,managed);
  assert.equal((await request(partnerRouter,{role:'partner_admin',query:{companyId:ids.direct}})).status,403); assert.equal(calls.reads.length,0);
  assert.equal((await request(partnerRouter,{role:'partner_admin',query:{companyId:ids.managed}})).status,200); assert.equal(calls.reads[0].companyId,ids.managed);
  assert.equal((await request(partnerRouter)).status,403);
});
test('partner replies and status changes stay in partner/company rooms',async t=>{
  const {calls,io}=setup(t,managed);
  assert.equal((await request(partnerRouter,{role:'partner_admin',method:'POST',url:`/company-support-tickets/${ids.ticket}/messages`,body:{message:'Partner reply'},io})).status,200);
  assert.equal((await request(partnerRouter,{role:'partner_admin',method:'PATCH',url:`/company-support-tickets/${ids.ticket}/status`,body:{status:'Resolved'},io})).status,200);
  assert.ok(calls.events.length>0); assert.ok(calls.events.every(e=>[`company:${ids.managed}`,`partner:${ids.partner}`].includes(e.room)));
});

const incomingId = '600000000000000000000010';
const outgoingId = '600000000000000000000011';
function receiptSetup(t, company = direct) {
  const context = setup(t, company);
  context.ticket.messages = [
    { _id:incomingId, senderRole:'company_admin', message:'Company request', readAt:null },
    { _id:outgoingId, senderRole:'superadmin', message:'Admin reply', readAt:null },
  ];
  t.mock.method(Ticket, 'findOneAndUpdate', async (filter, update, options) => {
    assert.deepEqual(filter, { _id:ids.ticket, companyId:company._id });
    assert.equal(options.timestamps, false, 'Reading must not reorder inbox tickets');
    assert.equal(options.new, true);
    assert.equal(options.arrayFilters[0]['message.readAt'], null, 'Never overwrite an earlier read time');
    assert.ok(update.$set['messages.$[message].readAt'] instanceof Date);
    const selectedIds = options.arrayFilters[0]['message._id'].$in;
    context.calls.writes.push({ filter, update, options });
    context.ticket.messages.forEach(message => {
      if (selectedIds.includes(message._id) && !message.readAt) message.readAt = update.$set['messages.$[message].readAt'];
    });
    return context.ticket;
  });
  return context;
}

test('read receipts start unread, and superadmin acknowledges only displayed company messages', async t => {
  const {ticket,calls,io}=receiptSetup(t);
  const result=await request(adminRouter,{method:'POST',url:path(ids.direct,`/${ids.ticket}/read`),body:{messageIds:[incomingId,outgoingId],readAt:'2000-01-01'},io});
  assert.equal(result.status,200);
  assert.ok(ticket.messages[0].readAt instanceof Date);
  assert.equal(ticket.messages[1].readAt,null);
  assert.equal(calls.writes.length,1);
  assert.deepEqual(calls.events.map(e=>e.room).sort(),[`company:${ids.direct}`,'superadmin']);
  assert.ok(calls.events.every(e=>e.event==='support:messages_read'));
  const firstRead=ticket.messages[0].readAt;
  await request(adminRouter,{method:'POST',url:path(ids.direct,`/${ids.ticket}/read`),body:{messageIds:[incomingId]},io});
  assert.equal(calls.writes.length,1,'Duplicate acknowledgement does not write again');
  assert.equal(ticket.messages[0].readAt,firstRead);
});

test('company acknowledges only support replies, not its own messages', async t => {
  const {ticket,calls,io}=receiptSetup(t);
  const result=await request(companyRouter,{role:'company_admin',method:'POST',url:`/support-tickets/${ids.ticket}/read`,body:{messageIds:[incomingId,outgoingId]},io});
  assert.equal(result.status,200);
  assert.equal(ticket.messages[0].readAt,null);
  assert.ok(ticket.messages[1].readAt instanceof Date);
  assert.deepEqual(calls.events.map(e=>e.room).sort(),[`company:${ids.direct}`,'superadmin']);
});

test('read receipts ignore own, unknown and unseen messages',async t=>{
  const {ticket,calls}=receiptSetup(t);
  await request(adminRouter,{method:'POST',url:path(ids.direct,`/${ids.ticket}/read`),body:{messageIds:[outgoingId,ids.other]}});
  assert.equal(calls.writes.length,0);
  assert.ok(ticket.messages.every(message=>message.readAt===null));
});

test('receipt requests reject invalid IDs and unauthorized company/ticket scope',async t=>{
  const {calls}=receiptSetup(t);
  for(const messageIds of [undefined,[],['bad'],[{$ne:null}],Array(201).fill(incomingId)]) {
    assert.equal((await request(adminRouter,{method:'POST',url:path(ids.direct,`/${ids.ticket}/read`),body:{messageIds}})).status,400);
  }
  assert.equal((await request(adminRouter,{method:'POST',url:path(ids.direct,`/${ids.other}/read`),body:{messageIds:[incomingId]}})).status,404);
  assert.equal((await request(companyRouter,{role:'company_admin',method:'POST',url:`/support-tickets/${ids.other}/read`,body:{messageIds:[outgoingId]}})).status,404);
  assert.equal((await request(adminRouter,{role:'company_admin',method:'POST',url:path(ids.direct,`/${ids.ticket}/read`),body:{messageIds:[incomingId]}})).status,403);
  assert.equal(calls.writes.length,0);
});

test('partner-managed companies cannot acknowledge messages through the direct support route',async t=>{
  const {calls}=receiptSetup(t,managed);
  assert.equal((await request(adminRouter,{method:'POST',url:path(ids.managed,`/${ids.ticket}/read`),body:{messageIds:[incomingId]}})).status,403);
  assert.equal(calls.writes.length,0);
});
