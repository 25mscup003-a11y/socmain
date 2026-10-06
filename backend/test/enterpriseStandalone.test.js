const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const mongoose = require('mongoose');
const Company = require('../src/models/Company.model');
const Partner = require('../src/models/Partner.model');
const Quote = require('../src/models/EnterpriseQuote.model');
const Order = require('../src/models/EnterpriseOrder.model');
const Addition = require('../src/models/EnterpriseAdditionOrder.model');
const Batch = require('../src/models/AddSystemSubscription.model');
const History = require('../src/models/PaymentHistory.model');
const allocate = require('../src/services/enterpriseLicenseAllocation.service');
const recalculate = require('../src/services/recalculateLicenseTotals.service');
const makePayments = require('../src/services/enterprisePayment.service');
const { calculateAddition } = require('../src/services/enterpriseAddition.service');

test('Enterprise purchases work atomically on standalone MongoDB', { skip: process.env.RUN_ENTERPRISE_DB_TESTS !== '1' }, async t => {
  require('dotenv').config({ quiet: true });
  const dbName = 'enterprise_test_' + crypto.randomUUID().replaceAll('-', '');
  await mongoose.connect(process.env.MONGO_URI, { dbName, serverSelectionTimeoutMS: 5000 });
  t.after(async () => {
    assert.equal(mongoose.connection.name, dbName);
    assert.match(dbName, /^enterprise_test_[a-f0-9]{32}$/);
    await mongoose.connection.dropDatabase();
    await mongoose.disconnect();
  });
  await Promise.all([Company, Partner, Quote, Order, Addition, Batch, History].map(model => model.init()));
  const future = new Date(Date.now() + 86400000 * 365);
  const seedPartner = async (qty, legacy = 0) => {
    const id = new mongoose.Types.ObjectId();
    await Partner.collection.insertOne({ _id: id, slug: 'enterprise-test-' + id, name: 'Test Partner', enterpriseLegacyConsumed: 0, enterpriseAllocations: [],
      agentLicensePurchases: [
        { status: 'active', agentQuantity: 100, consumedQuantity: 0, expiryDate: new Date(0) },
        { status: 'active', agentQuantity: qty, consumedQuantity: 0, expiryDate: future },
      ] });
    const company = await Company.create({ name: 'Isolated Test Company', email: `${id}@example.test`, partnerId: id,
      company_type: 'PARTNER_MANAGED', source: 'partner_referral', agentLicenseAllocation: legacy });
    return { company, partnerId: id };
  };
  const orderFor = quantity => ({ _id: new mongoose.Types.ObjectId(), systemCount: quantity, serverCount: 0, phoneCount: 0 });

  await t.test('stock consumption is atomic, excludes expired purchases and is idempotent', async () => {
    const { company, partnerId } = await seedPartner(12);
    const first = orderFor(8);
    await Promise.all([allocate(company, first), allocate(company, first), allocate(company, first)]);
    let partner = await Partner.findById(partnerId).lean();
    assert.equal(partner.agentLicensePurchases[0].consumedQuantity, 0);
    assert.equal(partner.agentLicensePurchases[1].consumedQuantity, 8);
    assert.equal(partner.enterpriseAllocations.length, 1);
    assert.equal(partner.agentLicenseSummary.activeLicenses, 4);
    const results = await Promise.allSettled([allocate(company, orderFor(3)), allocate(company, orderFor(3))]);
    assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
    assert.equal(results.find(r => r.status === 'rejected').reason.status, 409);
    partner = await Partner.findById(partnerId).lean();
    assert.equal(partner.agentLicensePurchases[1].consumedQuantity, 11);
    assert.equal(partner.enterpriseAllocations.length, 2);
    assert.equal(partner._enterpriseAllocation, undefined);
  });

  await t.test('legacy allocation credit is consumed once', async () => {
    const { company, partnerId } = await seedPartner(2, 5);
    const first = orderFor(6);
    await allocate(company, first); await allocate(company, first);
    const partner = await Partner.findById(partnerId).lean();
    assert.equal(partner.enterpriseLegacyConsumed, 4);
    assert.equal(partner.agentLicensePurchases[1].consumedQuantity, 2);
    await assert.rejects(allocate(company, orderFor(2)), { status: 409 });
  });

  const orders = new Map(), payments = new Map();
  const gateway = { orders: {
    create: async data => { const order = { ...data, id: 'order_' + crypto.randomUUID() }; orders.set(order.id, order); return order; },
    fetch: async id => orders.get(id),
  }, payments: { fetch: async id => payments.get(id) } };
  let transfers = 0;
  const service = makePayments({ getGateway: () => gateway, ensurePartnerLicenseStock: async () => {},
    createPartnerRouteTransfer: async () => { transfers++; return { payoutStatus: 'settled' }; } });
  const purchase = async (company, sys, revision = 1) => {
    let quote = await Quote.findOne({ companyId: company._id });
    if (!quote) quote = await Quote.create({ companyId: company._id, partnerId: company.partnerId, systemCount: sys,
      serverCount: 0, phoneCount: 0, billingCycle: 'yearly', amountInr: 3600, revision, status: 'quoted' });
    const { order } = await service.createOrder(company, { quoteId: String(quote._id), revision: quote.revision });
    const paymentId = 'pay_' + crypto.randomUUID();
    payments.set(paymentId, { status: 'captured', order_id: order.id, amount: order.amount, currency: 'INR' });
    return { order, paymentId };
  };

  await t.test('base plan plus other batches survive concurrent confirmations and replay', async () => {
    const { company } = await seedPartner(100);
    company.plan = { paymentStatus: 'paid', isActive: true, baseSystemCount: 10, systemCount: 13,
      expiresAt: future, startDate: new Date(), amountPaid: 1200, billingCycle: 'monthly' };
    await company.save();
    const original = await Batch.create({ companyId: company._id, addedSystemCount: 3, startDate: new Date(), endDate: future });
    const { order, paymentId } = await purchase(company, 20);
    await Promise.all([service.fulfill(order.id, paymentId), service.fulfill(order.id, paymentId)]);
    const updated = await Company.findById(company._id);
    assert.equal(updated.plan.systemCount, 33);
    assert.equal(updated.plan.baseSystemCount, 10);
    assert.equal(updated.plan.billingCycle, 'monthly');
    assert.equal(updated.plan.amountPaid, 1200);
    assert.equal(+updated.plan.expiresAt, +future);
    assert.equal(updated.enterpriseSubscriptionId, undefined);
    assert.equal(await Batch.countDocuments({ companyId: company._id }), 2);
    assert.equal(await History.countDocuments({ companyId: company._id }), 1);
    assert.equal((await Batch.findById(original._id)).addedSystemCount, 3);
    assert.equal(transfers, 1);
    await service.fulfill(order.id, paymentId);
    assert.equal(transfers, 1);
  });

  await t.test('Enterprise registration and later additions retain the cycle with separate payment-date periods', async () => {
    const { company } = await seedPartner(100);
    const first = await purchase(company, 10);
    payments.get(first.paymentId).created_at = Math.floor(Date.now() / 1000) - 15 * 86400;
    await service.fulfill(first.order.id, first.paymentId);
    let updated = await Company.findById(company._id);
    assert.equal(updated.plan.systemCount, 10);
    assert.equal(updated.plan.baseSystemCount, 0);
    assert.equal(updated.status, 'active');
    const parent = await Batch.findById(updated.enterpriseSubscriptionId);
    const counts = { systemCount: 5, serverCount: 2, phoneCount: 1, billingCycle: 'monthly' };
    const calc = await calculateAddition(updated, counts);
    const { order } = await service.createAdditionOrder(updated, { ...counts, purchaseKey: crypto.randomUUID(), expectedPaise: calc.totals.totalPaise });
    const paymentId = 'pay_' + crypto.randomUUID();
    payments.set(paymentId, { status: 'captured', order_id: order.id, amount: order.amount, currency: 'INR' });
    await Promise.all([service.fulfill(order.id, paymentId), service.fulfill(order.id, paymentId)]);
    const batch = await Batch.findOne({ paymentId });
    assert.ok(+batch.endDate < +parent.endDate); assert.equal(batch.billingCycle, 'monthly');
    assert.equal(+batch.endDate, +require('../src/utils/billingPeriod').getPeriodEnd('monthly', batch.startDate));
    assert.equal(batch.amountPaid, calc.totals.totalInr);
    assert.equal(calc.pricingSource, 'dynamic');
    assert.equal(calc.totals.baseInr, 2200);
    assert.equal(batch.priceType, 'renewal');
    assert.equal(String(batch.parentBatchId), String(parent._id));
    updated = await Company.findById(company._id);
    assert.equal(updated.plan.systemCount, 15); assert.equal(updated.plan.serverCount, 2); assert.equal(updated.plan.phoneCount, 1);
    assert.equal(updated.plan.baseSystemCount, 0);
    // Expiry removes the licenses without inventing a registration base plan.
    await Batch.updateMany({ companyId: company._id }, { $set: { endDate: new Date(0) } });
    updated = await recalculate(company._id);
    assert.equal(updated.plan.systemCount, 0); assert.equal(updated.plan.baseSystemCount, 0);
  });

  await t.test('saved requests and setup enqueue scoped emails atomically and drive login redirect', async () => {
    const User = require('../src/models/User.model');
    const notifications = require('../src/services/enterpriseNotification.service');
    const { saveEnterpriseQuote } = require('../src/services/enterpriseQuote.service');
    const { enterpriseLoginDestination } = require('../src/services/enterpriseLogin.service');
    // Tests never contact SMTP. Exercise the real DB claims using a fake transport.
    t.mock.method(notifications, 'deliver', async () => {});
    const { company, partnerId } = await seedPartner(100);
    const companyAdmin = { _id: new mongoose.Types.ObjectId(), role: 'company_admin', companyId: company._id,
      email: 'notify-company@example.test', isActive: true, accountStatus: 'active' };
    await User.collection.insertMany([companyAdmin, { _id: new mongoose.Types.ObjectId(), role: 'partner_admin', partnerId,
      email: 'notify-partner@example.test', isActive: true, accountStatus: 'active' },
    { _id: new mongoose.Types.ObjectId(), role: 'superadmin', email: 'notify-superadmin@example.test', isActive: true, accountStatus: 'active' }]);
    const messages = [];
    const worker = notifications.createEnterpriseNotifications({ sendMail: async message => { messages.push(message); return { accepted: [message.to] }; } });
    const body = { systemCount: 10, serverCount: 1, phoneCount: 0, billingCycle: 'monthly', notes: 'Test request', revision: 0 };
    const requested = await saveEnterpriseQuote(company, body, companyAdmin._id, false);
    assert.equal(requested.notification.status, 'pending');
    await Promise.all([worker.deliver(requested._id, requested.revision), worker.deliver(requested._id, requested.revision)]);
    assert.deepEqual(messages.map(message => message.to), ['notify-partner@example.test']);
    assert.equal((await Quote.findById(requested._id)).notification.status, 'sent');
    const ready = await saveEnterpriseQuote(company, { ...body, revision: requested.revision, amountInr: 1000 }, new mongoose.Types.ObjectId(), true);
    await worker.runPending();
    assert.deepEqual(messages.map(message => message.to), ['notify-partner@example.test', 'notify-company@example.test']);
    assert.equal((await Quote.findById(ready._id)).notification.status, 'sent');
    assert.equal(await enterpriseLoginDestination(companyAdmin, 'http://localhost:3000'), 'http://localhost:3000/company-admin/payments?tab=enterprise');
    const direct = await Company.create({ name: 'Direct email test', email: 'notify-direct@example.test' });
    const directRequest = await saveEnterpriseQuote(direct, body, companyAdmin._id, false);
    await worker.deliver(directRequest._id, directRequest.revision);
    assert.equal(messages.at(-1).to, 'notify-superadmin@example.test');
  });
});
