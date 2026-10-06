import { useEffect, useState, useCallback, useMemo } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import api from '../api/axios';
import { useAuth } from '../context/AuthContext';
import { openRazorpay } from '../utils/razorpay';
import Swal from 'sweetalert2';
import EnterprisePurchase from '../components/EnterprisePurchase';

const fmtInr  = (n) => `₹${Number(n || 0).toLocaleString('en-IN')}`;
const fmtDate = (d) => d ? new Date(d).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' }) : '—';
const fmtShort = (d) => d ? new Date(d).toLocaleDateString('en-IN', { day: '2-digit', month: 'short' }) : '—';

const StatusBadge = ({ status, active, nearExpiry }) => {
  if (status === 'expired') return <span style={{ background: 'rgba(239,68,68,0.15)', color: '#f87171', border: '1px solid #ef4444', padding: '2px 10px', borderRadius: 20, fontSize: 11, fontWeight: 700 }}>Expired</span>;
  if (!active) return <span style={{ background: 'rgba(245,158,11,0.15)', color: '#fbbf24', border: '1px solid #f59e0b', padding: '2px 10px', borderRadius: 20, fontSize: 11, fontWeight: 700 }}>Inactive</span>;
  if (nearExpiry) return <span style={{ background: 'rgba(245,158,11,0.15)', color: '#fbbf24', border: '1px solid #f59e0b', padding: '2px 10px', borderRadius: 20, fontSize: 11, fontWeight: 700 }}>⚠️ Near Expiry</span>;
  return <span style={{ background: 'rgba(16,185,129,0.15)', color: '#34d399', border: '1px solid #10b981', padding: '2px 10px', borderRadius: 20, fontSize: 11, fontWeight: 700 }}>Active</span>;
};

const generateInvoiceData = (item, user, company) => {
  const compName = company?.name || user?.companyName || user?.name || 'Company Client';
  const compEmail = company?.email || user?.email || 'N/A';
  const rawId = String(item?.paymentId || item?.orderId || item?._id || 'SOC');
  const invNumber = `INV-${rawId.slice(-8).toUpperCase()}`;
  const date = fmtDate(item?.paidAt || item?.addedDate || item?.startDate || new Date());
  const periodStart = item?.periodStart || item?.startDate || item?.addedDate || new Date();
  const periodEnd = item?.periodEnd || item?.endDate || item?.expiresAt || new Date(Date.now() + 30 * 24 * 3600 * 1000);
  const period = `${fmtDate(periodStart)} – ${fmtDate(periodEnd)}`;

  let description = 'Spartan Cyber Defense Center (SCDC) Plan Subscription';
  if (item?.addedSystemCount || item?.addedSystems) {
    const sys = item.addedSystemCount || item.addedSystems || 0;
    const srv = item.addedServerCount || item.addedServers || 0;
    const phn = item.addedPhoneCount || item.addedPhones || 0;
    description = `Add-System Batch (+${sys} Systems${srv ? `, +${srv} Servers` : ''}${phn ? `, +${phn} Phones` : ''})`;
  } else if (item?.planType) {
    description = `${item.planType} Plan Subscription`;
  } else if (item?.systemCount) {
    description = `Subscription (${item.systemCount} Systems, ${item.serverCount || 0} Servers, ${item.phoneCount || 0} Phones)`;
  }

  const amount = item?.amountInr || item?.totalInr || (item?.amountPaise ? item.amountPaise / 100 : 0) || 0;
  const subtotal = Number((amount / 1.18).toFixed(2));
  const gst = Number((amount - subtotal).toFixed(2));

  return {
    type: 'invoice',
    number: invNumber,
    date,
    period,
    description,
    amount,
    subtotal,
    gst,
    companyName: compName,
    companyEmail: compEmail,
    paymentId: item?.paymentId || item?.orderId || 'N/A',
    billingCycle: item?.billingCycle ? (item.billingCycle.charAt(0).toUpperCase() + item.billingCycle.slice(1)) : 'Monthly',
    status: 'PROCESSED',
  };
};

const generateReceiptData = (item, user, company) => {
  const compName = company?.name || user?.companyName || user?.name || 'Company Client';
  const compEmail = company?.email || user?.email || 'N/A';
  const rawId = String(item?.paymentId || item?.orderId || item?._id || 'SOC');
  const rcpNumber = `RCP-${rawId.slice(-8).toUpperCase()}`;
  const date = fmtDate(item?.paidAt || item?.addedDate || item?.startDate || new Date());

  let description = 'Base Subscription';
  if (item?.addedSystemCount || item?.addedSystems) {
    const sys = item.addedSystemCount || item.addedSystems || 0;
    const srv = item.addedServerCount || item.addedServers || 0;
    const phn = item.addedPhoneCount || item.addedPhones || 0;
    description = `Add-System Batch (+${sys} Systems${srv ? `, +${srv} Servers` : ''}${phn ? `, +${phn} Phones` : ''})`;
  } else if (item?.planType) {
    description = `${item.planType}`;
  } else if (item?.systemCount) {
    description = `${item.systemCount} Systems, ${item.serverCount || 0} Servers, ${item.phoneCount || 0} Phones`;
  }

  const amount = item?.amountInr || item?.totalInr || (item?.amountPaise ? item.amountPaise / 100 : 0) || 0;

  return {
    type: 'receipt',
    number: rcpNumber,
    date,
    description,
    amount,
    companyName: compName,
    companyEmail: compEmail,
    paymentId: item?.paymentId || item?.orderId || 'N/A',
    billingCycle: item?.billingCycle ? (item.billingCycle.charAt(0).toUpperCase() + item.billingCycle.slice(1)) : 'Monthly',
    status: 'PROCESSED',
  };
};

const handlePrintDocument = (doc) => {
  const printWindow = window.open('', '_blank', 'width=800,height=900');
  if (!printWindow) return;

  const isInvoice = doc.type === 'invoice';
  const title = isInvoice ? `Invoice_${doc.number}` : `Receipt_${doc.number}`;

  const receiptHtml = `
    <!DOCTYPE html>
    <html>
      <head>
        <title>${title}</title>
        <style>
          * { box-sizing: border-box; }
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #f1f5f9; color: #1e293b; margin: 0; padding: 40px 20px; display: flex; justify-content: center; }
          .receipt-container { width: 100%; max-width: 540px; background: #ffffff; border-radius: 20px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.08); border: 1px solid #e2e8f0; }
          .header-banner { background: #0d542b; padding: 36px 20px 28px; text-align: center; color: #ffffff; }
          .check-badge { display: inline-flex; align-items: center; justify-content: center; width: 56px; height: 56px; background: #84cc16; color: #ffffff; border-radius: 14px; font-size: 32px; font-weight: bold; margin: 0 auto 14px; box-shadow: 0 4px 10px rgba(0,0,0,0.15); }
          .header-title { font-size: 26px; font-weight: 800; margin-bottom: 4px; letter-spacing: -0.5px; }
          .header-sub { font-size: 13px; color: #86efac; font-weight: 500; }
          .body-content { padding: 30px 36px; }
          .amount-box { background: #eefdf4; border: 1px solid #bbf7d0; border-radius: 16px; padding: 24px; text-align: center; margin-bottom: 28px; }
          .amount-val { font-size: 38px; font-weight: 900; color: #15803d; letter-spacing: -0.5px; }
          .amount-label { font-size: 13px; color: #4b5563; font-weight: 600; margin-top: 4px; }
          .detail-list { display: flex; flex-direction: column; gap: 0; }
          .detail-row { display: flex; justify-content: space-between; align-items: center; padding: 14px 0; border-bottom: 1px solid #f1f5f9; font-size: 14px; }
          .detail-row:last-child { border-bottom: none; }
          .detail-label { color: #64748b; font-weight: 500; }
          .detail-val { color: #0f172a; font-weight: 700; text-align: right; }
          .font-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
          .status-badge { color: #166534; font-weight: 800; display: inline-flex; align-items: center; gap: 4px; }
          .footer-text { background: #f8fafc; padding: 18px 20px; text-align: center; font-size: 12px; color: #94a3b8; border-top: 1px solid #f1f5f9; }
          @media print {
            body { background: #fff; padding: 0; }
            .receipt-container { box-shadow: none; border: none; max-width: 100%; }
          }
        </style>
      </head>
      <body>
        <div class="receipt-container">
          <div class="header-banner">
            <div class="check-badge">✓</div>
            <div class="header-title">Payment Receipt</div>
            <div class="header-sub">Spartan Cyber Defense Center (SCDC)</div>
          </div>
          <div class="body-content">
            <div class="amount-box">
              <div class="amount-val">₹${Number(doc.amount || 0).toFixed(2)}</div>
              <div class="amount-label">Amount Paid</div>
            </div>
            <div class="detail-list">
              <div class="detail-row"><span class="detail-label">Receipt No.</span><span class="detail-val font-mono">${doc.number}</span></div>
              <div class="detail-row"><span class="detail-label">Customer</span><span class="detail-val">${doc.companyName}</span></div>
              <div class="detail-row"><span class="detail-label">Email</span><span class="detail-val">${doc.companyEmail}</span></div>
              <div class="detail-row"><span class="detail-label">Plan</span><span class="detail-val">${doc.description}</span></div>
              <div class="detail-row"><span class="detail-label">Billing Cycle</span><span class="detail-val">${doc.billingCycle}</span></div>
              <div class="detail-row"><span class="detail-label">Payment Date</span><span class="detail-val">${doc.date}</span></div>
              <div class="detail-row"><span class="detail-label">Payment ID</span><span class="detail-val font-mono">${doc.paymentId}</span></div>
              <div class="detail-row"><span class="detail-label">Status</span><span class="detail-val status-badge">✓ PROCESSED</span></div>
            </div>
          </div>
          <div class="footer-text">
            Thank you for your payment! &nbsp;|&nbsp; Spartan Cyber Defense Center (SCDC) © 2026
          </div>
        </div>
        <script>window.onload = function() { window.print(); }</script>
      </body>
    </html>
  `;

  const invoiceHtml = `
    <!DOCTYPE html>
    <html>
      <head>
        <title>${title}</title>
        <style>
          * { box-sizing: border-box; }
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #f1f5f9; color: #1e293b; margin: 0; padding: 40px 20px; display: flex; justify-content: center; }
          .invoice-container { width: 100%; max-width: 680px; background: #ffffff; border-radius: 20px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.08); border: 1px solid #e2e8f0; }
          .header-banner { background: #80001a; padding: 32px 36px; color: #ffffff; display: flex; justify-content: space-between; align-items: flex-start; }
          .brand-title { font-size: 22px; font-weight: 900; letter-spacing: -0.5px; margin-bottom: 4px; }
          .brand-sub { font-size: 13px; color: #fca5a5; font-weight: 500; }
          .inv-title { font-size: 26px; font-weight: 900; text-transform: uppercase; letter-spacing: 1px; text-align: right; }
          .inv-num { font-size: 13px; color: #fca5a5; margin-top: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-weight: 700; text-align: right; }
          .body-content { padding: 36px; }
          .grid-details { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 32px; font-size: 13px; }
          .grid-title { font-size: 11px; text-transform: uppercase; color: #94a3b8; font-weight: 800; letter-spacing: 0.5px; margin-bottom: 8px; }
          .customer-name { font-size: 16px; font-weight: 800; color: #0f172a; margin-bottom: 2px; }
          .customer-email { color: #64748b; }
          .badge-processed { display: inline-block; background: #fef08a; color: #854d0e; font-weight: 800; font-size: 11px; padding: 2px 8px; border-radius: 6px; text-transform: uppercase; }
          .inv-table { width: 100%; border-collapse: collapse; margin-bottom: 28px; }
          .inv-table th { background: #f8fafc; padding: 12px 16px; text-align: left; font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: 800; border-bottom: 1px solid #e2e8f0; letter-spacing: 0.5px; }
          .inv-table td { padding: 16px; border-bottom: 1px solid #f1f5f9; font-size: 14px; color: #334155; }
          .total-row { background: #fff5f5; }
          .total-row td { border-bottom: none; padding: 18px 16px; }
          .validity-text { font-size: 12px; color: #94a3b8; margin-bottom: 24px; font-weight: 500; }
          .footer-text { background: #f8fafc; padding: 18px 20px; text-align: center; font-size: 12px; color: #94a3b8; border-top: 1px solid #f1f5f9; }
          .font-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
          @media print {
            body { background: #fff; padding: 0; }
            .invoice-container { box-shadow: none; border: none; max-width: 100%; }
          }
        </style>
      </head>
      <body>
        <div class="invoice-container">
          <div class="header-banner">
            <div>
              <div class="brand-title">Spartan Cyber Defense Center (SCDC)</div>
              <div class="brand-sub">Security Assessment Platform</div>
            </div>
            <div>
              <div class="inv-title">INVOICE</div>
              <div class="inv-num">${doc.number}</div>
            </div>
          </div>
          <div class="body-content">
            <div class="grid-details">
              <div>
                <div class="grid-title">BILLED TO</div>
                <div class="customer-name">${doc.companyName}</div>
                <div class="customer-email">${doc.companyEmail}</div>
              </div>
              <div>
                <div class="grid-title">INVOICE DETAILS</div>
                <div style="margin-bottom: 4px;"><strong>Date:</strong> ${doc.date}</div>
                <div style="margin-bottom: 4px;"><strong>Status:</strong> <span class="badge-processed">PROCESSED</span></div>
                <div><strong>Payment ID:</strong> <span class="font-mono">${doc.paymentId}</span></div>
              </div>
            </div>

            <table class="inv-table">
              <thead>
                <tr>
                  <th style="text-align: left;">DESCRIPTION</th>
                  <th style="text-align: center;">BILLING CYCLE</th>
                  <th style="text-align: right;">AMOUNT</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><strong style="color: #0f172a;">${doc.description}</strong></td>
                  <td style="text-align: center; font-weight: 600;">${doc.billingCycle}</td>
                  <td style="text-align: right; font-weight: 700; color: #0f172a;">₹${Number(doc.subtotal || doc.amount || 0).toFixed(2)}</td>
                </tr>
                <tr>
                  <td style="color: #64748b;">GST (18%)</td>
                  <td></td>
                  <td style="text-align: right; color: #64748b; font-weight: 600;">₹${Number(doc.gst || 0).toFixed(2)}</td>
                </tr>
                <tr class="total-row">
                  <td colspan="2" style="font-weight: 800; color: #80001a; font-size: 16px;">Total Paid</td>
                  <td style="text-align: right; font-weight: 900; color: #80001a; font-size: 20px;">₹${Number(doc.amount || 0).toFixed(2)}</td>
                </tr>
              </tbody>
            </table>

            ${doc.period ? `<div class="validity-text">Valid From: ${doc.period.split('–')[0]?.trim()} &nbsp;|&nbsp; Valid Until: ${doc.period.split('–')[1]?.trim() || doc.period}</div>` : ''}
          </div>
          <div class="footer-text">
            This is a computer-generated invoice. No signature required. &nbsp;|&nbsp; Spartan Cyber Defense Center (SCDC) © 2026
          </div>
        </div>
        <script>window.onload = function() { window.print(); }</script>
      </body>
    </html>
  `;

  printWindow.document.open();
  printWindow.document.write(isInvoice ? invoiceHtml : receiptHtml);
  printWindow.document.close();
};

function CompanyPaymentsPage() {
  const { user, setCompany, refreshCompany, isImpersonating } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  // Base plan
  const [status,       setStatus]       = useState(null);
  const [history,      setHistory]      = useState([]);
  const [renewalPricing, setRenewalPricing] = useState(null);
  const [loading,      setLoading]      = useState(true);

  // Add-system batches
  const [batches,      setBatches]      = useState([]);
  const [batchLoading, setBatchLoading] = useState(false);

  // Add-system form
  const [addSystems,   setAddSystems]   = useState(0);
  const [addServers,   setAddServers]   = useState(0);
  const [addPhones,    setAddPhones]    = useState(0);
  const [addCycle,     setAddCycle]     = useState('monthly');
  const [addCalc,      setAddCalc]      = useState(null);
  const [addCalcLoad,  setAddCalcLoad]  = useState(false);
  const [serverDetails, setServerDetails] = useState('');

  // First-time activation when registration skipped plan payment
  const [activateSystems, setActivateSystems] = useState(10);
  const [activateServers, setActivateServers] = useState(0);
  const [activatePhones,  setActivatePhones]  = useState(0);
  const [activateCycle,   setActivateCycle]   = useState('monthly');
  const [activateCalc,    setActivateCalc]    = useState(null);
  const [activateCalcLoad, setActivateCalcLoad] = useState(false);

  // Renewal
  const [renewMode,    setRenewMode]    = useState('base'); // 'base' | 'batch' | 'enterprise'
  const [renewCycle,   setRenewCycle]   = useState('monthly');
  const [renewCalc,    setRenewCalc]    = useState(null);
  const [renewLoading, setRenewLoading] = useState(false);
  const [selectedBatch, setSelectedBatch] = useState(null);
  const [batchRenewCycle, setBatchRenewCycle] = useState('monthly');
  const [batchRenewCalc, setBatchRenewCalc] = useState(null);
  const [batchRenewLoad, setBatchRenewLoad] = useState(false);

  const [busy,       setBusy]       = useState(false);
  const [error,      setError]      = useState('');
  const [activeTab,  setActiveTab]  = useState('subscription');
  const [docModal,   setDocModal]   = useState(null);

  const openInvoiceModal = (item) => {
    const inv = generateInvoiceData(item, user, status?.company || status);
    setDocModal(inv);
  };

  const openReceiptModal = (item) => {
    const rcp = generateReceiptData(item, user, status?.company || status);
    setDocModal(rcp);
  };

  useEffect(() => {
    const tab = new URLSearchParams(location.search).get('tab');
    if (['upgrade', 'enterprise'].includes(tab)) setActiveTab(tab);
  }, [location.search]);

  // ── Load data ──────────────────────────────────────────────────────────────
  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [statusRes, histRes, pricingRes] = await Promise.all([
        api.get('/payment/status'),
        api.get('/payment/history').catch(() => ({ data: [] })),
        api.get('/pricing').catch(() => ({ data: {} })),
      ]);
      setStatus(statusRes.data);
      setHistory(histRes.data || []);
      const pricing = pricingRes.data || {};
      setRenewalPricing(pricing.renewal ? {
	        pricePerSystemMonthly: pricing.renewal.pricePerSystemMonthly,
	        pricePerSystemYearly:  pricing.renewal.pricePerSystemYearly,
	        pricePerPhoneMonthly:  pricing.renewal.pricePerPhoneMonthly ?? pricing.renewal.pricePerSystemMonthly,
	        pricePerPhoneYearly:   pricing.renewal.pricePerPhoneYearly ?? pricing.renewal.pricePerSystemYearly,
	        pricePerServerMonthly: pricing.renewal.pricePerServerMonthly,
        pricePerServerYearly:  pricing.renewal.pricePerServerYearly,
      } : null);
    } catch (err) {
      setError('Failed to load payment data');
    } finally {
      setLoading(false);
    }
  }, []);

  const loadBatches = useCallback(async () => {
    setBatchLoading(true);
    try {
      const { data } = await api.get('/add-system/list');
      setBatches(data || []);
    } catch { setBatches([]); }
    finally { setBatchLoading(false); }
  }, []);

  useEffect(() => {
    let alive = true;
    (async () => {
      // Keep effective totals current and recover preserved base quantities for
      // companies affected by older recalculation behavior.
      await api.post('/add-system/recalculate').catch(() => {});
      if (!alive) return;
      await Promise.all([loadData(), loadBatches(), refreshCompany()]);
    })();
    return () => { alive = false; };
  }, [loadData, loadBatches, refreshCompany]);
  useEffect(() => {
    if (activeTab === 'upgrade' || activeTab === 'renewal') {
      loadBatches();
      // ✅ Auto-recalculate systemCount when tab opens
      // This fixes existing companies whose plan.systemCount wasn't updated correctly
      if (activeTab === 'upgrade') {
        api.post('/add-system/recalculate').then(({ data }) => {
          if (data?.success && data.systemCount !== undefined) {
            // Update company in context so Dashboard/SystemsPage see new total
            refreshCompany();
          }
        }).catch(() => {});
      }
    }
  }, [activeTab, loadBatches, refreshCompany]);


  // ── Add-system cost calc ───────────────────────────────────────────────────
  useEffect(() => {
    const sys = Number(addSystems) || 0;
    const srv = Number(addServers) || 0;
    const phn = Number(addPhones) || 0;
    if (activeTab !== 'upgrade' || (sys === 0 && srv === 0 && phn === 0)) { setAddCalc(null); return; }
    const t = setTimeout(async () => {
      setAddCalcLoad(true);
      try {
        const { data } = await api.post(status?.enterpriseSubscriptionId ? '/payment/enterprise/addition/calculate' : '/add-system/calculate', { systemCount: sys, serverCount: srv, phoneCount: phn, billingCycle: addCycle });
        setAddCalc(data);
      } catch (err) { setAddCalc(null); setError(err.response?.data?.message || 'Unable to calculate license cost.'); }
      finally { setAddCalcLoad(false); }
    }, 400);
    return () => clearTimeout(t);
	  }, [addSystems, addServers, addPhones, addCycle, activeTab, status?.enterpriseSubscriptionId]);

  // ── First-time activation cost calc ─────────────────────────────────────────
  useEffect(() => {
    const plan = status?.plan;
    const hasPaidPlan = plan?.paymentStatus === 'paid' || plan?.isActive === true;
    const hasCounts = Number(plan?.systemCount || 0) + Number(plan?.serverCount || 0) + Number(plan?.phoneCount || 0) > 0;
    const needsActivation = activeTab === 'subscription' && !hasPaidPlan && !hasCounts;
    const sys = Number(activateSystems) || 0;
    const srv = Number(activateServers) || 0;
    const phn = Number(activatePhones) || 0;

    if (!needsActivation || (sys === 0 && srv === 0 && phn === 0)) { setActivateCalc(null); return; }

    const t = setTimeout(async () => {
      setActivateCalcLoad(true);
      try {
        const { data } = await api.post('/payment/calculate', {
          systemCount: sys,
          serverCount: srv,
          phoneCount: phn,
          billingCycle: activateCycle,
          isUpgrade: false,
        });
        setActivateCalc(data);
      } catch {
        setActivateCalc(null);
      } finally {
        setActivateCalcLoad(false);
      }
    }, 350);

    return () => clearTimeout(t);
  }, [status, activeTab, activateSystems, activateServers, activatePhones, activateCycle]);

  // ── Base renewal cost calc (uses ONLY registration base count) ───────────────
  useEffect(() => {
	    const plan = status?.plan;
	    // ✅ Use baseSystemCount (registration only) — not systemCount (total includes add-batches)
	    const baseSys = plan?.baseSystemCount > 0 ? plan.baseSystemCount : plan?.systemCount || 0;
	    const baseSrv = plan?.baseServerCount > 0 ? plan.baseServerCount : plan?.serverCount || 0;
	    const basePhn = plan?.basePhoneCount > 0 ? plan.basePhoneCount : plan?.phoneCount || 0;
    if (activeTab !== 'renewal' || renewMode !== 'base' || (status?.enterpriseSubscriptionId && plan?.paymentStatus !== 'paid') || (baseSys === 0 && baseSrv === 0 && basePhn === 0)) { setRenewCalc(null); return; }
    const t = setTimeout(async () => {
      setRenewLoading(true);
      try {
	        const { data } = await api.post('/payment/calculate', {
	          systemCount: baseSys, serverCount: baseSrv, phoneCount: basePhn,
	          billingCycle: renewCycle, isUpgrade: true,
	        });
	        setRenewCalc({ ...data, baseSys, baseSrv, basePhn });
      } catch { setRenewCalc(null); }
      finally { setRenewLoading(false); }
    }, 300);
    return () => clearTimeout(t);
  }, [renewCycle, status, activeTab, renewMode]);


  // ── Batch renewal cost calc ───────────────────────────────────────────────
  useEffect(() => {
    if (activeTab !== 'renewal' || renewMode !== 'batch' || !selectedBatch) { setBatchRenewCalc(null); return; }
    const t = setTimeout(async () => {
      setBatchRenewLoad(true);
      try {
        const { data } = await api.post('/add-system/calculate', {
          systemCount: selectedBatch.addedSystemCount,
          serverCount: selectedBatch.addedServerCount || 0,
          phoneCount: selectedBatch.addedPhoneCount || 0,
          billingCycle: batchRenewCycle,
        });
        setBatchRenewCalc(data);
      } catch { setBatchRenewCalc(null); }
      finally { setBatchRenewLoad(false); }
    }, 300);
    return () => clearTimeout(t);
  }, [batchRenewCycle, selectedBatch, activeTab, renewMode]);

  // ── Derived state ─────────────────────────────────────────────────────────
	  const plan      = status?.plan;
	  const now       = new Date();
	  const enterprisePrimary = batches.find(b => String(b._id) === String(status?.enterpriseSubscriptionId));
  const enterpriseRegistration = Boolean(status?.enterpriseSubscriptionId) && plan?.paymentStatus !== 'paid';
  const expiresAt = new Date((enterpriseRegistration ? enterprisePrimary?.endDate : plan?.expiresAt) || 0);
	  const planActive = (enterpriseRegistration ? enterprisePrimary?.status === 'active' : plan?.isActive) && now < expiresAt;
	  const nearExpiry  = planActive && (expiresAt - now) < 7 * 24 * 60 * 60 * 1000;
	  const showRenewal = !planActive || nearExpiry;
  const hasPurchasedPlan = plan?.paymentStatus === 'paid' || Number(plan?.systemCount || 0) + Number(plan?.serverCount || 0) + Number(plan?.phoneCount || 0) > 0;
  const needsBaseActivation = !enterpriseRegistration && !planActive && !hasPurchasedPlan;

  // Active batches (for renewal dropdown)
  const activeBatches  = batches.filter(b => b.status === 'active');
  const expiredBatches = batches.filter(b => b.status === 'expired');
  const addedSystemCount = activeBatches.reduce((s, b) => s + (Number(b.addedSystemCount) || 0), 0);
  const addedServerCount = activeBatches.reduce((s, b) => s + (Number(b.addedServerCount) || 0), 0);
  const addedPhoneCount = activeBatches.reduce((s, b) => s + (Number(b.addedPhoneCount) || 0), 0);
  const totalSystemCount = Number(plan?.systemCount) || addedSystemCount;
  const totalServerCount = Number(plan?.serverCount) || addedServerCount;
  const totalPhoneCount = Number(plan?.phoneCount) || addedPhoneCount;
  const baseSystemCount = Number(plan?.baseSystemCount) || Math.max(0, totalSystemCount - addedSystemCount);
  const baseServerCount = Number(plan?.baseServerCount) || Math.max(0, totalServerCount - addedServerCount);
  const basePhoneCount = Number(plan?.basePhoneCount) || Math.max(0, totalPhoneCount - addedPhoneCount);
  const currentPlanTitle = enterpriseRegistration ? '🏢 Enterprise (Registration)' : 'Base Subscription (Registration)';
  const currentPlanSystems = enterpriseRegistration ? Number(enterprisePrimary?.addedSystemCount || 0) : baseSystemCount;
  const currentPlanServers = enterpriseRegistration ? Number(enterprisePrimary?.addedServerCount || 0) : baseServerCount;
  const currentPlanPhones = enterpriseRegistration ? Number(enterprisePrimary?.addedPhoneCount || 0) : basePhoneCount;
  const currentBillingCycle = enterpriseRegistration ? enterprisePrimary?.billingCycle : plan?.billingCycle;
  const currentAmountPaid = enterpriseRegistration ? enterprisePrimary?.amountPaid : plan?.amountPaid;
  const currentPaymentStatus = enterpriseRegistration ? enterprisePrimary?.paymentStatus : plan?.paymentStatus;
  const currentStartDate = enterpriseRegistration ? enterprisePrimary?.startDate : plan?.startDate;
  const currentEndDate = enterpriseRegistration ? enterprisePrimary?.endDate : plan?.expiresAt;
  const currentPaymentId = enterpriseRegistration ? enterprisePrimary?.paymentId : status?.razorpay?.paymentId;
  const partnerStock = status?.partnerLicenseStock || {};
  const addRequestedLicenses = (Number(addSystems) || 0) + (Number(addServers) || 0) + (Number(addPhones) || 0);
  const partnerStockBlocked = Boolean(partnerStock.limited) && addRequestedLicenses > Number(partnerStock.available || 0);

	  // ── Handlers ──────────────────────────────────────────────────────────────

  const handleActivatePlan = async () => {
    if (isImpersonating) return setError('Payments are disabled during Super Admin partner login.');
    const sys = Number(activateSystems) || 0;
    const srv = Number(activateServers) || 0;
    const phn = Number(activatePhones) || 0;
    if (!activateCalc || activateCalc.totalInr <= 0 || (sys === 0 && srv === 0 && phn === 0)) {
      Swal.fire({ icon: 'warning', title: 'Invalid', text: 'Add at least 1 system, server, or phone.', background: '#0c1a2e', color: '#e0f2fe' });
      return;
    }

    navigate('/checkout', { state: { checkout: {
      mode: 'base',
      planName: 'Premium',
      description: `Activate Plan: ${sys} Systems, ${srv} Servers, ${phn} Phones`,
      counts: { systemCount: sys, serverCount: srv, phoneCount: phn },
      billingCycle: activateCycle,
      amountInr: activateCalc.totalInr,
      calc: activateCalc,
      isUpgrade: false,
      autoPay: true,
      email: user?.email,
      returnTo: '/payments',
    } } });
  };

	  // Add systems payment
	  const handleAddSystems = async () => {
      if (isImpersonating) return setError('Payments are disabled during Super Admin partner login.');
	    const sys = Number(addSystems) || 0;
	    const srv = Number(addServers) || 0;
	    const phn = Number(addPhones) || 0;
	    if (!addCalc || addCalc.totalInr <= 0 || (sys === 0 && srv === 0 && phn === 0)) {
	      Swal.fire({ icon: 'warning', title: 'Invalid', text: 'Add at least 1 system, server, or phone.', background: '#0c1a2e', color: '#e0f2fe' });
	      return;
	    }
    if (partnerStock.limited && (sys + srv + phn) > Number(partnerStock.available || 0)) {
      Swal.fire({
        icon: 'warning',
        title: 'Partner License Stock Required',
        text: `Only ${partnerStock.available || 0} partner license(s) are available. Please ask the Partner Admin to purchase more licenses first.`,
        background: '#0c1a2e',
        color: '#e0f2fe',
      });
      return;
    }
    navigate('/checkout', { state: { checkout: {
      mode: addCalc.enterprise ? 'enterprise-addition' : 'add-system',
      purchaseKey: addCalc.enterprise ? crypto.randomUUID() : undefined,
      totals: addCalc.enterprise ? addCalc.totals : undefined,
      periodEnd: addCalc.periodEnd,
      planName: 'Add More Licenses',
      description: `Add: +${sys} Systems, +${srv} Servers, +${phn} Phones`,
      counts: { systemCount: sys, serverCount: srv, phoneCount: phn },
      billingCycle: addCalc.billingCycle || addCycle,
      amountInr: addCalc.totalInr,
      calc: addCalc,
      serverDetails,
      email: user?.email,
      returnTo: '/payments',
    } } });
  };

  // Base plan renewal
  const handleBaseRenewal = async () => {
      if (isImpersonating) return setError('Payments are disabled during Super Admin partner login.');
	    const plan = status?.plan;
	    // ✅ FIX: Renew ONLY base systems (registration count)
	    const baseSys = plan?.baseSystemCount > 0 ? plan.baseSystemCount : plan?.systemCount || 0;
	    const baseSrv = plan?.baseServerCount > 0 ? plan.baseServerCount : plan?.serverCount || 0;
	    const basePhn = plan?.basePhoneCount > 0 ? plan.basePhoneCount : plan?.phoneCount || 0;
	    if (!renewCalc || renewCalc.totalInr <= 0 || (baseSys === 0 && baseSrv === 0 && basePhn === 0)) {
	      Swal.fire({ icon: 'warning', title: 'Cannot Renew', text: 'No base plan found.', background: '#0c1a2e', color: '#e0f2fe' });
	      return;
	    }
    navigate('/checkout', { state: { checkout: {
      mode: 'base',
      planName: 'Base Renewal',
      description: `Base Plan Renewal: ${baseSys} Systems, ${baseSrv} Servers, ${basePhn} Phones`,
      counts: { systemCount: baseSys, serverCount: baseSrv, phoneCount: basePhn },
      billingCycle: renewCycle,
      amountInr: renewCalc.totalInr,
      calc: renewCalc,
      isUpgrade: true,
      email: user?.email,
      returnTo: '/payments',
    } } });
  };

  // Batch renewal
  const handleBatchRenewal = async () => {
    if (isImpersonating) return setError('Payments are disabled during Super Admin partner login.');
    if (!selectedBatch || !batchRenewCalc) return;
    navigate('/checkout', { state: { checkout: {
      mode: 'batch-renewal',
      batchId: selectedBatch._id,
      planName: 'Batch Renewal',
      description: `Batch Renewal: +${selectedBatch.addedSystemCount} Systems, +${selectedBatch.addedServerCount || 0} Servers, +${selectedBatch.addedPhoneCount || 0} Phones`,
      counts: {
        systemCount: selectedBatch.addedSystemCount,
        serverCount: selectedBatch.addedServerCount || 0,
        phoneCount: selectedBatch.addedPhoneCount || 0,
      },
      billingCycle: batchRenewCycle,
      amountInr: batchRenewCalc.totalInr,
      calc: batchRenewCalc,
      email: user?.email,
      returnTo: '/payments',
    } } });
  };

  // AutoPay: base plan disable (free)
  const handleBaseAutoPayDisable = async () => {
    if (isImpersonating) return setError('AutoPay changes are disabled during Super Admin partner login.');
    try {
      const { data } = await api.post('/payment/autopay', { enabled: false });
      setStatus(data.company);
      await loadBatches();
      Swal.fire({ icon: 'success', title: 'AutoPay Disabled', text: 'Base plan and all active Add-System batches are now AutoPay disabled.', timer: 2200, showConfirmButton: false, background: '#0c1a2e', color: '#e0f2fe' });
    } catch (err) { setError(err.response?.data?.message || 'Failed'); }
  };

  // AutoPay: base plan enable
  const handleBaseAutoPayEnable = async () => {
    if (isImpersonating) return setError('AutoPay changes are disabled during Super Admin partner login.');
    const confirm = await Swal.fire({
      icon: 'info', title: '🔄 Enable AutoPay',
      html: `<p style="font-size:14px;color:#94a3b8">Authorize a real recurring PhonePe/UPI AutoPay mandate through Razorpay Subscriptions.</p>`,
      showCancelButton: true, confirmButtonText: 'Authorize AutoPay',
      confirmButtonColor: '#10b981', cancelButtonColor: '#374151',
      background: '#0c1a2e', color: '#e0f2fe',
    });
    if (!confirm.isConfirmed) return;
    setBusy(true);
    try {
      const { data } = await api.post('/payment/autopay-order');
      await openRazorpay({
        order: data.order, subscription: data.subscription, planLabel: 'Base Plan AutoPay', email: user?.email,
        onSuccess: async (response) => {
          const { data: confirmed } = await api.post('/payment/autopay-confirm', response);
          setStatus(confirmed.company);
          await Swal.fire({ icon: 'success', title: '✅ AutoPay Enabled!', text: 'Base plan AutoPay mandate is now enabled.', background: '#0c1a2e', color: '#e0f2fe' });
          loadData();
        },
        onFailure: (msg) => setError(`AutoPay payment failed: ${msg}`),
      });
    } catch (err) { setError(err.response?.data?.message || err.message); }
    finally { setBusy(false); }
  };

  // AutoPay: disable active add-system batches (free)
  const handleBatchAutoPayDisable = async (batch) => {
    if (isImpersonating) return setError('AutoPay changes are disabled during Super Admin partner login.');
    try {
      const { data } = await api.post(`/add-system/autopay/${batch._id}`, { enabled: false });
      if (Array.isArray(data.batches)) setBatches(data.batches);
      await loadBatches();
      Swal.fire({ icon: 'success', title: 'AutoPay Disabled', timer: 1800, showConfirmButton: false, background: '#0c1a2e', color: '#e0f2fe' });
    } catch (err) { setError(err.response?.data?.message || 'Failed'); }
  };

  // AutoPay: enable selected add-system batch
  const handleBatchAutoPayEnable = async (batch) => {
    if (isImpersonating) return setError('AutoPay changes are disabled during Super Admin partner login.');
    const activeBatchCount = batches.filter(b => {
      const end = new Date(b.endDate || 0);
      return b.status === 'active' && new Date() < end;
    }).length;
    const confirm = await Swal.fire({
      icon: 'info', title: '🔄 Enable AutoPay for Add Systems',
      html: `<p style="font-size:13px;color:#94a3b8">Authorize a real recurring PhonePe/UPI AutoPay mandate through Razorpay Subscriptions.</p>`,
      showCancelButton: true, confirmButtonText: 'Authorize AutoPay',
      confirmButtonColor: '#10b981', background: '#0c1a2e', color: '#e0f2fe',
    });
    if (!confirm.isConfirmed) return;
    setBusy(true);
    try {
      const { data } = await api.post(`/add-system/autopay-order/${batch._id}`);
      await openRazorpay({
        order: data.order, subscription: data.subscription, planLabel: `Batch AutoPay`, email: user?.email,
        onSuccess: async (response) => {
          const { data: confirmed } = await api.post(`/add-system/autopay-confirm/${batch._id}`, response);
          if (Array.isArray(confirmed.batches)) setBatches(confirmed.batches);
          await loadBatches();
          await Swal.fire({ icon: 'success', title: '✅ AutoPay Enabled for This Batch!', background: '#0c1a2e', color: '#e0f2fe' });
        },
        onFailure: (msg) => setError(`AutoPay failed: ${msg}`),
      });
    } catch (err) { setError(err.response?.data?.message || err.message); }
    finally { setBusy(false); }
  };

  const formatHistoryLicenses = (payment) => {
    if (payment.planType?.startsWith('enterprise')) return `🏢 ${payment.planType === 'enterprise_addition' ? 'Enterprise Add Systems' : 'Enterprise'}: +${payment.addedSystems ?? payment.systemCount ?? 0} Systems · +${payment.addedServers ?? payment.serverCount ?? 0} Servers · +${payment.addedPhones ?? payment.phoneCount ?? 0} Phones`;
    if (payment.planType === 'autopay_activation') return '🔄 AutoPay Activation Mandate';

    // 1. Add-System Batch / Upgrade
    if (payment.planType === 'add_system' || payment.notes?.type === 'add_system' || (payment.isUpgrade && payment.source !== 'renewal')) {
      const sys = Number(payment.addedSystems ?? payment.addedSystemCount ?? payment.systemCount) || 0;
      const srv = Number(payment.addedServers ?? payment.addedServerCount ?? payment.serverCount) || 0;
      const phn = Number(payment.addedPhones ?? payment.addedPhoneCount ?? payment.phoneCount) || 0;
      const parts = [
        sys > 0 ? `${sys} System${sys !== 1 ? 's' : ''}` : '',
        srv > 0 ? `${srv} Server${srv !== 1 ? 's' : ''}` : '',
        phn > 0 ? `${phn} Phone${phn !== 1 ? 's' : ''}` : '',
      ].filter(Boolean);
      return `⬆️ Add-System Batch: +${parts.join(' + ') || (sys ? `${sys} Systems` : '0 Licenses')}`;
    }

    // 2. Add-System Batch Renewal
    if (payment.planType === 'add_system_renewal' || payment.notes?.type === 'add_system_renewal') {
      const sys = Number(payment.addedSystems ?? payment.addedSystemCount ?? payment.systemCount) || 0;
      const srv = Number(payment.addedServers ?? payment.addedServerCount ?? payment.serverCount) || 0;
      const phn = Number(payment.addedPhones ?? payment.addedPhoneCount ?? payment.phoneCount) || 0;
      const parts = [
        sys > 0 ? `${sys} System${sys !== 1 ? 's' : ''}` : '',
        srv > 0 ? `${srv} Server${srv !== 1 ? 's' : ''}` : '',
        phn > 0 ? `${phn} Phone${phn !== 1 ? 's' : ''}` : '',
      ].filter(Boolean);
      return `🔄 Batch Renewal: +${parts.join(' + ') || (sys ? `${sys} Systems` : '0 Licenses')}`;
    }

    // 3. Base Plan Payment or Base Plan Renewal
    const sys = Number(payment.systemCount || payment.addedSystems || payment.addedSystemCount || payment.notes?.baseSystemCount) || 0;
    const srv = Number(payment.serverCount || payment.addedServers || payment.addedServerCount || payment.notes?.baseServerCount) || 0;
    const phn = Number(payment.phoneCount || payment.addedPhones || payment.addedPhoneCount || payment.notes?.basePhoneCount) || 0;

    const parts = [
      sys > 0 ? `${sys} System${sys !== 1 ? 's' : ''}` : '',
      srv > 0 ? `${srv} Server${srv !== 1 ? 's' : ''}` : '',
      phn > 0 ? `${phn} Phone${phn !== 1 ? 's' : ''}` : '',
    ].filter(Boolean);
    const label = parts.join(' + ') || (sys ? `${sys} Systems` : 'Base Subscription');

    if (payment.source === 'renewal' || payment.notes?.type === 'base_renewal') {
      return `🔄 Base Renewal: ${label}`;
    }
    return `🏠 Base Plan: ${label}`;
  };

  const combinedHistory = useMemo(() => {
    const list = [...history];

    batches.forEach(b => {
      const exists = list.some(h => 
        (h.paymentId && b.paymentId && h.paymentId === b.paymentId) || 
        String(h.notes?.batchId) === String(b._id) ||
        (h.orderId && b.orderId && h.orderId === b.orderId)
      );

      if (!exists && b._id) {
        const batchAmount = b.amountInr || b.amountPaid || (b.amountPaise ? b.amountPaise / 100 : 0) || b.price || 0;
        const bDate = b.addedDate || b.startDate || b.createdAt || new Date();
        list.push({
          _id: b._id,
          paymentId: b.paymentId || `ADD-${String(b._id).slice(-8)}`,
          paidAt: bDate,
          startDate: b.startDate || bDate,
          endDate: b.endDate,
          billingCycle: b.billingCycle || 'monthly',
          addedSystems: b.addedSystemCount || 0,
          addedServers: b.addedServerCount || 0,
          addedPhones: b.addedPhoneCount || 0,
          addedSystemCount: b.addedSystemCount || 0,
          addedServerCount: b.addedServerCount || 0,
          addedPhoneCount: b.addedPhoneCount || 0,
          amountInr: batchAmount,
          status: b.status === 'active' ? 'captured' : (b.status || 'captured'),
          planType: b.priceType?.startsWith('enterprise') ? b.priceType : 'add_system',
          isUpgrade: true,
          source: 'upgrade',
        });
      }
    });

    return list.sort((a, b) => new Date(b.paidAt || b.addedDate || b.startDate || b.createdAt || 0) - new Date(a.paidAt || a.addedDate || a.startDate || a.createdAt || 0));
  }, [history, batches]);

  // ── Tab config ────────────────────────────────────────────────────────────
  const tabs = [
    { id: 'subscription', label: '📊 Subscription' },
    { id: 'enterprise',   label: '🏢 Enterprise' },
    { id: 'upgrade',      label: 'Add Systems' },
    { id: 'renewal',      label: showRenewal ? '🔴 Renew Plan' : '🔄 Renew Plan' },
    { id: 'history',      label: '📋 History' },
  ];

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 300, color: '#60a5fa', fontSize: 14 }}>
      Loading payment data…
    </div>
  );

  const TabBtn = ({ tab }) => {
    const active  = activeTab === tab.id;
    const urgent  = tab.id === 'renewal' && showRenewal;
    return (
      <button onClick={() => setActiveTab(tab.id)} style={{
        padding: '8px 16px', border: 'none', borderRadius: 8,
        background: active ? (urgent ? 'rgba(239,68,68,0.2)' : '#1e3a5f') : 'transparent',
        color: active ? (urgent ? '#f87171' : '#93c5fd') : (urgent ? '#f87171' : '#475569'),
        fontSize: 13, cursor: 'pointer', fontWeight: active ? 700 : (urgent ? 600 : 400),
        outline: urgent ? '1px solid rgba(239,68,68,0.4)' : 'none',
        transition: 'all 0.2s',
      }}>{tab.label}</button>
    );
  };

  // ── Batch Table Row ───────────────────────────────────────────────────────
  const BatchRow = ({ b, idx, showRenewBtn = true }) => {
    const bEnd   = new Date(b.endDate || 0);
    const bNow   = new Date();
    const bActive = b.status === 'active' && bNow < bEnd;
    const bNear   = bActive && (bEnd - bNow) < 7 * 24 * 60 * 60 * 1000;
    return (
      <tr style={{ borderBottom: '1px solid #1e3a5f', background: idx % 2 === 0 ? 'rgba(0,0,0,0.15)' : 'transparent' }}>
	        <td style={td}>{fmtShort(b.addedDate)}{b.priceType?.startsWith('enterprise') && <div style={{ color: '#a5b4fc', fontSize: 11 }}>🏢 Enterprise{b.parentBatchId ? ' Add Systems' : ''}</div>}</td>
	        <td style={{ ...td, fontWeight: 700, color: '#60a5fa' }}>+{b.addedSystemCount}</td>
	        <td style={{ ...td, color: b.addedServerCount > 0 ? '#a78bfa' : '#334155' }}>
	          {[
	            b.addedServerCount > 0 ? `+${b.addedServerCount} srv` : '',
	            b.addedPhoneCount > 0 ? `+${b.addedPhoneCount} phone` : '',
	          ].filter(Boolean).join(' · ') || '—'}{b.serverDetails ? ` (${b.serverDetails})` : ''}
	        </td>
        <td style={td}>{fmtShort(b.startDate)}</td>
        <td style={{ ...td, color: bActive ? (bNear ? '#fbbf24' : '#94a3b8') : '#f87171' }}>{fmtShort(b.endDate)}</td>
        <td style={{ ...td, fontFamily: 'monospace', fontSize: 11 }}>{b.paymentId ? b.paymentId.slice(0, 14) + '…' : '—'}</td>
        <td style={td}>
          {b.status === 'active' && !b.priceType?.startsWith('enterprise') ? (
            <button onClick={() => b.autoPay ? handleBatchAutoPayDisable(b) : handleBatchAutoPayEnable(b)}
              style={{
                padding: '3px 12px', borderRadius: 20, cursor: 'pointer', fontSize: 11, fontWeight: 700, border: 'none',
                background: b.autoPay ? 'rgba(16,185,129,0.2)' : 'rgba(100,116,139,0.2)',
                color: b.autoPay ? '#34d399' : '#64748b',
                outline: `1px solid ${b.autoPay ? '#10b981' : '#475569'}`,
              }}>
              {b.autoPay ? '✅ ON' : '⏸ OFF'}
            </button>
          ) : <span style={{ color: '#334155', fontSize: 11 }}>—</span>}
        </td>
        <td style={td}>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
            <StatusBadge status={b.status} active={bActive} nearExpiry={bNear} />
            {showRenewBtn && b.status !== 'cancelled' && (
              <button
                onClick={() => { setRenewMode(b.priceType?.startsWith('enterprise') ? 'enterprise' : 'batch'); setSelectedBatch(b); setActiveTab('renewal'); }}
                style={{ padding: '3px 10px', borderRadius: 6, border: '1px solid #2563eb', background: 'rgba(37,99,235,0.15)', color: '#60a5fa', fontSize: 11, cursor: 'pointer', fontWeight: 600 }}>
                Renew
              </button>
            )}
            <button
              onClick={() => openInvoiceModal(b)}
              title="View & Download Invoice"
              style={{ padding: '3px 8px', borderRadius: 6, border: '1px solid #38bdf866', background: 'rgba(56,189,248,0.12)', color: '#38bdf8', fontSize: 11, cursor: 'pointer', fontWeight: 700 }}>
              📄 Invoice
            </button>
            <button
              onClick={() => openReceiptModal(b)}
              title="View & Download Receipt"
              style={{ padding: '3px 8px', borderRadius: 6, border: '1px solid #34d39966', background: 'rgba(52,211,153,0.12)', color: '#34d399', fontSize: 11, cursor: 'pointer', fontWeight: 700 }}>
              📧 Receipt
            </button>
          </div>
        </td>
      </tr>
    );
  };

  const th = { padding: '10px 12px', fontSize: 11, color: '#475569', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.4px', textAlign: 'left', whiteSpace: 'nowrap' };
  const td = { padding: '10px 12px', fontSize: 12, color: '#94a3b8', verticalAlign: 'middle' };

  return (
    <div>
      <h2 style={{ fontSize: 22, color: '#e0f2fe', marginBottom: 6, fontWeight: 700 }}>💳 Plans & Payments</h2>
      <p style={{ color: '#475569', fontSize: 13, marginBottom: 24 }}>
        Manage subscriptions, add licenses, renew, and view payment history
      </p>

      {error && (
        <div style={{ background: '#1c0a0a', color: '#fca5a5', padding: '10px 14px', borderRadius: 6, marginBottom: 16, fontSize: 13, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          {error}
          <button onClick={() => setError('')} style={{ background: 'none', border: 'none', color: '#fca5a5', cursor: 'pointer', fontSize: 16 }}>✕</button>
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 24, background: '#0c1a2e', padding: 4, borderRadius: 10, width: 'fit-content', flexWrap: 'wrap' }}>
        {tabs.map(t => <TabBtn key={t.id} tab={t} />)}
      </div>

      {/* ══════════ SUBSCRIPTION TAB ══════════ */}
      {activeTab === 'enterprise' && <EnterprisePurchase />}
	      {activeTab === 'subscription' && (
	        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
	          {needsBaseActivation && (
	            <div style={{ background: '#0c1a2e', borderRadius: 12, padding: 24, border: '1px solid #f59e0b' }}>
	              <h3 style={{ fontSize: 16, color: '#fcd34d', fontWeight: 700, marginBottom: 4 }}>Activate Your Base Plan</h3>
                  <button type="button" onClick={() => setActiveTab('enterprise')} style={{ padding: '9px 14px', border: '1px solid #6366f1', borderRadius: 7, background: '#1e1b4b', color: '#c7d2fe', cursor: 'pointer', marginBottom: 12 }}>Choose Enterprise — custom price for your company</button>
	              <p style={{ fontSize: 12, color: '#94a3b8', marginBottom: 18 }}>
	                Choose your first license counts and complete payment. Phones include Android and iPhone devices.
	              </p>

	              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 14, marginBottom: 16 }}>
	                {[
	                  { label: 'Systems', value: activateSystems, set: setActivateSystems, hint: 'Linux, Windows, macOS' },
	                  { label: 'Servers', value: activateServers, set: setActivateServers, hint: 'Server endpoints' },
	                  { label: 'Phones', value: activatePhones, set: setActivatePhones, hint: 'Android + iPhone' },
	                ].map(({ label, value, set, hint }) => (
	                  <div key={label}>
	                    <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 6 }}>{label}</label>
	                    <input
	                      type="number"
	                      min="0"
	                      value={value}
	                      onChange={e => set(e.target.value)}
	                      style={{ width: '100%', padding: '10px 12px', borderRadius: 6, boxSizing: 'border-box', background: '#060e1a', color: '#e2e8f0', fontSize: 20, fontWeight: 700, border: '1px solid #1e3a5f', textAlign: 'center' }}
	                    />
	                    <div style={{ fontSize: 10, color: '#475569', marginTop: 4 }}>{hint}</div>
	                  </div>
	                ))}
	              </div>

	              <div style={{ marginBottom: 16 }}>
	                <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 8 }}>Billing Cycle</label>
	                <div style={{ display: 'flex', gap: 8 }}>
	                  {['monthly', 'yearly'].map(c => (
	                    <div key={c} onClick={() => setActivateCycle(c)} style={{
	                      flex: 1, padding: '8px 12px', borderRadius: 6, cursor: 'pointer', textAlign: 'center',
	                      border: `2px solid ${activateCycle === c ? '#f59e0b' : '#1e3a5f'}`,
	                      background: activateCycle === c ? 'rgba(245,158,11,0.15)' : '#060e1a',
	                    }}>
	                      <span style={{ fontSize: 13, fontWeight: 700, color: activateCycle === c ? '#fcd34d' : '#475569', textTransform: 'capitalize' }}>{c}</span>
	                    </div>
	                  ))}
	                </div>
	              </div>

	              {activateCalcLoad && <div style={{ color: '#fcd34d', fontSize: 12, textAlign: 'center', padding: 8 }}>Calculating…</div>}
	              {activateCalc && !activateCalcLoad && (
	                <div style={{ background: '#0a2e1f', border: '1px solid #10b981', borderRadius: 8, padding: 14, marginBottom: 16 }}>
	                  {Number(activateCalc.systemCount) > 0 && <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}><span style={{ color: '#6ee7b7', fontSize: 12 }}>{activateCalc.systemCount} Systems</span><span style={{ color: '#6ee7b7', fontSize: 12, fontWeight: 700 }}>{fmtInr(activateCalc.subtotalSystems)}</span></div>}
	                  {Number(activateCalc.serverCount) > 0 && <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}><span style={{ color: '#6ee7b7', fontSize: 12 }}>{activateCalc.serverCount} Servers</span><span style={{ color: '#6ee7b7', fontSize: 12, fontWeight: 700 }}>{fmtInr(activateCalc.subtotalServers)}</span></div>}
	                  {Number(activateCalc.phoneCount) > 0 && <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}><span style={{ color: '#6ee7b7', fontSize: 12 }}>{activateCalc.phoneCount} Phones</span><span style={{ color: '#6ee7b7', fontSize: 12, fontWeight: 700 }}>{fmtInr(activateCalc.subtotalPhones)}</span></div>}
	                  <div style={{ borderTop: '1px solid #10b981', paddingTop: 8, marginTop: 8, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
	                    <span style={{ fontSize: 14, color: '#e0f2fe', fontWeight: 700 }}>Pay Now</span>
	                    <span style={{ fontSize: 22, color: '#34d399', fontWeight: 800 }}>{fmtInr(activateCalc.totalInr)}</span>
	                  </div>
	                </div>
	              )}

	              <button onClick={handleActivatePlan} disabled={busy || !activateCalc || activateCalcLoad} style={{
	                width: '100%', padding: 12, borderRadius: 8, border: 'none',
	                background: (busy || !activateCalc || activateCalcLoad) ? '#1e3a5f' : 'linear-gradient(135deg, #f59e0b, #d97706)',
	                color: '#0f172a', fontSize: 14, cursor: (busy || !activateCalc || activateCalcLoad) ? 'not-allowed' : 'pointer', fontWeight: 800,
	              }}>
	                {busy ? 'Processing…' : 'Activate & Pay'}
	              </button>
	            </div>
	          )}

	          {/* Current plan/license card */}
	          <div style={{ background: 'linear-gradient(135deg, #0c1a2e, #0f2040)', borderRadius: 12, padding: 24, border: `1px solid ${planActive ? (nearExpiry ? '#f59e0b' : '#10b981') : '#92400e'}` }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
              <div>
                <div style={{ fontSize: 12, color: '#475569', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.5px' }}>{currentPlanTitle}</div>
	                <div style={{ fontSize: 22, fontWeight: 800, color: '#e0f2fe' }}>
	                  {currentPlanSystems} Systems, {currentPlanServers} Servers & {currentPlanPhones} Phones
	                </div>
              </div>
              <StatusBadge status={!planActive && currentEndDate && now >= expiresAt ? 'expired' : undefined} active={planActive} nearExpiry={nearExpiry} />
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
              {[
                { label: 'Billing Cycle',  value: currentBillingCycle ? currentBillingCycle.charAt(0).toUpperCase() + currentBillingCycle.slice(1) : '—' },
                { label: 'Amount Paid',    value: currentAmountPaid ? fmtInr(currentAmountPaid) : '—' },
                { label: 'Payment Status', value: <span style={{ color: currentPaymentStatus === 'paid' ? '#34d399' : '#f87171' }}>{currentPaymentStatus?.toUpperCase() || '—'}</span> },
                { label: 'Start Date',     value: fmtDate(currentStartDate) },
                { label: 'Expiry Date',    value: <span style={{ color: planActive ? (nearExpiry ? '#f59e0b' : '#94a3b8') : '#f87171' }}>{fmtDate(currentEndDate)}</span> },
                { label: 'Payment ID',     value: currentPaymentId ? currentPaymentId.slice(0, 16) + '…' : '—' },
              ].map(({ label, value }) => (
                <div key={label} style={{ background: 'rgba(0,0,0,0.2)', borderRadius: 8, padding: 12 }}>
                  <div style={{ fontSize: 10, color: '#475569', marginBottom: 4, textTransform: 'uppercase' }}>{label}</div>
                  <div style={{ fontSize: 13, color: '#94a3b8', fontWeight: 600 }}>{value}</div>
                </div>
              ))}
            </div>

            <div style={{ display: 'flex', gap: 10, marginTop: 16, flexWrap: 'wrap' }}>
              <button
                onClick={() => openInvoiceModal({
                  paymentId: currentPaymentId,
                  amountInr: currentAmountPaid,
                  startDate: currentStartDate,
                  expiresAt: currentEndDate,
                  billingCycle: currentBillingCycle,
                  planType: 'Base Subscription Plan',
                  paidAt: currentStartDate
                })}
                style={{
                  padding: '7px 14px', borderRadius: 8, background: 'rgba(56,189,248,0.15)', border: '1px solid #38bdf866',
                  color: '#38bdf8', fontSize: 12, fontWeight: 700, cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: 6
                }}
              >
                📄 View / Download Invoice
              </button>
              <button
                onClick={() => openReceiptModal({
                  paymentId: currentPaymentId,
                  amountInr: currentAmountPaid,
                  startDate: currentStartDate,
                  expiresAt: currentEndDate,
                  billingCycle: currentBillingCycle,
                  planType: 'Base Subscription Plan',
                  paidAt: currentStartDate
                })}
                style={{
                  padding: '7px 14px', borderRadius: 8, background: 'rgba(52,211,153,0.15)', border: '1px solid #34d39966',
                  color: '#34d399', fontSize: 12, fontWeight: 700, cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: 6
                }}
              >
                📧 View / Download Receipt
              </button>
            </div>
	            {showRenewal && !needsBaseActivation && (
              <div style={{ marginTop: 16, background: planActive ? 'rgba(245,158,11,0.1)' : 'rgba(239,68,68,0.1)', border: `1px solid ${planActive ? '#f59e0b' : '#ef4444'}`, borderRadius: 8, padding: '10px 14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ fontSize: 13, color: planActive ? '#fcd34d' : '#fca5a5' }}>
                  {planActive ? '⚠️ Your plan is expiring soon!' : 'Your plan has expired.'}
                </div>
                <button onClick={() => { setRenewMode(enterpriseRegistration ? 'enterprise' : 'base'); setActiveTab('renewal'); }} style={{ padding: '6px 16px', borderRadius: 8, border: 'none', cursor: 'pointer', fontWeight: 700, fontSize: 12, background: planActive ? '#f59e0b' : '#ef4444', color: '#fff' }}>
                  Renew Now →
                </button>
              </div>
            )}
          </div>

          {/* Add-system batches summary */}
          {activeBatches.length > 0 && (
            <div style={{ background: '#0c1a2e', borderRadius: 12, padding: 20, border: '1px solid #2563eb33' }}>
              <div style={{ fontSize: 14, color: '#60a5fa', fontWeight: 700, marginBottom: 12 }}>Purchased License Batches ({activeBatches.length} active)</div>
	              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 10 }}>
                <div style={{ background: 'rgba(37,99,235,0.1)', borderRadius: 8, padding: '10px 14px', textAlign: 'center' }}>
                  <div style={{ fontSize: 11, color: '#475569', marginBottom: 4, textTransform: 'uppercase' }}>Total Added Systems</div>
                  <div style={{ fontSize: 28, color: '#60a5fa', fontWeight: 800 }}>{activeBatches.reduce((s, b) => s + b.addedSystemCount, 0)}</div>
                </div>
	                <div style={{ background: 'rgba(109,40,217,0.1)', borderRadius: 8, padding: '10px 14px', textAlign: 'center' }}>
	                  <div style={{ fontSize: 11, color: '#475569', marginBottom: 4, textTransform: 'uppercase' }}>Total Added Servers</div>
	                  <div style={{ fontSize: 28, color: '#a78bfa', fontWeight: 800 }}>{activeBatches.reduce((s, b) => s + (b.addedServerCount || 0), 0)}</div>
	                </div>
	                <div style={{ background: 'rgba(20,184,166,0.1)', borderRadius: 8, padding: '10px 14px', textAlign: 'center' }}>
	                  <div style={{ fontSize: 11, color: '#475569', marginBottom: 4, textTransform: 'uppercase' }}>Total Added Phones</div>
	                  <div style={{ fontSize: 28, color: '#2dd4bf', fontWeight: 800 }}>{activeBatches.reduce((s, b) => s + (b.addedPhoneCount || 0), 0)}</div>
	                </div>
	                <div style={{ background: 'rgba(16,185,129,0.1)', borderRadius: 8, padding: '10px 14px', textAlign: 'center' }}>
	                  <div style={{ fontSize: 11, color: '#475569', marginBottom: 4, textTransform: 'uppercase' }}>Grand Total (Usage)</div>
	                  <div style={{ fontSize: 28, color: '#34d399', fontWeight: 800 }}>{totalSystemCount} Systems</div>
	                  <div style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>{totalServerCount} Servers · {totalPhoneCount} Phones</div>
	                </div>
              </div>
            </div>
          )}

          {/* Base AutoPay */}
          {!enterpriseRegistration && <div style={{ background: '#0c1a2e', borderRadius: 12, padding: 20, border: '1px solid #1e3a5f' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontSize: 15, color: '#e0f2fe', fontWeight: 700, marginBottom: 4 }}>🔄 Base Plan AutoPay</div>
                <div style={{ fontSize: 12, color: '#475569' }}>
                  {plan?.autoPay ? 'Base subscription will auto-renew at expiry.' : 'Enable to auto-renew your base plan with a real mandate.'}
                </div>
              </div>
              {plan?.autoPay ? (
                <button onClick={handleBaseAutoPayDisable} disabled={busy} style={{ padding: '8px 20px', borderRadius: 8, cursor: 'pointer', fontWeight: 600, fontSize: 13, background: 'rgba(239,68,68,0.15)', color: '#f87171', outline: '1px solid #ef4444', border: 'none' }}>
                  ⏸ Disable AutoPay
                </button>
              ) : (
                <button onClick={handleBaseAutoPayEnable} disabled={busy} style={{ padding: '8px 20px', borderRadius: 8, cursor: 'pointer', fontWeight: 600, fontSize: 13, background: 'rgba(16,185,129,0.15)', color: '#34d399', outline: '1px solid #10b981', border: 'none' }}>
                  ✅ Enable AutoPay
                </button>
              )}
            </div>
          </div>}
        </div>
      )}

      {/* ══════════ RENEWAL TAB ══════════ */}
      {activeTab === 'renewal' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Section selector */}
          <div role="tablist" aria-label="Renewal plan type" style={{ display: 'flex', flexWrap: 'wrap', gap: 0, background: '#060e1a', borderRadius: 10, padding: 4, width: 'fit-content' }}>
            {[{ id: 'base', label: '🏠 Base Subscription' }, { id: 'batch', label: '⬆️ Add-System Batch' }, { id: 'enterprise', label: '🏢 Enterprise' }].map(m => (
              <button type="button" role="tab" aria-selected={renewMode === m.id} key={m.id} onClick={() => setRenewMode(m.id)} style={{
                padding: '8px 20px', border: 'none', borderRadius: 8, cursor: 'pointer', fontSize: 13, fontWeight: renewMode === m.id ? 700 : 400,
                background: renewMode === m.id ? '#1e3a5f' : 'transparent',
                color: renewMode === m.id ? '#93c5fd' : '#475569',
                transition: 'all 0.2s',
              }}>{m.label}</button>
            ))}
          </div>

          {/* A: Base renewal */}
          {renewMode === 'base' && enterpriseRegistration && (
            <div style={{ background: '#0c1a2e', borderRadius: 12, padding: 24, border: '1px solid #1e3a5f', color: '#94a3b8' }}>
              <p>Your registration plan is Enterprise. Open the Enterprise tab to renew it.</p>
              <button type="button" onClick={() => setRenewMode('enterprise')} style={{ padding: '8px 16px', borderRadius: 8, border: '1px solid #6366f1', background: '#1e1b4b', color: '#c7d2fe', cursor: 'pointer' }}>🏢 Renew Enterprise</button>
            </div>
          )}
          {renewMode === 'base' && !enterpriseRegistration && (
            <div style={{ background: '#0c1a2e', borderRadius: 12, padding: 24, border: `1px solid ${showRenewal ? '#ef4444' : '#1e3a5f'}` }}>
              <h3 style={{ fontSize: 16, color: showRenewal ? '#f87171' : '#e0f2fe', fontWeight: 700, marginBottom: 4 }}>
                🏠 Renew Base Subscription
              </h3>

              {/* Key info box */}
              <div style={{ background: 'rgba(109,40,217,0.08)', border: '1px solid rgba(109,40,217,0.3)', borderRadius: 8, padding: '10px 14px', marginBottom: 16, fontSize: 12, color: '#94a3b8' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8 }}>
                  <div>
	                    <div style={{ color: '#475569', fontSize: 10, textTransform: 'uppercase', marginBottom: 2 }}>Base Systems (Registration)</div>
	                    <div style={{ color: '#c4b5fd', fontWeight: 800, fontSize: 18 }}>
	                      {renewCalc?.baseSys ?? (plan?.baseSystemCount > 0 ? plan.baseSystemCount : plan?.systemCount ?? 0)} Systems · {renewCalc?.basePhn ?? (plan?.basePhoneCount > 0 ? plan.basePhoneCount : plan?.phoneCount ?? 0)} Phones
	                    </div>
                    <div style={{ color: '#475569', fontSize: 10, marginTop: 2 }}>Only base systems — Add-System batches have their own renewal</div>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ color: '#475569', fontSize: 10, textTransform: 'uppercase', marginBottom: 2 }}>Expires</div>
                    <div style={{ color: planActive ? (nearExpiry ? '#fbbf24' : '#94a3b8') : '#f87171', fontWeight: 700, fontSize: 14 }}>
                      {fmtDate(plan?.expiresAt)}
                    </div>
                  </div>
                </div>
              </div>

              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 8 }}>New Billing Cycle</label>
                <div style={{ display: 'flex', gap: 8 }}>
                  {['monthly', 'yearly'].map(c => (
                    <div key={c} onClick={() => setRenewCycle(c)} style={{
                      flex: 1, padding: '8px 12px', borderRadius: 6, cursor: 'pointer', textAlign: 'center',
                      border: `2px solid ${renewCycle === c ? '#7c3aed' : '#1e3a5f'}`,
                      background: renewCycle === c ? 'rgba(109,40,217,0.2)' : '#060e1a', transition: 'all 0.2s',
                    }}>
                      <span style={{ fontSize: 13, fontWeight: 600, color: renewCycle === c ? '#c4b5fd' : '#475569', textTransform: 'capitalize' }}>{c}</span>
                      {c === 'yearly' && <span style={{ fontSize: 10, color: '#10b981', marginLeft: 4 }}>💚 Best Value</span>}
                    </div>
                  ))}
                </div>
              </div>
              {renewLoading && <div style={{ color: '#a78bfa', fontSize: 12, textAlign: 'center', padding: 8 }}>Calculating…</div>}
              {renewCalc && !renewLoading && (
                <div style={{ background: 'rgba(109,40,217,0.1)', border: '1px solid rgba(167,139,250,0.4)', borderRadius: 8, padding: 16, marginBottom: 16 }}>
                  <div style={{ fontSize: 11, color: '#a78bfa', marginBottom: 8 }}>💰 Base Plan Renewal Cost (Renewal Pricing)</div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ color: '#94a3b8', fontSize: 12 }}>{renewCalc.baseSys} Systems × {renewCycle}</span>
                    <span style={{ color: '#c4b5fd', fontSize: 12, fontWeight: 600 }}>{fmtInr(renewCalc.subtotalSystems || renewCalc.totalInr)}</span>
                  </div>
	                  {(renewCalc.baseSrv > 0) && (
	                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
	                      <span style={{ color: '#94a3b8', fontSize: 12 }}>{renewCalc.baseSrv} Servers × {renewCycle}</span>
	                      <span style={{ color: '#c4b5fd', fontSize: 12, fontWeight: 600 }}>{fmtInr(renewCalc.subtotalServers)}</span>
	                    </div>
	                  )}
	                  {(renewCalc.basePhn > 0) && (
	                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
	                      <span style={{ color: '#94a3b8', fontSize: 12 }}>{renewCalc.basePhn} Phones × {renewCycle}</span>
	                      <span style={{ color: '#c4b5fd', fontSize: 12, fontWeight: 600 }}>{fmtInr(renewCalc.subtotalPhones)}</span>
	                    </div>
	                  )}
                  <div style={{ borderTop: '1px solid rgba(167,139,250,0.3)', paddingTop: 8, marginTop: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: 14, color: '#e0f2fe', fontWeight: 700 }}>Renewal Total</span>
                    <span style={{ fontSize: 22, color: '#c4b5fd', fontWeight: 800 }}>{fmtInr(renewCalc.totalInr)}</span>
                  </div>
                  <div style={{ fontSize: 11, color: '#475569', marginTop: 4 }}>⚠️ This does NOT renew Add-System batches. Each batch has its own renewal.</div>
                </div>
              )}
	              {!(plan?.baseSystemCount > 0 || plan?.systemCount > 0 || plan?.basePhoneCount > 0 || plan?.phoneCount > 0 || plan?.baseServerCount > 0 || plan?.serverCount > 0) && (
                <div style={{ textAlign: 'center', padding: 20, color: '#475569', fontSize: 13, background: 'rgba(0,0,0,0.2)', borderRadius: 8, marginBottom: 16 }}>
                  ℹ️ No base plan found.
                </div>
              )}
              <button onClick={handleBaseRenewal} disabled={busy || !renewCalc || renewLoading} style={{
                width: '100%', padding: 14, borderRadius: 10, border: 'none',
                background: (busy || !renewCalc || renewLoading) ? '#1e3a5f' : 'linear-gradient(135deg, #7c3aed, #6d28d9)',
                color: (busy || !renewCalc || renewLoading) ? '#4b5563' : '#fff',
                fontSize: 15, cursor: (busy || !renewCalc || renewLoading) ? 'not-allowed' : 'pointer', fontWeight: 700,
              }}>
                {busy ? 'Processing…' : '🏠 Renew Base Plan — ' + (renewCalc ? fmtInr(renewCalc.totalInr) : 'Calculating...')}
              </button>
            </div>
          )}

          {/* B: Batch renewal */}
          {renewMode === 'batch' && (
            <div style={{ background: '#0c1a2e', borderRadius: 12, padding: 24, border: '1px solid #2563eb33' }}>
              <h3 style={{ fontSize: 16, color: '#60a5fa', fontWeight: 700, marginBottom: 4 }}>⬆️ Renew Add-System Batch</h3>
              <p style={{ fontSize: 12, color: '#475569', marginBottom: 20 }}>
                Select a specific batch to renew — each batch is billed independently.
              </p>

              {activeBatches.length === 0 && expiredBatches.length === 0 ? (
                <div style={{ textAlign: 'center', padding: 30, color: '#475569', fontSize: 13 }}>
                  No add-system batches found. Use "⬆️ Add Systems" tab to purchase.
                </div>
              ) : (
                <>
                  {/* Batch list */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 20 }}>
                    {[...activeBatches, ...expiredBatches].map(b => {
                      const bEnd = new Date(b.endDate || 0);
                      const bActive = b.status === 'active' && new Date() < bEnd;
                      const isSelected = selectedBatch?._id === b._id;
                      return (
                        <div key={b._id} onClick={() => b.priceType?.startsWith('enterprise') ? setRenewMode('enterprise') : setSelectedBatch(b)} style={{
                          background: isSelected ? 'rgba(37,99,235,0.2)' : 'rgba(0,0,0,0.2)',
                          border: `2px solid ${isSelected ? '#2563eb' : '#1e3a5f'}`,
                          borderRadius: 10, padding: '12px 16px', cursor: 'pointer', transition: 'all 0.2s',
                          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                        }}>
                          <div>
	                            <div style={{ color: '#e0f2fe', fontWeight: 700, fontSize: 14 }}>
	                              +{b.addedSystemCount} Systems {b.addedServerCount > 0 ? `+${b.addedServerCount} Servers` : ''} {b.addedPhoneCount > 0 ? `+${b.addedPhoneCount} Phones` : ''}
	                            </div>
                            <div style={{ fontSize: 11, color: '#475569', marginTop: 2 }}>
                              Added: {fmtDate(b.addedDate)} · Expires: {fmtDate(b.endDate)} · {b.billingCycle}
                              {b.serverDetails ? ` · ${b.serverDetails}` : ''}
                            </div>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                            <StatusBadge status={b.status} active={bActive} />
                            {isSelected && <span style={{ color: '#2563eb', fontSize: 18 }}>✓</span>}
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  {selectedBatch && (
                    <>
                      <div style={{ marginBottom: 16 }}>
                        <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 8 }}>Billing Cycle for This Batch</label>
                        <div style={{ display: 'flex', gap: 8 }}>
                          {['monthly', 'yearly'].map(c => (
                            <div key={c} onClick={() => setBatchRenewCycle(c)} style={{
                              flex: 1, padding: '8px 12px', borderRadius: 6, cursor: 'pointer', textAlign: 'center',
                              border: `2px solid ${batchRenewCycle === c ? '#2563eb' : '#1e3a5f'}`,
                              background: batchRenewCycle === c ? '#0f2a4a' : '#060e1a', transition: 'all 0.2s',
                            }}>
                              <span style={{ fontSize: 13, fontWeight: 600, color: batchRenewCycle === c ? '#93c5fd' : '#475569', textTransform: 'capitalize' }}>{c}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                      {batchRenewLoad && <div style={{ color: '#60a5fa', fontSize: 12, textAlign: 'center', padding: 8 }}>Calculating…</div>}
                      {batchRenewCalc && !batchRenewLoad && (
                        <div style={{ background: 'rgba(37,99,235,0.1)', border: '1px solid rgba(37,99,235,0.4)', borderRadius: 8, padding: 16, marginBottom: 16 }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
	                            <span style={{ color: '#93c5fd', fontWeight: 700 }}>Renewal Total (+{selectedBatch.addedSystemCount} Systems, +{selectedBatch.addedServerCount || 0} Servers, +{selectedBatch.addedPhoneCount || 0} Phones)</span>
                            <span style={{ fontSize: 22, color: '#60a5fa', fontWeight: 800 }}>{fmtInr(batchRenewCalc.totalInr)}</span>
                          </div>
                          <div style={{ fontSize: 11, color: '#475569', marginTop: 6 }}>
                            New expiry: {batchRenewCycle === 'yearly' ? '1 year from today' : '1 month from today'} · Using renewal pricing rates
                          </div>
                        </div>
                      )}
                      <button onClick={handleBatchRenewal} disabled={busy || !batchRenewCalc || batchRenewLoad} style={{
                        width: '100%', padding: 14, borderRadius: 10, border: 'none',
                        background: (busy || !batchRenewCalc) ? '#1e3a5f' : 'linear-gradient(135deg, #2563eb, #1d4ed8)',
                        color: (busy || !batchRenewCalc) ? '#4b5563' : '#fff',
                        fontSize: 15, cursor: (busy || !batchRenewCalc) ? 'not-allowed' : 'pointer', fontWeight: 700,
                      }}>
                        {busy ? 'Processing…' : `⬆️ Renew Batch — ${batchRenewCalc ? fmtInr(batchRenewCalc.totalInr) : 'Select batch first'}`}
                      </button>
                    </>
                  )}
                </>
              )}
            </div>
          )}
          {renewMode === 'enterprise' && <EnterprisePurchase />}
        </div>
      )}

      {/* ══════════ ADD SYSTEMS TAB ══════════ */}
      {activeTab === 'upgrade' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Add form */}
          <div style={{ background: '#0c1a2e', borderRadius: 12, padding: 24, border: '1px solid #1e3a5f' }}>
            <h3 style={{ fontSize: 16, color: '#e0f2fe', fontWeight: 700, marginBottom: 4 }}>⬆️ Add More Systems, Servers or Phones</h3>
            <p style={{ fontSize: 12, color: '#475569', marginBottom: 4 }}>
              Current base: <strong style={{ color: '#60a5fa' }}>{baseSystemCount} systems</strong>, <strong style={{ color: '#60a5fa' }}>{baseServerCount} servers</strong> & <strong style={{ color: '#60a5fa' }}>{basePhoneCount} phones</strong>
              <span style={{ color: '#64748b' }}> | Total active: </span>
              <strong style={{ color: '#34d399' }}>{totalSystemCount} systems</strong>, <strong style={{ color: '#34d399' }}>{totalServerCount} servers</strong> & <strong style={{ color: '#34d399' }}>{totalPhoneCount} phones</strong>
            </p>
            <p style={{ fontSize: 12, color: '#f87171', marginBottom: 20 }}>
              Added licenses start their own billing period on the payment date. Monthly licenses renew one month later; yearly licenses renew one year later.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 16, marginBottom: 16 }}>
              <div>
                <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 6 }}>Add Systems (+)</label>
                <input type="number" min="0" value={addSystems} onChange={e => setAddSystems(e.target.value)}
                  style={{ width: '100%', padding: '10px 12px', borderRadius: 6, boxSizing: 'border-box', background: '#060e1a', color: '#e2e8f0', fontSize: 20, fontWeight: 700, border: '1px solid #2563eb', textAlign: 'center' }} />
              </div>
	              <div>
	                <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 6 }}>Add Servers (+)</label>
	                <input type="number" min="0" value={addServers} onChange={e => setAddServers(e.target.value)}
	                  style={{ width: '100%', padding: '10px 12px', borderRadius: 6, boxSizing: 'border-box', background: '#060e1a', color: '#e2e8f0', fontSize: 20, fontWeight: 700, border: '1px solid #1e3a5f', textAlign: 'center' }} />
	              </div>
	              <div>
	                <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 6 }}>Add Phones (+)</label>
	                <input type="number" min="0" value={addPhones} onChange={e => setAddPhones(e.target.value)}
	                  style={{ width: '100%', padding: '10px 12px', borderRadius: 6, boxSizing: 'border-box', background: '#060e1a', color: '#e2e8f0', fontSize: 20, fontWeight: 700, border: '1px solid #1e3a5f', textAlign: 'center' }} />
	                <div style={{ fontSize: 10, color: '#475569', marginTop: 4 }}>Android + iPhone</div>
	              </div>
            </div>

            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 8 }}>Billing Cycle</label>
              {status?.enterpriseSubscriptionId ? <p style={{ color: '#a5b4fc', fontSize: 13 }}>Billing cycle: {addCalc?.billingCycle || enterprisePrimary?.billingCycle}. Each addition starts a full cycle on its payment date: monthly renews one month later, yearly renews one year later.</p> : <div style={{ display: 'flex', gap: 8 }}>
                {['monthly', 'yearly'].map(c => (
                  <div key={c} onClick={() => setAddCycle(c)} style={{
                    flex: 1, padding: '8px 12px', borderRadius: 6, cursor: 'pointer', textAlign: 'center',
                    border: `2px solid ${addCycle === c ? '#2563eb' : '#1e3a5f'}`,
                    background: addCycle === c ? '#0f2a4a' : '#060e1a', transition: 'all 0.2s',
                  }}>
                    <span style={{ fontSize: 13, fontWeight: 600, color: addCycle === c ? '#93c5fd' : '#475569', textTransform: 'capitalize' }}>{c}</span>
                  </div>
                ))}
              </div>}
            </div>

            {addCalcLoad && <div style={{ color: '#60a5fa', fontSize: 12, textAlign: 'center', padding: 8 }}>Calculating…</div>}
            {addCalc && !addCalcLoad && (
              <div style={{ background: '#0a2e1f', border: '1px solid #10b981', borderRadius: 8, padding: 16, marginBottom: 16 }}>
                <div style={{ fontSize: 11, color: '#10b981', fontWeight: 600, marginBottom: 10 }}>{addCalc.enterprise ? '💰 Enterprise Add Systems — full billing period' : '💰 This Batch Cost (Renewal Pricing)'}</div>
	                {Number(addSystems) > 0 && <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}><span style={{ color: '#6ee7b7', fontSize: 12 }}>+{addSystems} Systems</span><span style={{ color: '#6ee7b7', fontSize: 12, fontWeight: 600 }}>{fmtInr(addCalc.subtotalSystems)}</span></div>}
	                {Number(addServers) > 0 && <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}><span style={{ color: '#6ee7b7', fontSize: 12 }}>+{addServers} Servers</span><span style={{ color: '#6ee7b7', fontSize: 12, fontWeight: 600 }}>{fmtInr(addCalc.subtotalServers)}</span></div>}
	                {Number(addPhones) > 0 && <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}><span style={{ color: '#6ee7b7', fontSize: 12 }}>+{addPhones} Phones</span><span style={{ color: '#6ee7b7', fontSize: 12, fontWeight: 600 }}>{fmtInr(addCalc.subtotalPhones)}</span></div>}
                <div style={{ borderTop: '1px solid #10b981', paddingTop: 8, marginTop: 8, display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ fontSize: 14, color: '#e0f2fe', fontWeight: 700 }}>Pay Now</span>
                  <span style={{ fontSize: 20, color: '#34d399', fontWeight: 800 }}>{fmtInr(addCalc.totalInr)}</span>
                </div>
                <div style={{ fontSize: 11, color: '#475569', marginTop: 6 }}>
                  Licenses expire: {addCalc.enterprise ? fmtDate(addCalc.periodEnd) : addCycle === 'yearly' ? '~1 year from today' : '~1 month from today'}
                </div>
              </div>
            )}

            {partnerStock.limited && (
              <div style={{
                background: partnerStockBlocked ? 'rgba(245,158,11,.12)' : 'rgba(16,185,129,.12)',
                border: `1px solid ${partnerStockBlocked ? '#f59e0b' : '#10b981'}`,
                color: partnerStockBlocked ? '#fbbf24' : '#6ee7b7',
                borderRadius: 8,
                padding: 10,
                marginBottom: 12,
                fontSize: 12,
                fontWeight: 700,
              }}>
                Partner stock available: {partnerStock.available || 0}. Requested: {addRequestedLicenses}.
                {partnerStockBlocked ? ' Please ask the Partner Admin to purchase more licenses first.' : ' You can add this batch.'}
              </div>
            )}

            <button onClick={handleAddSystems} disabled={busy || !addCalc || addCalcLoad || partnerStockBlocked} style={{
              width: '100%', padding: 12, borderRadius: 8, border: 'none',
              background: (busy || !addCalc || addCalcLoad || partnerStockBlocked) ? '#1e3a5f' : 'linear-gradient(135deg, #2563eb, #1d4ed8)',
              color: '#fff', fontSize: 14, cursor: (busy || !addCalc || addCalcLoad || partnerStockBlocked) ? 'not-allowed' : 'pointer', fontWeight: 700,
            }}>
	              {partnerStockBlocked ? 'Partner License Stock Required' : busy ? 'Processing…' : status?.enterpriseSubscriptionId ? '⬆️ Add Licenses to Enterprise' : '⬆️ Add Licenses (New Batch)'}
            </button>
          </div>

          {/* Batch table */}
          <div style={{ background: '#0c1a2e', borderRadius: 12, padding: 20, border: '1px solid #1e3a5f' }}>
            <div style={{ fontSize: 14, color: '#e0f2fe', fontWeight: 700, marginBottom: 16 }}>
              📋 Add-System Subscription History
              <span style={{ fontSize: 11, color: '#475569', fontWeight: 400, marginLeft: 8 }}>
                (Enterprise purchases and added licenses)
              </span>
            </div>

            {batchLoading ? (
              <div style={{ textAlign: 'center', color: '#60a5fa', padding: 30, fontSize: 13 }}>Loading batches…</div>
            ) : batches.length === 0 ? (
              <div style={{ textAlign: 'center', color: '#475569', padding: 40, fontSize: 13 }}>
                <div style={{ fontSize: 32, marginBottom: 8 }}>📭</div>
                No add-system batches yet. Use the form above to add systems.
              </div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ borderBottom: '2px solid #1e3a5f' }}>
                      <th style={th}>Add Date</th>
                      <th style={th}>Systems</th>
                      <th style={th}>Servers / Phones / Details</th>
                      <th style={th}>Start Date</th>
                      <th style={th}>End Date</th>
                      <th style={th}>Payment ID</th>
                      <th style={th}>AutoPay</th>
                      <th style={th}>Status / Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {batches.map((b, i) => <BatchRow key={b._id} b={b} idx={i} />)}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ══════════ HISTORY TAB ══════════ */}
      {activeTab === 'history' && (
        <div>
          <h3 style={{ fontSize: 15, color: '#e0f2fe', fontWeight: 700, marginBottom: 16 }}>Payment History (Base Plan & Add-System Batches)</h3>
          {combinedHistory.length === 0 ? (
            <div style={{ textAlign: 'center', color: '#475569', padding: '40px 20px', background: '#0c1a2e', borderRadius: 12, border: '1px solid #1e3a5f' }}>
              <div style={{ fontSize: 32, marginBottom: 8 }}>📭</div>
              No payment history yet
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {combinedHistory.map((p, i) => (
                <div key={p._id || i} style={{ background: '#0c1a2e', borderRadius: 10, padding: 16, border: '1px solid #1e3a5f' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
                    <div>
	                      <div style={{ fontSize: 14, color: '#e0f2fe', fontWeight: 700 }}>
	                        {formatHistoryLicenses(p)}
	                      </div>
                      <div style={{ fontSize: 11, color: '#475569', marginTop: 2 }}>{fmtDate(p.paidAt)} · {p.billingCycle}</div>
                    </div>
                    <div style={{ textAlign: 'right' }}>
                      <div style={{ fontSize: 18, color: '#34d399', fontWeight: 800 }}>{fmtInr(p.amountInr)}</div>
                      <div style={{ fontSize: 11, color: '#475569' }}>{p.paymentId ? p.paymentId.slice(0, 16) + '…' : '—'}</div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 12, paddingTop: 10, borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                    <div style={{ fontSize: 11, color: '#64748b' }}>
                      Status: <span style={{ color: p.status === 'captured' || p.status === 'paid' ? '#34d399' : '#38bdf8', fontWeight: 700 }}>{(p.status || 'PAID').toUpperCase()}</span>
                    </div>
                    <div style={{ display: 'flex', gap: 8 }}>
                      <button
                        onClick={() => openInvoiceModal(p)}
                        style={{ padding: '5px 12px', borderRadius: 6, border: '1px solid #38bdf866', background: 'rgba(56,189,248,0.12)', color: '#38bdf8', fontSize: 11, fontWeight: 700, cursor: 'pointer' }}
                      >
                        📄 Download Invoice
                      </button>
                      <button
                        onClick={() => openReceiptModal(p)}
                        style={{ padding: '5px 12px', borderRadius: 6, border: '1px solid #34d39966', background: 'rgba(52,211,153,0.12)', color: '#34d399', fontSize: 11, fontWeight: 700, cursor: 'pointer' }}
                      >
                        📧 Download Receipt
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
      {/* Document Preview & Download Modal */}
      {docModal && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(5,10,25,0.85)',
          backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20
        }} onClick={(e) => { if (e.target === e.currentTarget) setDocModal(null); }}>
          <div style={{
            background: '#0f172a', border: '1px solid #334155', borderRadius: 16, width: '100%', maxWidth: 680,
            boxShadow: '0 25px 50px -12px rgba(0,0,0,0.7)', overflow: 'hidden', display: 'flex', flexDirection: 'column', maxHeight: '90vh'
          }}>
            {/* Header toolbar */}
            <div style={{
              padding: '16px 24px', background: '#1e293b', borderBottom: '1px solid #334155',
              display: 'flex', justifyContent: 'space-between', alignItems: 'center'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ fontSize: 20 }}>{docModal.type === 'invoice' ? '📄' : '📧'}</span>
                <div>
                  <div style={{ color: '#f8fafc', fontWeight: 800, fontSize: 16 }}>
                    {docModal.type === 'invoice' ? 'Tax Invoice Document' : 'Official Payment Receipt'}
                  </div>
                  <div style={{ color: '#94a3b8', fontSize: 11, fontFamily: 'monospace' }}>{docModal.number}</div>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                <button
                  onClick={() => handlePrintDocument(docModal)}
                  style={{
                    background: 'linear-gradient(135deg, #2563eb, #3b82f6)', color: '#fff', border: 'none',
                    padding: '8px 16px', borderRadius: 8, fontSize: 12, fontWeight: 800, cursor: 'pointer',
                    display: 'inline-flex', alignItems: 'center', gap: 6, boxShadow: '0 4px 12px rgba(37,99,235,0.3)'
                  }}
                >
                  📥 Download / Print PDF
                </button>
                <button
                  onClick={() => setDocModal(null)}
                  style={{ background: '#334155', color: '#94a3b8', border: 'none', width: 32, height: 32, borderRadius: 8, fontSize: 16, cursor: 'pointer' }}
                >
                  ✕
                </button>
              </div>
            </div>

            {/* Modal body document preview */}
            <div style={{ padding: 24, overflowY: 'auto', flex: 1, background: '#090d16', display: 'flex', justifyContent: 'center' }}>
              {docModal.type === 'receipt' ? (
                <div style={{
                  width: '100%', maxWidth: 500, background: '#ffffff', color: '#1e293b', borderRadius: 20,
                  overflow: 'hidden', boxShadow: '0 10px 25px rgba(0,0,0,0.3)', border: '1px solid #e2e8f0', fontFamily: 'system-ui, sans-serif'
                }}>
                  <div style={{ background: '#0d542b', padding: '32px 20px 24px', textAlign: 'center', color: '#ffffff' }}>
                    <div style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: 50, height: 50, background: '#84cc16', color: '#ffffff', borderRadius: 12, fontSize: 28, fontWeight: 'bold', marginBottom: 10, margin: '0 auto 10px' }}>✓</div>
                    <div style={{ fontSize: 24, fontWeight: 800, margin: '2px 0' }}>Payment Receipt</div>
                    <div style={{ fontSize: 13, color: '#86efac', fontWeight: 500 }}>Spartan Cyber Defense Center (SCDC)</div>
                  </div>
                  <div style={{ padding: '24px 28px' }}>
                    <div style={{ background: '#eefdf4', border: '1px solid #bbf7d0', borderRadius: 14, padding: 20, textAlign: 'center', marginBottom: 24 }}>
                      <div style={{ fontSize: 34, fontWeight: 900, color: '#15803d' }}>₹{Number(docModal.amount || 0).toFixed(2)}</div>
                      <div style={{ fontSize: 12, color: '#4b5563', fontWeight: 600, marginTop: 2 }}>Amount Paid</div>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, fontSize: 13 }}>
                      {[
                        { label: 'Receipt No.', val: docModal.number, mono: true },
                        { label: 'Customer', val: docModal.companyName },
                        { label: 'Email', val: docModal.companyEmail },
                        { label: 'Plan', val: docModal.description },
                        { label: 'Billing Cycle', val: docModal.billingCycle },
                        { label: 'Payment Date', val: docModal.date },
                        { label: 'Payment ID', val: docModal.paymentId, mono: true },
                        { label: 'Status', val: <span style={{ color: '#166534', fontWeight: 800 }}>✓ PROCESSED</span> },
                      ].map(({ label, val, mono }) => (
                        <div key={label} style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 10, borderBottom: '1px solid #f1f5f9' }}>
                          <span style={{ color: '#64748b' }}>{label}</span>
                          <span style={{ color: '#0f172a', fontWeight: 700, fontFamily: mono ? 'monospace' : 'inherit' }}>{val}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div style={{ background: '#f8fafc', padding: '14px 20px', textAlign: 'center', fontSize: 11, color: '#94a3b8', borderTop: '1px solid #f1f5f9' }}>
                    Thank you for your payment! &nbsp;|&nbsp; Spartan Cyber Defense Center (SCDC) © 2026
                  </div>
                </div>
              ) : (
                <div style={{
                  width: '100%', maxWidth: 580, background: '#ffffff', color: '#1e293b', borderRadius: 20,
                  overflow: 'hidden', boxShadow: '0 10px 25px rgba(0,0,0,0.3)', border: '1px solid #e2e8f0', fontFamily: 'system-ui, sans-serif'
                }}>
                  <div style={{ background: '#80001a', padding: '28px 32px', color: '#ffffff', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div>
                      <div style={{ fontSize: 20, fontWeight: 900, marginBottom: 2 }}>Spartan Cyber Defense Center (SCDC)</div>
                      <div style={{ fontSize: 12, color: '#fca5a5' }}>Security Assessment Platform</div>
                    </div>
                    <div style={{ textAlign: 'right' }}>
                      <div style={{ fontSize: 24, fontWeight: 900, letterSpacing: 1 }}>INVOICE</div>
                      <div style={{ fontSize: 12, color: '#fca5a5', fontFamily: 'monospace', fontWeight: 700, marginTop: 2 }}>{docModal.number}</div>
                    </div>
                  </div>
                  <div style={{ padding: '28px 32px' }}>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 24, fontSize: 12 }}>
                      <div>
                        <div style={{ fontSize: 10, textTransform: 'uppercase', color: '#94a3b8', fontWeight: 800, marginBottom: 6 }}>BILLED TO</div>
                        <div style={{ fontSize: 15, fontWeight: 800, color: '#0f172a' }}>{docModal.companyName}</div>
                        <div style={{ color: '#64748b' }}>{docModal.companyEmail}</div>
                      </div>
                      <div>
                        <div style={{ fontSize: 10, textTransform: 'uppercase', color: '#94a3b8', fontWeight: 800, marginBottom: 6 }}>INVOICE DETAILS</div>
                        <div style={{ marginBottom: 3 }}><strong>Date:</strong> {docModal.date}</div>
                        <div style={{ marginBottom: 3 }}><strong>Status:</strong> <span style={{ background: '#fef08a', color: '#854d0e', fontWeight: 800, fontSize: 10, padding: '2px 8px', borderRadius: 6 }}>PROCESSED</span></div>
                        <div><strong>Payment ID:</strong> <span style={{ fontFamily: 'monospace' }}>{docModal.paymentId}</span></div>
                      </div>
                    </div>

                    <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: 20 }}>
                      <thead>
                        <tr style={{ background: '#f8fafc' }}>
                          <th style={{ textAlign: 'left', padding: '10px 14px', fontSize: 10, color: '#64748b', textTransform: 'uppercase', borderBottom: '1px solid #e2e8f0' }}>DESCRIPTION</th>
                          <th style={{ textAlign: 'center', padding: '10px 14px', fontSize: 10, color: '#64748b', textTransform: 'uppercase', borderBottom: '1px solid #e2e8f0' }}>BILLING CYCLE</th>
                          <th style={{ textAlign: 'right', padding: '10px 14px', fontSize: 10, color: '#64748b', textTransform: 'uppercase', borderBottom: '1px solid #e2e8f0' }}>AMOUNT</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr>
                          <td style={{ padding: 14, borderBottom: '1px solid #f1f5f9', fontSize: 13, color: '#0f172a', fontWeight: 700 }}>{docModal.description}</td>
                          <td style={{ padding: 14, borderBottom: '1px solid #f1f5f9', fontSize: 13, textAlign: 'center', fontWeight: 600 }}>{docModal.billingCycle}</td>
                          <td style={{ padding: 14, borderBottom: '1px solid #f1f5f9', fontSize: 13, textAlign: 'right', fontWeight: 700 }}>₹{Number(docModal.subtotal || docModal.amount || 0).toFixed(2)}</td>
                        </tr>
                        <tr>
                          <td style={{ padding: 14, borderBottom: '1px solid #f1f5f9', fontSize: 13, color: '#64748b' }}>GST (18%)</td>
                          <td></td>
                          <td style={{ padding: 14, borderBottom: '1px solid #f1f5f9', fontSize: 13, textAlign: 'right', color: '#64748b', fontWeight: 600 }}>₹{Number(docModal.gst || 0).toFixed(2)}</td>
                        </tr>
                        <tr style={{ background: '#fff5f5' }}>
                          <td colSpan="2" style={{ padding: 16, fontWeight: 800, color: '#80001a', fontSize: 15 }}>Total Paid</td>
                          <td style={{ padding: 16, textAlign: 'right', fontWeight: 900, color: '#80001a', fontSize: 18 }}>₹{Number(docModal.amount || 0).toFixed(2)}</td>
                        </tr>
                      </tbody>
                    </table>

                    {docModal.period && (
                      <div style={{ fontSize: 11, color: '#94a3b8', marginBottom: 16 }}>
                        Valid From: {docModal.period.split('–')[0]?.trim()} &nbsp;|&nbsp; Valid Until: {docModal.period.split('–')[1]?.trim() || docModal.period}
                      </div>
                    )}
                  </div>
                  <div style={{ background: '#f8fafc', padding: '14px 20px', textAlign: 'center', fontSize: 11, color: '#94a3b8', borderTop: '1px solid #f1f5f9' }}>
                    This is a computer-generated invoice. No signature required. &nbsp;|&nbsp; Spartan Cyber Defense Center (SCDC) © 2026
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function DepartmentPaymentsPage() {
  const [department, setDepartment] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    api.get('/department')
      .then(({ data }) => {
        const departments = Array.isArray(data) ? data : (data?.departments || []);
        setDepartment(departments[0] || null);
      })
      .catch(err => setError(err.response?.data?.message || 'Unable to load department allocation'))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div style={{ color: '#93c5fd' }}>Loading department allocation…</div>;
  if (error) return <div style={{ padding: 14, border: '1px solid #7f1d1d', borderRadius: 10, color: '#fca5a5', background: '#350d16' }}>{error}</div>;
  if (!department) return <div style={{ color: '#fbbf24' }}>No department is assigned to this account.</div>;

  const allocation = [
    ['Systems', department.systemUsedCount, department.assignedSystemCount, '🖥'],
    ['Servers', department.serverUsedCount, department.assignedServerCount, '🖧'],
    ['Phones', department.phoneUsedCount, department.assignedPhoneCount, '📱'],
  ];

  return (
    <div style={{ color: '#e2e8f0', display: 'grid', gap: 18 }}>
      <section style={{ padding: 22, border: '1px solid #1e3a5f', borderRadius: 14, background: 'linear-gradient(135deg,#0c1a2e,#101d35)' }}>
        <div style={{ color: '#7dd3fc', fontSize: 11, fontWeight: 900, textTransform: 'uppercase', letterSpacing: '.08em' }}>Department Payments</div>
        <h2 style={{ margin: '7px 0 5px', fontSize: 24 }}>{department.name}</h2>
        <p style={{ margin: 0, color: '#94a3b8', fontSize: 13 }}>Read-only license allocation supplied by your company administrator.</p>
      </section>
      <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(210px,1fr))', gap: 14 }}>
        {allocation.map(([label, usedValue, assignedValue, icon]) => {
          const used = Number(usedValue || 0);
          const assigned = Number(assignedValue || 0);
          return (
            <article key={label} style={{ padding: 18, border: '1px solid #1e3a5f', borderRadius: 12, background: '#0b1528' }}>
              <div style={{ color: '#7dd3fc', fontSize: 12, fontWeight: 800 }}>{icon} {label}</div>
              <div style={{ marginTop: 10, fontSize: 28, fontWeight: 900 }}>{used}/{assigned}</div>
              <div style={{ marginTop: 5, color: '#94a3b8', fontSize: 11 }}>{Math.max(0, assigned - used)} licenses available</div>
            </article>
          );
        })}
      </section>
      <div style={{ padding: 14, border: '1px solid #92400e', borderRadius: 10, color: '#fbbf24', background: '#451a0322', fontSize: 12 }}>
        Purchases, renewals and AutoPay remain company-level controls. Contact your Company Admin to change this allocation.
      </div>
    </div>
  );
}

export default function PaymentsPage() {
  const { isDeptAdmin } = useAuth();
  return isDeptAdmin ? <DepartmentPaymentsPage /> : <CompanyPaymentsPage />;
}
