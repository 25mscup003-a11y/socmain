const nodemailer = require('nodemailer');

let transporter = null;

function getTransporter() {
  if (transporter) return transporter;
  const smtpPort = Number(process.env.SMTP_PORT) || 587;
  const smtpSecure = process.env.SMTP_SECURE
    ? process.env.SMTP_SECURE === 'true'
    : smtpPort === 465;

  transporter = nodemailer.createTransport({
    host:   process.env.SMTP_HOST   || 'smtp.gmail.com',
    port:   smtpPort,
    secure: smtpSecure,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
  return transporter;
}

/**
 * sendMail({ to, subject, html, text })
 * Returns nodemailer info object or throws on failure.
 */
async function sendMail({ to, subject, html, text, cc, replyTo }) {
  const t = getTransporter();
  return t.sendMail({
    from: process.env.SMTP_FROM || `"SOC SaaS" <${process.env.SMTP_USER}>`,
    to,
    cc,
    replyTo,
    subject,
    html,
    text,
  });
}

/**
 * Invite email template
 */
function inviteEmailHtml({ companyName, invitedByName, invitedByEmail, role, inviteLink }) {
  const safeCompany = escapeHtml(companyName || 'SOC SaaS');
  const safeInviter = escapeHtml(invitedByName || 'Admin');
  const safeInviterEmail = escapeHtml(invitedByEmail || '');
  const safeRole = escapeHtml(role || 'analyst');
  const safeLink = escapeHtml(inviteLink);
  return `
    <div style="margin:0;padding:0;background:#050816;font-family:Inter,Segoe UI,Arial,sans-serif;color:#e5eefc">
      <div style="max-width:640px;margin:0 auto;padding:28px 16px">
        <div style="border:1px solid #1d4ed8;border-radius:22px;overflow:hidden;background:linear-gradient(145deg,#07162e 0%,#111827 56%,#0f172a 100%);box-shadow:0 24px 60px rgba(2,6,23,.55)">
          <div style="padding:30px 32px;border-bottom:1px solid rgba(96,165,250,.22);background:radial-gradient(circle at top right,rgba(16,185,129,.22),transparent 34%),radial-gradient(circle at top left,rgba(37,99,235,.28),transparent 42%)">
            <div style="display:inline-block;padding:7px 12px;border-radius:999px;background:rgba(16,185,129,.14);color:#6ee7b7;font-size:12px;font-weight:900;letter-spacing:.06em;text-transform:uppercase">SOC SaaS Access Invitation</div>
            <h1 style="margin:18px 0 8px;color:#f8fafc;font-size:30px;line-height:1.2;font-weight:950">Secure analyst access invited</h1>
            <p style="margin:0;color:#bfdbfe;font-size:15px;line-height:1.65">
              <strong style="color:#ffffff">${safeInviter}</strong> has invited you to join <strong style="color:#ffffff">${safeCompany}</strong> on SOC SaaS.
            </p>
          </div>

          <div style="padding:28px 32px">
            <div style="display:grid;gap:12px;margin-bottom:22px">
              <div style="padding:15px 16px;border-radius:14px;background:rgba(15,23,42,.82);border:1px solid rgba(96,165,250,.22)">
                <div style="color:#94a3b8;font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:.04em">Organization</div>
                <div style="color:#e0f2fe;font-size:18px;font-weight:950;margin-top:5px">${safeCompany}</div>
              </div>
              <div style="padding:15px 16px;border-radius:14px;background:rgba(15,23,42,.82);border:1px solid rgba(16,185,129,.24)">
                <div style="color:#94a3b8;font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:.04em">Access Role</div>
                <div style="color:#34d399;font-size:18px;font-weight:950;margin-top:5px">${safeRole}</div>
              </div>
              ${safeInviterEmail ? `
                <div style="padding:15px 16px;border-radius:14px;background:rgba(15,23,42,.82);border:1px solid rgba(168,85,247,.22)">
                  <div style="color:#94a3b8;font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:.04em">Partner Admin</div>
                  <div style="color:#c4b5fd;font-size:15px;font-weight:900;margin-top:5px;word-break:break-all">${safeInviterEmail}</div>
                </div>
              ` : ''}
            </div>

            <a href="${safeLink}" style="display:block;text-align:center;text-decoration:none;background:linear-gradient(90deg,#2563eb,#7c3aed);color:#ffffff;border-radius:14px;padding:15px 20px;font-size:16px;font-weight:950;box-shadow:0 14px 30px rgba(37,99,235,.35)">Accept Invitation</a>

            <div style="margin-top:22px;border-left:4px solid #f59e0b;background:rgba(245,158,11,.12);border-radius:12px;padding:14px 16px;color:#fde68a;font-size:13px;line-height:1.6;font-weight:750">
              This secure invitation link expires in 48 hours. If you did not expect this email, ignore it or contact your Partner Admin.
            </div>
          </div>

          <div style="padding:18px 32px;background:rgba(2,6,23,.72);border-top:1px solid rgba(96,165,250,.18);color:#64748b;font-size:12px;line-height:1.6">
            SOC SaaS protects access with role-based permissions, organization scoping, and monitored login activity.
          </div>
        </div>
      </div>
    </div>
  `;
}

/**
 * Password reset email template
 */
function resetPasswordEmailHtml({ resetLink }) {
  return `
    <div style="font-family:system-ui,sans-serif;max-width:480px;margin:0 auto;padding:32px">
      <h2 style="color:#1e3a8a">Reset your password</h2>
      <p style="color:#374151">Click the button below to reset your SOC SaaS password.
         This link expires in 1 hour.</p>
      <a href="${resetLink}"
         style="display:inline-block;margin:24px 0;padding:12px 24px;background:#2563eb;
                color:#fff;border-radius:6px;text-decoration:none;font-weight:500">
        Reset password
      </a>
      <p style="color:#6b7280;font-size:13px">
        If you didn't request this, ignore this email.
      </p>
    </div>
  `;
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function partnerInvitationEmailHtml({ partnerName, adminName, email, password, loginLink }) {
  const safePartner = escapeHtml(partnerName || 'Partner');
  const safeAdmin = escapeHtml(adminName || 'Partner Admin');
  const safeEmail = escapeHtml(email);
  const safePassword = escapeHtml(password);
  const safeLogin = escapeHtml(loginLink);

  return `
    <div style="margin:0;padding:0;background:#070b1d;font-family:Inter,Segoe UI,Arial,sans-serif;color:#e5eefc">
      <div style="max-width:640px;margin:0 auto;padding:28px 16px">
        <div style="border:1px solid #1d4ed8;border-radius:20px;overflow:hidden;background:linear-gradient(145deg,#07162e 0%,#10113a 55%,#111827 100%);box-shadow:0 24px 60px rgba(15,23,42,.45)">
          <div style="padding:28px 30px;border-bottom:1px solid rgba(96,165,250,.22);background:radial-gradient(circle at top right,rgba(37,99,235,.35),transparent 38%)">
            <div style="display:inline-block;padding:7px 12px;border-radius:999px;background:rgba(34,197,94,.14);color:#86efac;font-size:12px;font-weight:800;letter-spacing:.04em;text-transform:uppercase">SOC SaaS Secure Onboarding</div>
            <h1 style="margin:18px 0 8px;color:#f8fafc;font-size:28px;line-height:1.2;font-weight:900">Partner account created</h1>
            <p style="margin:0;color:#bfdbfe;font-size:15px;line-height:1.6">Welcome ${safeAdmin}. Your partner workspace for <strong style="color:#ffffff">${safePartner}</strong> is ready.</p>
          </div>

          <div style="padding:28px 30px">
            <div style="border:1px solid rgba(96,165,250,.28);border-radius:16px;background:rgba(15,23,42,.72);padding:18px 20px;margin-bottom:22px">
              <div style="color:#93c5fd;font-size:13px;font-weight:800;margin-bottom:12px">Login credentials</div>
              <div style="display:grid;gap:12px">
                <div style="padding:12px 14px;border-radius:12px;background:#020617;border:1px solid rgba(148,163,184,.18)">
                  <div style="color:#94a3b8;font-size:12px;font-weight:700">Email</div>
                  <div style="color:#e0f2fe;font-size:15px;font-weight:800;margin-top:4px;word-break:break-all">${safeEmail}</div>
                </div>
                <div style="padding:12px 14px;border-radius:12px;background:#020617;border:1px solid rgba(148,163,184,.18)">
                  <div style="color:#94a3b8;font-size:12px;font-weight:700">Temporary Password</div>
                  <div style="color:#fbbf24;font-size:18px;font-weight:900;margin-top:4px;letter-spacing:.02em">${safePassword}</div>
                </div>
              </div>
            </div>

            <a href="${safeLogin}" style="display:block;text-align:center;text-decoration:none;background:linear-gradient(90deg,#2563eb,#7c3aed);color:#ffffff;border-radius:14px;padding:15px 20px;font-size:16px;font-weight:900;box-shadow:0 14px 28px rgba(37,99,235,.3)">Login to Partner Portal</a>

            <div style="margin-top:22px;border-left:4px solid #f59e0b;background:rgba(245,158,11,.12);border-radius:12px;padding:14px 16px;color:#fde68a;font-size:13px;line-height:1.55;font-weight:700">
              Security note: please reset your password after first login. Do not share this temporary password with anyone.
            </div>
          </div>

          <div style="padding:18px 30px;background:rgba(2,6,23,.7);border-top:1px solid rgba(96,165,250,.18);color:#64748b;font-size:12px;line-height:1.6">
            This email was sent by SOC SaaS. If you were not expecting this invitation, please contact your Super Admin.
          </div>
        </div>
      </div>
    </div>
  `;
}

module.exports = { sendMail, inviteEmailHtml, resetPasswordEmailHtml, partnerInvitationEmailHtml };
