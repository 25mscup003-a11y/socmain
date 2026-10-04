# Kafka UI email OTP verification, 2026-10-05

The local UI at `http://localhost:18080/login` requires its existing
username/password followed by a fresh six-digit email OTP. Gmail SMTP settings
come from `backend/.env`. The configured SMTP mailbox receives the code. The
Authenticator/QR flow has been removed.

Validation completed:

- Eleven isolated Node tests passed: password and OTP gating, direct-OTP,
  forged-cookie and CSRF rejection, attempt limits, challenge/session expiry,
  restart invalidation, concurrent verification, upstream failures, browser
  binding, resend invalidation/cooldown, preserved attempt counts, SMTP failures
  and acceptance of only the configured mail recipient.
- Chromium exercised the email flow against the real Kafbat instance using a
  temporary gateway and captured test emails. Invalid OTP rejection, dashboard
  rendering, logout, and a second login requiring a new email code all passed.
  No QR image is present. The resend button is available and the page fits a
  390px viewport. Brokers, topics, groups and metrics returned HTTP 200; the
  cluster was ONLINE and no browser JavaScript errors were observed.
- Gmail SMTP authentication passed with the configured account.
- The deployed gateway is healthy. A live password login sent an OTP accepted
  by Gmail SMTP; incorrect passwords and API access before OTP were rejected.
  The noninteractive live check did not read the mailbox or verify its code;
  full code verification and authenticated APIs passed in the captured-email
  browser test above. Only the OTP gateway was recreated.
- JavaScript syntax, Compose validation and `git diff --check` passed. The
  gateway uses Nodemailer 10.0.14; its dependency audit reported no known
  vulnerabilities.

The private SMTP settings file is 0600 in a 0700 runtime directory and is
mounted read-only. The full backend environment is not mounted. Codes are
stored only as keyed hashes in gateway memory, never exposed through the UI
or logs. Resend invalidates the old code and does not reset failed attempts.
Codes expire after ten minutes; sessions expire after 30 idle minutes or eight
total hours. Gateway restart invalidates sessions and pending codes.

The gateway owns the loopback binding on port 18080. Kafbat has no published
host port. These changes apply to the local UI, not the production template.
`verify-ui` sends an email and checks the login gate. In an interactive terminal,
it accepts the received code to test authenticated APIs; noninteractive runs
explicitly report those authenticated checks as not run.
