# Automatic block / isolation verification — 9 October 2026

The final requested rule is **at least two distinct threat matches from the four requested API providers**. A missing key, timeout, rate limit, malformed response, or stale result is an abstention. It does not veto two other matches. With fewer than two matches, automatic block and isolation are deferred.

| Provider | Positive match in this integration |
|---|---|
| AbuseIPDB (`ABUSEIPDB_KEY`) | Abuse confidence score >=75 |
| VirusTotal (`VIRUSTOTAL_API_KEY`) | Malicious/suspicious verdict, detections >0, or score >=10; all detections together count as one provider |
| OTX (`OTX_API_KEY`) | Pulse count >0 |
| IPinfo (`IPINFO_TOKEN`) | Queried for direct IPinfo context and trusted organization checks. The configured Lite integration provides no malicious-IP verdict, so it contributes no positive vote. Country, ASN, abuse contact, and VPN/proxy/Tor/hosting flags are not malicious verdicts. |

Consequently, the current Lite integration needs two of AbuseIPDB, OTX and VirusTotal. It does not invent a fourth threat verdict from location data. IPinfo failures do not prevent those providers from meeting quorum. Existing trusted organization/AbuseIPDB allowlist checks still veto automatic enforcement.

Feodo, Emerging Threats and Tor feeds remain optional enrichment. The gate records their cached health/hits separately; it neither waits for their downloads nor counts their hits toward the API quorum. Existing background feed refresh continues.

## Decision and delivery

- The common gate is `backend/src/services/ipsThreatGate.service.js`. IDS policy/sensor decisions, generic alert auto-block, TI auto-block, and automatic SOAR/playbook network actions pass through it before dispatch. Explicit manual actions retain their existing authorization flow.
- Successful API evidence must be less than 10 minutes old, not future dated. Concurrent decisions for the same IP share in-flight provider lookups. A cached result inside that window can be used; this does not promise a new external API call for every event.
- Each decision records provider status, match flags, matching provider names, optional feed context, and the reason in IPS audit. Failure to persist verification audit still defers enforcement.
- Approval uses version 2, policy `two-of-four`, matching IP/company/action, and at least two distinct names in `matchedProviders`. It expires within 60 seconds or sooner when supporting evidence expires. Unavailable/nonmatching evidence does not shorten the approval.
- Backend delivery, the Python agent and standalone IPS reject old version-1 approvals, missing/duplicate/unknown votes, wrong scope/action and expired proofs. Legacy queued SOAR network commands without verification require a stored manual origin; automatic/unknown origins are canceled.
- Automatic IPS isolation retains exact endpoint/company/IP, fresh heartbeat, a new persisted High/Critical threat after incident start, whitelist, recovery-race and containment checks. Its command remains valid for at most 30 seconds. Passing reputation quorum alone does not immediately isolate an endpoint.
- Insufficient quorum produces `verification_deferred`; it does not become three firewall retries followed by fallback isolation. A later detection can retry verification.

## Agent and standalone integration

Local agent IDS/Suricata/WAF network-IP blocks and geolocation-triggered block/isolate request approval from the signed `/api/agent/network-response/check` endpoint. The backend derives company/system from the authenticated agent. Provider keys remain on the backend.

The standalone IPS requests approval from `/api/ips/verify-automatic` using `IPS_WEBHOOK_SECRET` and company context. Set `SOC_BACKEND_URL` to the reachable main backend URL; its default `http://127.0.0.1:5000` is suitable only when both services share a host/network namespace. The same shared secret must be configured on both services. These endpoints return decisions; they do not issue firewall actions themselves.

Explicit country/firewall policies, HTTP request filtering, unblocking and recovery retain their existing policy flows. This change targets automatic network IP blocking and endpoint isolation.

## Validation and rollout

Validation uses mocked providers/database/transports/firewalls. It covers every pair among the three reputation providers with the other two requested providers unavailable; zero/one vote; duplicate VT detections; failed/stale/future data; optional feeds; neutral IPinfo data; expiry and scoped proofs; signed agent requests; shared-secret route authorization; legacy queued commands; engine deferral; and endpoint command delivery.

Final checks passed: 14 targeted backend test files; 71 Python agent tests; 9 standalone IPS suites / 88 tests; company and superadmin production builds; and `git diff --check`. The standalone HTTP suite required running outside the sandbox because localhost listening returned EPERM. Existing Vite CJS deprecation and bundle-size warnings remain. Build artifacts were written under `/tmp`.

The source changes require deployment/restart of the backend and standalone IPS and rebuild/sign/deployment of the updated agent package. No agent release, live firewall action, test email or real provider availability check was performed in this task. Mocked tests do not establish live enforcement or provider health.
