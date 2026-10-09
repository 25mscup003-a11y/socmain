# IDS / IPS audit — 9 October 2026

Company pages: `/company-admin/ids` aur `/company-admin/ips`.

Source audit, local database ki read-only inspection, regression tests aur mocked browser checks kiye gaye. Neeche source fixes aur current configuration alag diye hain. Live system ko isolate/block/unblock nahi kiya aur koi test email nahi bheji. Agent source changes installed endpoints par abhi deploy nahi kiye gaye hain.

## 1. Har tab ka audit

| Page / tab | Kya check hota hai | Result / fix |
|---|---|---|
| IDS — Overview | `/ids/stats`, policy violations, threat/severity overview | Summary fallback reviewed. IDS event counts ko active IP-block count ki jagah dikhana hataya. |
| IDS — Threats | `/idsips/threats`, logs, recent IDS stats; noise filtering | Sensor/threat source classification reviewed; existing regression checks passed. |
| IDS — Logs | `/idsips/logs`, filters, pagination, IP enrichment, optional AI analysis | Read/filter flow reviewed. Debug data routes ab authenticated superadmin tak restricted hain. AI provider ka live execution test nahi hua. |
| IDS — Coverage | `/idsips/capabilities`, supported sensors and attack classes | Supported capability catalog hai; ise har endpoint par live sensor running hone ka proof na samjhein. |
| IPS — Blocklist | Backend records, IPS status, selected company/agent; manual block/unblock | Confirmed / queued / failed responses alag. Whitelist skip successful block nahi. Unblock se isolation apne aap nahi khulti. Action refresh ab stale GET cache bypass karta hai. |
| IPS — Block Country | Country, department/system scope, direction, rule revision, agent sync/heartbeat status | Country policy and agent tests passed. Offline, unsupported, pending aur failed states alag hain. Management address exclusion checked. |
| IPS — Whitelist | Company allow rules, local whitelist mirror, IPS-server whitelist; IP/CIDR/domain matching | Remote whitelist match ab retry-failure ban kar auto-isolation trigger nahi karta. Whitelist tests passed. |
| IPS — WAF | Status, attacks, integration, attack-protection policy | KPI actual `/waf/attacks` statistics se aata hai. Routing/proxy/NFQUEUE ke bahar ka traffic automatically WAF-inspected nahi hota. |
| IPS — Policy IDS&IPS | Enabled rules, matching conditions, mode, revision, violations, TI gate | Policy `mode=block` ko enforcement se pehle `blocked=true` mark karna hataya. TI skip/enforcement outcome alag record hota hai. |
| IPS — Audit Log | Persisted `IpsAuditEvent`, actor, target, action, severity, metadata | Browser se fake “Server Restored”, “Isolation Completed”, “Email Sent” jaise confirmation categories nahi ban sakte. Manual actions alag record hote hain. |
| IPS — Isolation Flow | Persisted system isolation, pending commands, ACK/failure, manual reconnect | Confirmed isolation count aur pending/failed count alag. Failed/pending isolation ko manually reconnect kar sakte hain. |

IPS ke 7 KPI cards ek row mein hain; narrow screen par horizontal scrolling hai. Whitelist, WAF, policy, audit aur isolation counts actual APIs se load hote hain; failed summary requests ko false green zero dikhane ke bajay unknown dikhaya jata hai. Backend block records desired/recorded blocks bhi rakhte hain: count alone sab endpoints ke physical firewall ACKs ka proof nahi hai.

## 2. Block aur isolation kahan check hote hain

### Automatic IP block

1. IDS policy path event ka company/system, enabled policy, platform, severity, sensor, pattern, protocol, source IP aur destination port match karta hai.
2. Shared threat-intelligence gate IPinfo, AbuseIPDB, OTX aur VirusTotal query karta hai. Kam-se-kam **2 distinct threat-provider matches** chahiye. Gate defer kare to block skip hota hai.
3. Policy block / TI-confirmed sensor decision full IPS engine tak jata hai. Severity-only decisions direct IP block service use karte hain; unmein isolation/email escalation cycle nahi hoti.
4. Shared IP block service valid address, company context, reserved/private/loopback guard, company allow rules, whitelist aur wahi two-provider quorum check karti hai. Generic alert, TI aur SOAR automatic callers bhi covered hain. IPv6 aur IPv4-mapped IPv6 normalization included hai.
5. Backend block record banata hai; central IPS webhook aur eligible endpoint agents ko enforcement deta hai. Selected system ho to wahi; system selection na ho to company ke active, IPS-enabled, version-reporting agents target hote hain.
6. Central firewall ka explicit `enforced=true` ya endpoint ACK confirmation chahiye. Database save / HTTP 200 from a delegated or log-only IPS server / queued command alone proof nahi hain.
7. Full engine mein enforcement ke 3 attempts, attempts ke beech 5 seconds. Teeno enforcement attempts fail hon to block-failure email aur fresh-threat isolation check; sirf missing ACK isolation ka proof nahi hai. **TI quorum missing ho to enforcement retry/fallback isolation cycle nahi chalti**; later detection dobara verify kar sakta hai. Request/ACK/network time iske upar add hota hai.
8. Successful block ke baad current setting mein isolation skip hoti hai. Expired block incident future detection ko suppress nahi karega; manual unblock bhi completed block incident clear karta hai.

`IPS_AUTO_BLOCK=true` generic alert pipeline ko enable karta hai. Yeh har automatic path ka global kill switch nahi hai: explicit IDS policy, TI aur SOAR decisions ke apne entry points hain.

Latest user-requested policy: unavailable/failed/stale providers abstain; they do not veto two other matches. AbuseIPDB >=75, OTX pulse >0, aur VirusTotal malicious/suspicious verdict, detections >0 ya score >=10 positive signals hain. Ek provider ki multiple detections ek hi vote hain. **IPinfo Lite geo/ASN/organization deta hai, malicious verdict nahi: uska successful lookup vote nahi hai. Current integration mein AbuseIPDB/OTX/VirusTotal mein se 2 matches chahiye.** Feodo, Emerging Threats aur Tor feeds optional enrichment hain; unke hits quorum mein count nahi hote aur unka unavailable hona blocker nahi hai. Old `IPS_TI_FAIL_OPEN` setting shared quorum ko bypass nahi kar sakti. Explicit manual block/isolate automatic quorum se exempt hain. [Detailed automatic-response verification](Automatic_Response_Threat_Verification_2026-10-09.md).

### Endpoint isolation

- Automatic engine: `ipsEngine.service.js` → `ips.service.js:queueEndpointCommand` → endpoint `agent:command` or heartbeat queue.
- Manual engine API: `POST /ips-engine/isolate` — optional threat IP block attempt ke saath endpoint isolation.
- Direct system API: `POST /system/:id/isolate` — endpoint isolation command.
- Company ownership, active target and manager role check hote hain. Missing/foreign target reject hota hai.
- Command queue mein save hoti hai; socket ACK ka initial wait 4 seconds hai. Explicit manual commands offline/late agent heartbeat se execute ho sakti hain. Automatic isolation ke liye neeche diye freshness aur expiry checks mandatory hain.
- `isIsolated=true` agent confirmation ke baad. Unknown, duplicate aur superseded ACK state change nahi karte. Failed re-isolation purana confirmed isolated state nahi mitati.
- Opposite queued isolate/reconnect aur block/unblock supersede hote hain. Full queue par explicit failure milta hai; purani IPS commands silently discard nahi hoti.

Automatic isolation se pehle ab `ipsIsolationGuard.service.js` ye checks karta hai:

1. Exact company, active enrolled endpoint aur source IP; IPS/response disabled na ho. Heartbeat pichhle **2 minutes** ki ho; missing/future/stale heartbeat par isolation defer.
2. Company Firewall allow rules, local whitelist aur configured IPS server ki current whitelist recheck. Whitelist read/DB verification fail ho to automatic isolation defer.
3. Initial incident ke **baad ka naya persisted High/Critical alert**, usi company + endpoint + source IP ka, pichhle **2 minutes** mein. Status open/investigating ho. Resolved, false-positive, under-observation, manual/synthetic, already blocked/quarantined/contained aur IPS action records excluded.
4. Alert creation/receipt aur available event timestamp dono fresh hon; purani buffered telemetry sirf ab ingest hone se fresh evidence nahi banti. Current policy mein late successful IP-block ACK bhi isolation rokta hai.
5. Pending/manual recovery automatic isolation se supersede nahi hoti. Verification ke dauran manual action aaye to engine phase aur atomic queue checks automatic request rok dete hain.
6. Shared threat gate se fresh **2 distinct provider matches** required hain; ek unavailable provider alone isolation veto nahi karta. Allowlist/fresh-evidence/heartbeat checks independently mandatory hain.

Passing decision ka automatic command maximum **30 seconds** valid hai (heartbeat/evidence pehle stale ho to validity aur kam). Immediate socket delivery aur **dono backend heartbeat routes** exact original evidence/whitelist/block state dobara check karte hain. Original expiry extend nahi hoti. Agent heartbeat aur socket dispatch expired/invalid automatic command reject karte hain; purane automatic commands jinke paas fresh verification nahi hai bhi reject hote hain. Confirmed-isolation/recovery socket notifications ab action dobara execute nahi kartin. Manual isolation aur startup par already-confirmed isolation reapply supported hain; explicit manual isolate pending automatic request ko replace karta hai.

`Isolation Check` / `Isolation Deferred` audit mein reason milta hai; incident API `isolationDecision` expose karti hai. Deferred incident agle detection par dobara eligible hai. Deferred checks/expired commands ke liye isolation-success/failure email nahi bheji jati; three failed blocks ka existing Block Failed email rehta hai aur ab unconditional “Isolation Triggered” nahi kehta.

Yeh persisted threat evidence ka recheck hai, naya live malware scan nahi. Sirf duplicate counter/lastSeen update ya suppressed telemetry naya alert qualify nahi karti; insufficient fresh evidence par isolation defer rahegi. Backend aur agent clocks synchronized hone chahiye. Agent expiry/notification fixes installed agents par release deploy hone ke baad apply hongi.

### Agent par actual firewall

- **Linux:** `inet soc_isolation` nftables table. Loopback aur resolved management IP/TCP port allowed; remaining input/output dropped. Purana broad established-session allow removed. Re-isolation atomic nft batch se hoti hai; failed replacement purani isolation ko pehle remove nahi karti.
- **Windows:** original profile settings aur enabled local allow-rule names protected snapshot mein save. Existing local allow rules temporarily disable, management exception install, profiles block, effective policy verify. Reconnect original snapshot restore karta hai. GPO allow rules hon to local agent isolation success claim nahi karta. Legacy isolation with management rule but missing snapshot fails explicitly instead of guessing original policy.
- **macOS:** existing PF isolation anchor path reviewed. Native PF anchor activation / existing states / traffic verification is audit mein live test nahi hue. Existing PF-state cleanup is change mein add nahi hui; full containment certified nahi hai.
- Agent firewall permission/command failure ab successful IP-unblock ACK nahi banti. Local rule state failure par retain hoti hai.

Standalone `ipsserver` ke `/isolate` aur `/unisolate` endpoints endpoint isolation implement nahi karte; 501 return karte hain. Actual endpoint isolation main backend/agent own karte hain. Standalone service ke legacy timer/templates ko main backend timings na samjhein.

## 3. Unisolation, auto-unblock aur timings

| Action / setting | Current behavior |
|---|---|
| `IPS_BLOCK_TTL_HOURS=24` | IP block ka default duration 24 hours. Request `ttlHours=0` permanent block hai. Custom TTL central webhook tak pass hoti hai. |
| Backend expiry sweep | Har 5 minutes due blocks ke removal commands check/send karta hai. Audit records delete nahi hote. Failure/pending TTL removal retryable rehti hai; offline agent se delay badh sakta hai. |
| `IPS_AUTO_ISOLATE_DELAY_MS=300000` | 5-minute alert window only jab successful-block escalation enabled ho. |
| `IPS_ISOLATE_AFTER_SUCCESSFUL_BLOCK=false` | Abhi successful block ke baad 5-minute isolation/reminder cycle **off**. Three failed attempts wala fallback isse alag hai. |
| `IPS_ALERT_INTERVAL_MS=45000` | Applicable alert phase mein reminder 45 seconds par. Current successful-block setting mein yeh phase start nahi hota. |
| `IPS_AUTO_RECOVER_DELAY_MS=1200000` | Isolation ACK ke baad 20-minute durable recovery deadline. Manually isolated systems bhi existing auto-recovery policy mein eligible hain. |
| Recovery sweep | Startup ke lagbhag 5 seconds baad, phir har 60 seconds. Database deadline use hoti hai; duplicate in-memory recovery timer removed. |
| Offline agent | Last heartbeat 2 minutes se purani ho to auto-unisolate defer. “No telemetry” ko “safe” nahi mana jata. Is offline deferral par dedicated email nahi. |
| Recent attack | Quiet window mein same company ke endpoint ya associated source-IP ke high/critical alerts milen to isolated rehna; next check latest threat +20 minutes. Synthetic events aur IPS action records excluded. Deferral email bhejne ka attempt hota hai. |
| Quiet window passed | Reconnect queue; endpoint ACK par restored state + recovery email. Queue alone restoration nahi. |
| Manual unisolate | Isolation Flow → `DELETE /system/:id/isolate`; engine `/recover` bhi endpoint isolation hi remove karta hai. Manual override quiet-window wait bypass karta hai. |
| Manual IP unblock | `/ips-proxy/unblock` IP restriction remove/request karta hai. Network isolation alag rehti hai. |
| Explicit combined override | Blocklist ka authorization/checklist flow IP unblock ke saath `restoreEndpoint=true` dekar reconnect explicitly request karta hai. Dono outcomes alag hain. |

Auto-unisolation threat IP ka block nahi hatati. IP ke liye uski TTL ya explicit unblock action chahiye. Expiry deadline exact second par physical removal guarantee nahi karti; sweeper interval, connectivity aur ACK matter karte hain.

## 4. Email kis ko jaati hai

Main backend recipient resolver: active company admins + target system ke department admins (`departmentId` or `departmentIds`) + authenticated actor/fallback where available + configured `SMTP_USER`. Addresses lowercase/deduplicated hain. Manual override audit ab isi resolver ko use karta hai.

Read-only inspection mein main company `6a8efb532c942f67c29534cc` ke recipients:

| Affected systems | Company admin | Department admin | SMTP sender copy |
|---|---|---|---|
| `windows`, `vivo`, `linux1`, `kali` | `av96165607@gmail.com` | `av96165@gmail.com` | `av96165607@gmail.com` — duplicate remove hota hai |
| `h` | `av96165607@gmail.com` | `av961@gmail.com` | Same sender — duplicate remove hota hai |
| No associated target department | Company admin | Department cannot be resolved | Sender remains included |

Doosri companies ke admins `av9616@gmail.com` aur `av9@gmail.com` is company's admin lookup mein include nahi hote. **SMTP sender copy global hai:** doosri company ke incident par bhi configured sender ko copy milegi. Recipient department selection aur action authorization alag cheezein hain; manager middleware company scope enforce karta hai, sab IPS response routes par department-only authorization boundary nahi hai.

Configured sender: `SOC SaaS <av96165607@gmail.com>`, Gmail SMTP, port 587. Credentials present the; secret values report mein include nahi kiye.

| Event | Email behavior |
|---|---|
| Normal successful auto-block, current configuration | Dedicated isolation-cycle email nahi |
| Manual block API | Dedicated email nahi |
| Three unsuccessful full-engine block attempts | Block Failed notification |
| Applicable alert phase | Initial alert + configured reminders |
| Automatic isolation deferred / expired | Audit + dashboard reason; no isolation-confirmation email |
| Isolation ACK success/failure | Isolation Completed / Isolation Failed notification; direct system/restart paths covered |
| Manual unisolate / auto-unisolate queued | Queue ko restored email nahi mana jata |
| Reconnect ACK success/failure | Recovery confirmation / Recovery Failed notification |
| Recovery deferred by recent high/critical alert | Deferral notification; system remains isolated |
| UI manual unblock / explicit override | Approval/request email, followed separately by reconnect ACK notification if reconnect requested |
| TTL auto-unblock or bare IP-unblock API | No dedicated main-engine email; command/agent/block record tracks the action |

SMTP accepting a message is **not inbox delivery proof**. Rejected recipients / SMTP errors record failure. Durable email outbox/retry and inbox delivery verification are not implemented. Backend restart between state ACK and email delivery can still lose a notification; audit/database availability also matters.

Read-only snapshot: 5 systems, none isolated; no active/overdue active backend IP blocks. Historical audit contained detection/incident/user-action/attack-cleared records, but no Email Sent/Email Failed records. This is not evidence that every historical email reached an inbox.

## 5. Validation and remaining operational checks

Latest two-provider quorum follow-up: 14 targeted backend test files, 71 Python tests, 9 standalone suites / 88 tests, both frontend production builds and whitespace checks passed. [Final policy, coverage and rollout details](Automatic_Response_Threat_Verification_2026-10-09.md). The earlier isolation/UI audit results below remain historical evidence for those changes.

- Backend: 16 relevant test files passed after the isolation-guard fix; added tests cover ACK dedupe, inverse commands, full queue, whitelist bypass, incident expiry, manual-recovery race, route ownership/status and email recipient/rejection behavior.
- Agent: 44 Python tests passed across firewall, isolation, heartbeat, whitelist and country policy. Native Windows PowerShell execution was mocked; snapshot script generation/selection is covered, Windows execution is not certified by these tests.
- Standalone IPS (earlier audit): 8 suites / 70 tests passed, with log-only/mocked enforcement. Local test-server listen required sandbox escalation.
- Company and superadmin production builds passed with the new isolation audit filters and deferred-state refresh. Existing Vite deprecation / large-bundle warnings remain.
- Browser (earlier audit): 11 tabs opened with mocked API data and no page JavaScript errors; 7 IPS cards verified in one row at 1440px and 390px. Read-only smoke issued no mutation requests. Additional mocked checks passed for pending IP-unblock and failed unisolate messages. [Browser results](IDS_IPS_Browser_Checks_2026-10-09.json).
- New isolation regressions cover initial/stale/buffered/foreign/resolved/synthetic/contained alerts, missing heartbeat, disabled response, whitelist/read failure, 3 unsuccessful block attempts, the 5-minute escalation path, late ACKs, manual recovery races, fresh retry, short expiry, and agent heartbeat/socket dispatch. Tests use mocked database/transport/firewall calls; no real isolation or email was performed.
- Whitelist/country/backend policy tests do not prove a live router, packet sensor or mail inbox is configured correctly.

Before treating this as deployed enforcement: rebuild/sign the agent package, deploy through the normal release process, and test one controlled Linux/Windows endpoint with an independent recovery path. Check allowed management traffic, blocked existing/new sessions, DNS/reconnection behavior, actual firewall rules, ACKs, recovery and real email delivery. No release was published and no endpoint was updated during this audit.

Known limits to retain in review: multi-worker concurrent TTL/re-block operations do not have a distributed per-target lock; company-wide block records do not model every endpoint/port as a separate durable enforcement lifecycle; multi-endpoint ACK details need to be read per endpoint. Main incident alert/retry timers are still in memory, whereas recovery deadlines are durable. A management hostname that needs fresh DNS or changes address during isolation requires a stable recovery design. These are not certified by the mocked tests.

Source entry points: [company page](../../company/src/pages/IDSPage.jsx), [IDS ingestion/policies](../../backend/src/routes/ids.routes.js), [IP service and ACK queue](../../backend/src/services/ips.service.js), [engine/recovery/email](../../backend/src/services/ipsEngine.service.js), [fresh isolation guard](../../backend/src/services/ipsIsolationGuard.service.js), [agent expiry guard](../../backend/soc-agent/core/command_guard.py), [manual routes](../../backend/src/routes/ips-engine.routes.js), [agent firewall](../../backend/soc-agent/core/fw_backend.py), [Windows snapshot restoration](../../backend/soc-agent/core/windows_isolation.py).
