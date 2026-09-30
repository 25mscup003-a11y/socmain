# AJNAT SOC — Repository-Audited 12-Month Financial Model

**Prepared:** 12 September 2026  
**Currency:** USD; investor-summary INR conversion at **$1 = ₹88** (**ASSUMPTION; verify at transaction date**)  
**Purpose:** planning and technical due diligence, not an accounting opinion, vendor quotation, tax opinion, or investment solicitation.

## 1. Executive answer

AJNAT SOC is a functioning, broad security platform rather than a generic SaaS dashboard. The repository contains two React portals, a large Node/Express API, MongoDB operational storage, authenticated Socket.IO, multi-tenant and role-scoped SOC workflows, Python and Android endpoint agents, an independent IPS webhook/firewall service, Velociraptor, SOAR, reporting, audit trails, and optional production-scale Kafka, Redis, ClickHouse, S3-compatible archival, KMS, and OpenTelemetry.

The endpoint does not carry a fixed third-party fee per installation. It does, however, generate recurring ingestion, database, archive, network, monitoring, and support load. In the base model that scalable usage is **$0.25 per paid agent/month**, plus the stepwise infrastructure tier. The largest unresolved commercial dependency is threat intelligence: the code calls VirusTotal in commercial workflows, but its public API is not permitted for commercial products. The base model therefore reserves **$6,500/month shared API/TI cost**, principally a **$6,250/month external estimate** based on the published $75,000 annual Google Threat Intelligence API-slot reference. A signed quotation and license-right review are mandatory.

At list price of **$20/agent/month**, steady-state break-even is approximately **2,026 paid agents**, or **$40,520 MRR**, under the lean loaded team and base shared-service assumptions. For operating safety, the commercial target should be **2,200–2,500 agents**. At 1,000 paid agents, the representative base burn is **$40,250/month** and annual cost is **$483,000**; annual revenue is $240,000, producing a $243,000 operating loss. At 2,500 agents, the modeled annual operating profit becomes approximately $99,300 before tax.

Recommended funding is **$0.75M for 18 months**, including contingency and scale-up headroom. This is higher than a simple 18 × current burn calculation because enterprise security procurement requires audits, redundancy, onboarding capacity, and a sales cycle buffer.

### Classification legend

- **KNOWN:** supplied business fact, notably $20 list price and $200 starting server assumption.
- **CODE-DERIVED:** directly evidenced by active source/configuration.
- **ASSUMPTION:** management-model input requiring approval.
- **EXTERNAL ESTIMATE:** market or vendor-derived planning input, not a quote.
- **NEEDS VERIFICATION:** quotation, measured load, contract, accounting, legal, or tax evidence required.

All forecasts are planning estimates. No projected value is represented as a historical fact.

## 2. Repository audit and implementation findings

### 2.1 Applications and service topology

| Area | Finding | Status / evidence classification | Cost implication |
|---|---|---|---|
| Company/partner/SOC portal | React 18 + Vite application in `company`; Axios, Leaflet, Socket.IO client, Razorpay and Stytch config | CODE-DERIVED | CDN/static hosting, maps/auth/payment usage, support for a large UI surface |
| Super Admin portal | Separate React 18 + Vite application in `superadmin`; administration, companies, partners, SOC managers, revenue, security and reports | CODE-DERIVED | Separate build/deployment and privileged-access testing |
| Core backend | Node/Express app in `backend/src/server.js`, with 80+ route modules and Socket.IO | CODE-DERIVED | API compute, load balancer, WebSocket capacity, patching/on-call |
| Operational database | Mongoose with a large MongoDB model set: companies, tenants, systems, agents, alerts, events, cases, assignments, payments, audit, SOAR and evidence metadata | CODE-DERIVED | Primary DB, indexes, replicas, backups, IOPS and retention |
| Endpoint agent | Python cross-platform agent in `backend/soc-agent`; packaged/downloaded by backend; Android agent also present | CODE-DERIVED | Telemetry volume, signing, release pipeline, bandwidth and endpoint QA |
| Agent/server communications | Authenticated HTTPS/mTLS-capable API; heartbeat/policy sync, telemetry/alerts, response commands; Socket.IO is primarily portal/server live fan-out | CODE-DERIVED | Requests per endpoint, TLS, ingress compute, egress responses |
| IPS service | Independent Node service under `ipsserver/back-end`, direct MongoDB driver, Socket.IO, SMTP, webhook secret, firewall execution integrations | CODE-DERIVED | Separate process/host isolation, privileged operations and monitoring |
| Network/security tooling | Zeek/Suricata documentation and ingestion paths; nftables/iptables/platform-firewall execution; WAF/IDS/IPS routes | CODE-DERIVED, deployment activation NEEDS VERIFICATION | Sensor placement and throughput can exceed central SaaS costs; customer-prem sensor may be preferable |
| Velociraptor | Server/client systemd configurations, API integration and persisted datastore/filestore | CODE-DERIVED | Server storage/compute and forensic collection bursts |
| Kafka | KafkaJS producer/consumer, retry and DLQ topics; compose stack; required by high-scale profile | CODE-DERIVED, optional at low scale | Broker cluster/storage from scale tier onward |
| Redis | Socket.IO adapter, nonce store and scalable read cache | CODE-DERIVED, optional at low scale; required by high-scale profile | HA cache/fan-out service |
| ClickHouse | Active service implementation and migration; `HOT_EVENT_STORE=clickhouse/dual` | CODE-DERIVED, optional at low scale | Analytical event store from mid/high scale |
| Object archive | AWS SDK S3 archive worker and provisioning script | CODE-DERIVED, feature-gated | Object storage, requests, lifecycle and retrieval |
| Key management | Local-file or AWS KMS provider, tenant keys, rotation and audit | CODE-DERIVED | KMS requests/key fees or secure local HSM-like operations |
| Observability | Prometheus client `/metrics`, OpenTelemetry HTTP instrumentation/export, runtime logging | CODE-DERIVED | Metrics/log/traces retention and alerting |
| Reports/evidence | Daily/compliance reports, encrypted evidence locker, upload staging, backup encryption | CODE-DERIVED | Durable/WORM-capable storage, backup and rendering compute |
| Authentication | JWT, Argon2/bcrypt, 2FA/TOTP/QR, trusted devices; Stytch telemetry/fraud integration | CODE-DERIVED | Authentication/fingerprint/SSO usage and enterprise identity work |
| Multi-tenancy | Tenant middleware, company and department scoping, tenant keys, socket authorization, SOC company/department assignments | CODE-DERIVED | Isolation tests, per-tenant retention/KMS, compliance burden |
| SOC roles | SOC Manager, L1, L2 and L3 routes and dashboards, invitations, shifts, escalation, chat, cases, audit review | CODE-DERIVED | Human 24×7 coverage is not provided merely by software and must be priced separately |
| Partner channel | Partner dashboard, registration, approvals, commissions/payment gates and SOC manager functions | CODE-DERIVED | Channel support, commission and reconciliation |
| SOAR | Rules, templates, connectors, approvals, execution/audit logs, deterministic/default playbooks and automated endpoint responses | CODE-DERIVED | Connector support, secret custody, false-positive liability |
| Background work | Alert worker, archive worker, correlation timers, threat-feed refresh, heartbeat sweeper, daily/periodic reports, KMS rotation and IPS recovery timers | CODE-DERIVED | Dedicated workers and durable scheduling needed in production |

### 2.2 Active external services

Active code references were found for Azure AI, VirusTotal, AbuseIPDB, AlienVault OTX, IPinfo Lite, ip-api.com, proxycheck.io, Stytch, SMTP, Razorpay, Google Maps configuration, Slack/generic SOAR webhooks, Velociraptor, AWS S3/KMS, and public Feodo Tracker, Emerging Threats and Tor feeds. Merely declared packages were not counted unless a source import or runtime call was present.

No Twilio-style SMS provider was found. TOTP is local through Speakeasy; email is SMTP. Google Maps has a frontend key but actual billable request volume and enabled map SKU require verification. Razorpay is transactional rather than a fixed infrastructure fee and is excluded from revenue/gross margin until merchant pricing and collection geography are confirmed.

### 2.3 Material technical-financial caveats

1. The checked-in scale guide explicitly identifies roughly 10,000–20,000 reporting agents as the high profile and requires durable ingestion, distributed sockets, analytical storage and multiple API nodes. Therefore $200/month cannot credibly cover the upper tiers.
2. Local Kafka compose is single-broker, replication factor 1 and plaintext internally. It is useful for development, not the assumed enterprise HA production topology.
3. Some agent defaults poll frequently (examples include 10-second Windows event polling, 20-second network polling, 30–60-second process/memory/file intervals and 5-minute inventories). Only findings/aggregates should be transmitted. Actual bytes/agent/day are **NEEDS VERIFICATION** through a 30-day telemetry benchmark.
4. The code supports local file evidence and archives, but production retention, immutability, residency and customer deletion policies are management decisions. They strongly affect storage COGS.
5. Feature breadth raises QA and support cost. “Implemented route/page” does not itself prove production hardening, sensor coverage, 24×7 operations, SLA, or regulatory certification.

## 3. Architecture cost map

Base costs below represent the 1,000-agent planning case and are allocations, not vendor quotes.

| Component | Technology | Purpose | Current implementation | Cost driver | Fixed/variable | Est. monthly cost |
|---|---|---|---|---|---|---:|
| Web/API nodes | Node/Express | REST, auth, package delivery, workflows | Active | CPU, concurrency, agent requests | Step-fixed | $350 |
| Frontend hosting/CDN | Vite static builds | Company and Super Admin portals | Active builds | bandwidth/builds | Mostly fixed | $40 |
| Load balancer/TLS/DNS | Reverse proxy/LB | HTTPS, WebSocket routing | Production dependency | connections, certificates, egress | Step-fixed | $75 |
| MongoDB | MongoDB/Mongoose | Operational and tenant records | Core active store | data, indexes, IOPS, HA | Step-fixed + variable | $350 |
| Redis | Redis | socket fan-out, cache, nonce | Active optional paths | memory, HA | Step-fixed | $75 |
| Kafka/workers | Kafka/KafkaJS | durable alert ingestion, retry/DLQ | Active optional broker mode | events, partitions, storage | Step-fixed | $150 |
| ClickHouse | ClickHouse | hot analytical events | Active optional/dual mode | compressed events, queries | Step-fixed + variable | $125 |
| Object/evidence/archive | S3-compatible/local | packages, encrypted evidence, cold events | Active feature paths | GB-month, requests, retrieval | Variable | $75 |
| Velociraptor | Velociraptor | hunts/forensics | Active integration/config | collected evidence, hunt bursts | Step-fixed + variable | $75 |
| Monitoring/logs/backups | Prometheus/OTel/logs/snapshots | availability, auditability, recovery | Instrumented; provider TBD | GB ingest/retention, backup size | Variable | $110 |
| IPS isolation | Node webhook + OS/vendor firewall | block/unblock/WAF operations | Separate active service | protected sites, webhook load | Step-fixed | $50 |
| DR reserve | Cross-zone backups/restore testing | recovery | Production requirement | copy size and warm capacity | Step-fixed + variable | $25 |
| **Total** |  |  |  |  |  | **$1,500** |

At 100 agents the **KNOWN $200 base production server** can host API/IPS for a pilot, but the complete minimum production allowance is $700 after database, backup, staging and monitoring. It is not an HA/SLA-grade configuration.

## 4. Infrastructure scale plan

### Base monthly infrastructure

| Paid agents | Likely topology | Monthly | Annual | Trigger / qualification |
|---:|---|---:|---:|---|
| 100 | 1 × ~$200 production VM; small managed Mongo or replica-capable DB; tiny staging; backups/monitoring | $700 | $8,400 | Pilot; limited HA; measured retention required |
| 500 | Larger API host or 2 small nodes, DB upgrade, staging, object backup | $1,000 | $12,000 | Add LB if SLA customers arrive |
| 1,000 | 2 API/process roles, managed Mongo, Redis/Kafka starter, archive/monitoring | $1,500 | $18,000 | Separate workers and IPS privileges |
| 5,000 | 3–4 API/worker nodes, Mongo replica tier, Redis, 3-node Kafka or managed equivalent, ClickHouse, S3 | $4,500 | $54,000 | Durable ingestion and analytical store required |
| 10,000 | 4–8 API/worker capacity, HA Mongo/Redis, 3 brokers, ClickHouse replicas, stronger monitoring/DR | $8,500 | $102,000 | Repository high-scale profile begins |
| 25,000 | Two failure domains, larger DB/analytics cluster, partition growth, warm DR | $18,000 | $216,000 | Load and restore testing mandatory |
| 50,000 | Multi-zone fleet, sharded/partitioned data services, dedicated security/observability and DR | $34,000 | $408,000 | Architecture review; regional split may be required |

The requested 2,500-agent interpolation is **$2,600/month** ($31,200/year). These figures assume central ingestion of security findings and bounded telemetry—not raw packet capture from every endpoint. Raw PCAP or unlimited full logs must be metered and sold as an add-on.

### Sensitivity range

| Cost case | 100 | 1,000 | 10,000 | 50,000 | Meaning |
|---|---:|---:|---:|---:|---|
| Low | $450 | $1,000 | $5,500 | $22,000 | self-managed, shorter retention, no warm DR |
| Base | $700 | $1,500 | $8,500 | $34,000 | production planning case above |
| High | $1,200 | $3,000 | $17,000 | $68,000 | managed HA, longer retention, higher event rate/residency |

**NEEDS VERIFICATION:** events and bytes per agent/day, alert rate, dashboard concurrency, evidence volume, 90th/99th percentile query latency, RPO/RTO, data residency and retention. These measurements determine the correct tier more than endpoint count alone.

## 5. Third-party API and service audit

| Service | Used where / purpose | Pricing model | Estimated base usage | Monthly | Annual | Classification |
|---|---|---|---|---:|---:|---|
| Google Threat Intelligence / VirusTotal | Backend and endpoint hash/IP/URL enrichment; SOAR connector | Commercial license/quota | Shared commercial slot/reserve | $6,250 | $75,000 | EXTERNAL ESTIMATE; **EXTERNAL PRICING VERIFICATION REQUIRED** |
| AbuseIPDB | Threat-intel service IP checks | Plan quota | Premium planning tier, ≤50k checks/day | $89 | $1,068 | EXTERNAL ESTIMATE; current public annual-billed price |
| AlienVault OTX | IP/domain enrichment | Public/community API; commercial rights/limits must be reviewed | Cached and alert-triggered | $0 | $0 | ASSUMPTION; **EXTERNAL PRICING VERIFICATION REQUIRED** |
| Public Feodo/ET/Tor feeds | Scheduled list download | Public feed terms | Periodic shared refresh | $0 | $0 | CODE-DERIVED + NEEDS VERIFICATION of redistribution rights |
| Azure AI | AI analysis job service | Tokens/model/region | $0.10/agent/mo base workload allocation | $100 at 1k | $1,200 | ASSUMPTION; **EXTERNAL PRICING VERIFICATION REQUIRED** |
| Stytch | Fingerprint/auth/fraud lookup | MAU/fingerprints, connections/add-ons | ≤10k MAU/fingerprints | $0–$99 | $0–$1,188 | EXTERNAL ESTIMATE; branding/enterprise SLA extra |
| IPinfo Lite | Login/IP enrichment | Lite currently free for basic country/ASN | Cached shared lookups | $0 | $0 | EXTERNAL ESTIMATE; attribution/endpoint compatibility review required |
| ip-api.com / ipwho.is / proxycheck.io | Fallback geolocation/privacy | Public/freemium limits | Alert/login triggered | $0 pilot; $50 reserve | $0–$600 | ASSUMPTION; **EXTERNAL PRICING VERIFICATION REQUIRED** |
| SMTP/email | Invites, alerts, reports, support, SOAR | Per message/dedicated IP/provider | 25k–100k transactional messages | $50 | $600 | EXTERNAL ESTIMATE |
| Google Maps | Configured frontend key / maps | SKU/request based | Low dashboard map usage | $0–$100 | $0–$1,200 | ASSUMPTION; **EXTERNAL PRICING VERIFICATION REQUIRED** |
| Razorpay | Checkout/subscriptions/partner payments | Transaction percentage + taxes | Applied to collected revenue | Excluded | Excluded | NEEDS VERIFICATION; model separately by payment mix |
| AWS/S3-compatible archive | Cold events/evidence | GB-month, request, retrieval, egress | Included in infrastructure tier | Included | Included | ASSUMPTION |
| AWS KMS | Tenant/master key operations | Key-month + requests | Included in infrastructure tier | Included | Included | ASSUMPTION |
| Slack/generic webhook | SOAR notification connector | Customer workspace or provider plan | BYO connector | $0 | $0 | ASSUMPTION |
| Velociraptor | Self-hosted open-source server | Infrastructure/support | Included in infrastructure | Included | Included | CODE-DERIVED |

The model rounds these into a **$6,500/month fixed/shared API reserve + $0.25/agent/month variable API/usage allowance**. Low case is $250/month shared + $0.10/agent if premium VT is omitted/BYOK; high case is $12,500/month shared + $0.75/agent. The low case is not acceptable for a commercial VT-powered promise until licensing is resolved.

## 6. Revenue and pricing

Formulae:

`Monthly revenue = active paid agents × price per agent/month`  
`Annualized revenue (ARR) = monthly revenue × 12`

| Agents | Standard MRR @ $20 | Standard ARR | Enterprise MRR @ $15 | Enterprise ARR | Large-volume MRR @ $10 | Large-volume ARR |
|---:|---:|---:|---:|---:|---:|---:|
| 100 | $2,000 | $24,000 | $1,500 | $18,000 | $1,000 | $12,000 |
| 500 | $10,000 | $120,000 | $7,500 | $90,000 | $5,000 | $60,000 |
| 1,000 | $20,000 | $240,000 | $15,000 | $180,000 | $10,000 | $120,000 |
| 2,500 | $50,000 | $600,000 | $37,500 | $450,000 | $25,000 | $300,000 |
| 5,000 | $100,000 | $1,200,000 | $75,000 | $900,000 | $50,000 | $600,000 |
| 10,000 | $200,000 | $2,400,000 | $150,000 | $1,800,000 | $100,000 | $1,200,000 |
| 25,000 | $500,000 | $6,000,000 | $375,000 | $4,500,000 | $250,000 | $3,000,000 |
| 50,000 | $1,000,000 | $12,000,000 | $750,000 | $9,000,000 | $500,000 | $6,000,000 |

Discount guardrail: $15 remains attractive after base variable cost; $10 should require minimum volume, annual prepayment, bounded retention/support, and excluded premium TI or customer-provided licenses. Otherwise large accounts can consume disproportionate storage and SOC labor.

## 7. Year-1 staffing

Salary assumptions reflect an India-centered remote startup team paid in USD equivalents. Hiring geography, shift allowance, equity and seniority are **NEEDS VERIFICATION**. Founder pay is included; no free labor is assumed.

### Lean startup team

| Role | HC/FTE | Monthly salary/FTE | Monthly total | Annual total | Why required |
|---|---:|---:|---:|---:|---|
| Founder/CTO | 1.0 | $2,500 | $2,500 | $30,000 | architecture, product, enterprise diligence |
| Backend developers | 2.0 | $2,000 | $4,000 | $48,000 | API, ingestion, tenancy, integrations |
| Frontend developer | 1.0 | $1,600 | $1,600 | $19,200 | two broad portals |
| DevOps/Cloud engineer | 0.5 | $2,000 | $1,000 | $12,000 | deploy, backup, monitoring, incident response |
| SOC Manager | 1.0 | $2,200 | $2,200 | $26,400 | playbooks, QA, shifts, customers |
| L1 analysts | 2.0 | $800 | $1,600 | $19,200 | triage; not full 24×7 coverage |
| L2 analyst | 1.0 | $1,300 | $1,300 | $15,600 | investigation/escalation |
| L3/threat hunter | 0.5 | $2,200 | $1,100 | $13,200 | hard incidents/detections |
| QA engineer | 0.5 | $1,200 | $600 | $7,200 | endpoint/platform regression |
| Customer support | 1.0 | $800 | $800 | $9,600 | onboarding and tickets |
| Sales executive | 1.0 | $1,300 | $1,300 | $15,600 | pipeline and closes |
| Finance/admin | 0.5 | $1,600 | $800 | $9,600 | billing, payroll, contracts |
| **Cash salaries** | **12.0 FTE-equivalent** |  | **$18,800** | **$225,600** |  |
| Employer benefits/overhead | 15% |  | $2,820 | $33,840 | payroll taxes/benefits/equipment allowance |
| Hiring/shift/contractor reserve | — | — | $1,380 | $16,560 | leave, specialist legal/security cover |
| **Loaded payroll** |  |  | **$23,000** | **$276,000** | base model |

This team cannot promise staffed 24×7 human monitoring. A single continuously staffed L1 seat generally needs about 4.5–5.0 FTE after leave/training. Sell software/business-hours monitoring initially, or price a separately staffed MDR tier.

### Growth team

| Role | Headcount | Monthly total | Annual total | Rationale |
|---|---:|---:|---:|---|
| Leadership: CEO/CTO, product/security, finance/admin | 3.0 | $8,000 | $96,000 | governance, product and finance |
| Backend/data/platform engineering | 5.0 | $11,000 | $132,000 | scale and reliability |
| Frontend/mobile/endpoint engineering | 3.0 | $5,400 | $64,800 | portals plus endpoint matrix |
| DevOps/SRE/security engineering | 2.0 | $5,000 | $60,000 | HA, on-call, hardening |
| QA/automation | 2.0 | $2,800 | $33,600 | release and agent compatibility |
| SOC Manager/shift leads | 2.0 | $4,800 | $57,600 | operations and quality |
| L1 analysts | 6.0 | $5,400 | $64,800 | extended shifts; capacity depends on alert rate |
| L2 analysts | 3.0 | $4,500 | $54,000 | investigations |
| L3/threat hunting/detection | 2.0 | $5,000 | $60,000 | research/content and incidents |
| Customer success/support | 3.0 | $3,000 | $36,000 | onboarding/renewals |
| Sales/BD | 3.0 | $5,000 | $60,000 | enterprise/channel pipeline |
| **Cash salaries subtotal** | **34.0** | **$59,900** | **$718,800** |  |
| 15% employer overhead | — | $8,985 | $107,820 | benefits/taxes/tools |
| **Fully loaded growth payroll** |  | **$68,885** | **$826,620** | full target organization |

For scenario comparability, the profit table uses a staged **$50,000/month ($600,000/year)** growth payroll at 10,000+ agents, assuming hiring lags and some roles remain fractional during the year. The full growth organization above should be used for a mature annual budget.

## 8. Other operating expenses

### Lean monthly budget

| Item | Monthly | Annual | Classification |
|---|---:|---:|---|
| Legal, company secretarial, accounting and tax | $500 | $6,000 | ASSUMPTION |
| Domain/DNS/certificates | $50 | $600 | ASSUMPTION; TLS certificates can be free |
| Developer/collaboration/software subscriptions | $750 | $9,000 | ASSUMPTION |
| Remote work/equipment amortization | $500 | $6,000 | ASSUMPTION |
| Marketing/content/advertising | $3,000 | $36,000 | ASSUMPTION |
| Sales commission reserve | $1,000 | $12,000 | ASSUMPTION; should ultimately be revenue-variable |
| Customer onboarding/training | $400 | $4,800 | ASSUMPTION |
| Travel/events | $350 | $4,200 | ASSUMPTION |
| Compliance/readiness | $700 | $8,400 | ASSUMPTION |
| Penetration testing/audit reserve | $500 | $6,000 | ASSUMPTION; actual engagement lumpy |
| Cyber/E&O/D&O insurance | $250 | $3,000 | ASSUMPTION; quote required |
| Administrative/banking/office | $300 | $3,600 | ASSUMPTION |
| Emergency contingency | $700 | $8,400 | ASSUMPTION |
| **Total** | **$9,000** | **$108,000** |  |

Growth scenario uses $20,000/month ($240,000/year) for higher marketing, commissions, compliance, insurance, travel and onboarding. Payment processing, indirect taxes and sales taxes are excluded because customer/payment geography is unknown; payment fees should reduce revenue or enter COGS once quoted.

## 9. Complete Year-1 operating cost — representative 1,000-agent steady state

| Expense category | Monthly | Annual | Fixed/variable | Assumption | Confidence |
|---|---:|---:|---|---|---|
| Production + staging infrastructure | $1,500 | $18,000 | Step-fixed/variable | base scale tier | Medium |
| Shared APIs/TI | $6,500 | $78,000 | Mostly fixed | commercial TI reserve | Low until quote |
| API/usage variable allowance | $250 | $3,000 | Variable | $0.25 × 1,000 | Low/medium |
| Loaded payroll | $23,000 | $276,000 | Semi-fixed | lean staffing | Medium |
| Sales & marketing incl. commission | $4,000 | $48,000 | Mixed | lean budget | Medium |
| Administration, support, compliance, audit, insurance, travel | $4,300 | $51,600 | Mixed | itemized above | Low/medium |
| Contingency | $700 | $8,400 | Reserve | itemized above | Medium |
| **Total / burn** | **$40,250** | **$483,000** |  |  |  |

Roll-up: infrastructure $18,000; APIs $81,000; payroll $276,000; sales/marketing $48,000; administration/other $51,600; contingency $8,400. **Total Year-1 cash requirement before revenue: $483,000.** With $240,000 annualized revenue at a constant 1,000 agents, net cash burn is approximately $243,000 before working-capital timing and taxes.

Low/base/high annual gross cash need at the 1,000-agent scale is approximately **$330k / $483k / $760k**. Low assumes founder-heavy staffing and BYO/limited TI; high assumes stronger staffing, managed HA, larger compliance program and premium services. Board approval should be based on the base case plus contingency, not the low case.

## 10. Unit economics

Base at 2,500 agents (where shared costs are more representative):

| Metric | Calculation | Result | Treatment |
|---|---|---:|---|
| Revenue/agent/month | list price | $20.00 | Revenue |
| Variable API/usage | assumption | $0.25 | COGS |
| Infrastructure/agent | $2,600 / 2,500 | $1.04 | COGS |
| Shared TI/API allocation | $6,500 / 2,500 | $2.60 | COGS |
| Direct cost/agent/month | $0.25 + $1.04 + $2.60 | $3.89 | COGS |
| Gross profit/agent/month | $20 − $3.89 | $16.11 | Gross profit |
| Gross margin | $16.11 / $20 | 80.6% | Base allocation |
| Contribution margin before shared TI | $20 − $0.25 − $1.04 | $18.71 (93.6%) | Scale decision metric |
| Support/SOC labor allocation | $23,000 / 2,500 | $9.20 | OPEX in SaaS model; COGS if sold as managed service |

Per-customer costs depend on seats. At 100 endpoints/company in this case, infrastructure allocation is ~$104/month, shared+variable API allocation ~$285/month and loaded support/SOC allocation ~$920/month. The company pays $2,000/month at list price. Customer-specific onboarding, raw-log retention and SLA should be separately priced.

### CAC and LTV assumption

For a representative 100-agent customer:

- **CAC:** $8,000 (**ASSUMPTION**) including enterprise sales labor, marketing, proof-of-concept and onboarding.
- **Gross profit/customer/month:** 100 × $20 × 80.6% = **$1,612**.
- **Monthly logo churn:** 1.5% (**ASSUMPTION**), implying ~66.7-month simple lifetime; use a conservative 36-month cap.
- **LTV:** $1,612 × 36 = **$58,032**.
- **LTV/CAC:** $58,032 / $8,000 = **7.25×**.
- **CAC payback:** $8,000 / $1,612 = **5.0 months**.

This is a target, not observed performance. Until cohort retention and booked sales-cost data exist, CAC/LTV are **NEEDS VERIFICATION**. At 25-agent SMB size, onboarding can destroy these economics; use channel/self-serve motions or a minimum platform fee.

## 11. Steady-state profit scenarios

All scenarios assume the stated agent count is active for all 12 months; they are not ramp-year forecasts. Formulae: revenue = agents × $20 × 12; API = ($6,500 + $0.25 × agents) × 12; gross profit = revenue − infrastructure − API; operating profit = gross profit − payroll − other OPEX; estimated net profit = positive operating profit × 75% (25% illustrative tax) or the full loss. Taxes are jurisdiction-dependent and **NEEDS VERIFICATION**.

| Scenario | Agents | Annual revenue | Annual infra | API/TI | Payroll | Other | Total cost | Gross profit | EBITDA/operating profit | Net estimate | Net margin |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| A | 100 | $24,000 | $8,400 | $78,300 | $276,000 | $108,000 | $470,700 | -$62,700 | -$446,700 | -$446,700 | -1,861.3% |
| B | 500 | $120,000 | $12,000 | $79,500 | $276,000 | $108,000 | $475,500 | $28,500 | -$355,500 | -$355,500 | -296.3% |
| C | 1,000 | $240,000 | $18,000 | $81,000 | $276,000 | $108,000 | $483,000 | $141,000 | -$243,000 | -$243,000 | -101.3% |
| D | 2,500 | $600,000 | $31,200 | $85,500 | $276,000 | $108,000 | $500,700 | $483,300 | $99,300 | $74,475 | 12.4% |
| E | 5,000 | $1,200,000 | $54,000 | $93,000 | $276,000 | $108,000 | $531,000 | $1,053,000 | $669,000 | $501,750 | 41.8% |
| F | 10,000 | $2,400,000 | $102,000 | $108,000 | $600,000 | $240,000 | $1,050,000 | $2,190,000 | $1,350,000 | $1,012,500 | 42.2% |
| G | 25,000 | $6,000,000 | $216,000 | $153,000 | $600,000 | $240,000 | $1,209,000 | $5,631,000 | $4,791,000 | $3,593,250 | 59.9% |
| H | 50,000 | $12,000,000 | $408,000 | $228,000 | $600,000 | $240,000 | $1,476,000 | $11,364,000 | $10,524,000 | $7,893,000 | 65.8% |

The 25k/50k operating margins are mechanically high because the staged payroll is held at $600k. A real MDR/SOC operation must add shifts, customer success, sales and regional/compliance staffing; use these rows as software-platform upside, not a staffing commitment. Conversely, moving analyst labor into COGS for a managed-service contract lowers reported gross margin.

At $15 pricing, the approximate lean break-even moves to ~2,746 agents; at $10 it moves to ~4,103 before infrastructure step changes. Large-volume discounting therefore requires contractual controls.

## 12. Customer-based model

Customer archetypes: small = 25 agents, medium = 100, large = 500, enterprise = 1,000. Actual portfolios will mix sizes.

| Agent target | All-small customers | All-medium | All-large | All-enterprise | MRR @ $20 | ARR @ $20 |
|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 40 | 10 | 2 | 1 | $20,000 | $240,000 |
| 5,000 | 200 | 50 | 10 | 5 | $100,000 | $1,200,000 |
| 10,000 | 400 | 100 | 20 | 10 | $200,000 | $2,400,000 |
| 25,000 | 1,000 | 250 | 50 | 25 | $500,000 | $6,000,000 |
| 50,000 | 2,000 | 500 | 100 | 50 | $1,000,000 | $12,000,000 |

A useful mixed 5,000-agent portfolio is 4 enterprise (4,000) + 5 medium (500) + 20 small (500) = 29 customers. Concentration risk is much higher than in an all-SMB portfolio, but sales/support efficiency is better.

## 13. Break-even

Using a representative 1,000–2,500-agent operating tier:

`Monthly fixed operating cost = $23,000 loaded payroll + $9,000 other OPEX + $6,500 shared APIs/TI + $1,500 infrastructure = $40,000`

`Contribution per agent = $20.00 revenue − $0.25 variable API/usage = $19.75`

`Break-even agents = $40,000 / $19.75 = 2,025.3 → 2,026 paid agents`

`Break-even MRR = 2,026 × $20 = $40,520`  
`Break-even ARR = $40,520 × 12 = $486,240`

Because infrastructure steps at 2,500 and sales/payroll do not remain perfectly fixed, use **2,200–2,500 paid agents** as the operating break-even target. With a base ramp of 100 agents at month 1, 1,000 at month 6, 2,500 at month 12, break-even is reached around **month 10–11**, but Year 1 remains cash-flow negative due to earlier losses. This timing is an **ASSUMPTION**, not a forecast based on signed pipeline.

## 14. Three-year outlook

These are end-of-year run-rate views; revenue shown is ARR at ending agents, while costs are annualized at the ending operating scale. Customer count assumes an average 100 agents/customer for comparability.

### Conservative

| Year | Paid agents | Customers | MRR | ARR | Infra | Payroll | Other OPEX incl APIs | Gross profit | Operating profit | Margin |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Y1 | 1,000 | 10 | $20k | $240k | $18k | $276k | $189k | $141k | -$243k | -101% |
| Y2 | 2,500 | 25 | $50k | $600k | $31k | $360k | $218k | $483k | -$9k | -2% |
| Y3 | 5,000 | 50 | $100k | $1.20M | $54k | $480k | $333k | $1.053M | $333k | 28% |

### Base

| Year | Paid agents | Customers | MRR | ARR | Infra | Payroll | Other OPEX incl APIs | Gross profit | Operating profit | Margin |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Y1 | 2,500 | 25 | $50k | $600k | $31k | $276k | $194k | $483k | $99k | 17% |
| Y2 | 7,500 | 75 | $150k | $1.80M | $78k | $540k | $330k | $1.62M | $852k | 47% |
| Y3 | 20,000 | 200 | $400k | $4.80M | $168k | $900k | $624k | $4.50M | $3.11M | 65% |

### Aggressive

| Year | Paid agents | Customers | MRR | ARR | Infra | Payroll | Other OPEX incl APIs | Gross profit | Operating profit | Margin |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Y1 | 5,000 | 50 | $100k | $1.20M | $54k | $360k | $273k | $1.053M | $513k | 43% |
| Y2 | 20,000 | 200 | $400k | $4.80M | $168k | $900k | $624k | $4.50M | $3.11M | 65% |
| Y3 | 50,000 | 500 | $1.00M | $12.0M | $408k | $1.80M | $1.23M | $11.36M | $8.56M | 71% |

The aggressive case requires validated capacity, materially larger sales and operations teams, and likely lower blended price. Margins should be recalculated with actual MDR scope, churn, discounts and payment fees. Base Year 1 ending ARR is not the same as collected Year-1 revenue during a ramp.

In these outlook tables, “Other OPEX incl APIs” contains the shared/variable API allowance plus sales, administration, compliance and contingency. Gross profit subtracts infrastructure and only the API portion of that column; operating profit subtracts infrastructure, payroll and the entire column exactly once.

## 15. Funding requirement and milestones

Starting from the $40,250 base monthly gross burn:

| Runway | Core burn | Reserve/headroom | Suggested raise | INR @ ₹88/$ |
|---|---:|---:|---:|---:|
| 12 months | $483,000 | ~15% | **$560,000** | **₹4.93 crore** |
| 18 months | $724,500 | ~15% plus scale rounding | **$850,000** | **₹7.48 crore** |
| 24 months | $966,000 | ~15% plus scale rounding | **$1,120,000** | **₹9.86 crore** |

Recommended practical seed target: **$750k–$850k (₹6.60–₹7.48 crore)** for 18 months, with hiring gates tied to revenue. Revenue collections extend runway; procurement delays, receivables and annual vendor prepayments shorten it.

If AJNAT raises $850k, milestones before the next round should be:

- 99.9% measured service availability; restore tests meeting approved RPO/RTO; reproducible agent releases and code signing.
- Telemetry benchmark through at least 10,000 test/reporting endpoints and documented capacity per API/worker/database tier.
- 15–30 paying companies and 2,500–5,000 paid agents, with less than 25% revenue concentration in one customer.
- $50k–$100k MRR / $600k–$1.2M ARR run rate, >75% gross margin on like-for-like SaaS COGS and positive contribution margin.
- Documented L1/L2/L3 process, case QA, escalation SLA and explicit hours of human coverage.
- Enterprise RBAC/tenant-isolation tests, immutable audit/evidence design, SSO/SCIM roadmap and DPA/security documentation.
- Independent penetration test with critical/high remediation; SOC 2 or ISO 27001 readiness and scoped certification plan.
- Signed commercial rights/quotations for VirusTotal/Google TI and every redistributed threat feed.
- Qualified pipeline of at least 3× next-12-month bookings target and measured CAC/payback/churn cohorts.

## 16. Use of funds

| Use | % | $ on $850k |
|---|---:|---:|
| Engineering/product/QA | 30% | $255,000 |
| Infrastructure/data/DR | 10% | $85,000 |
| SOC operations/detection content | 20% | $170,000 |
| Sales & marketing/customer success | 20% | $170,000 |
| Compliance/security/audits/insurance | 10% | $85,000 |
| Administration/legal/finance | 5% | $42,500 |
| Emergency reserve | 5% | $42,500 |
| **Total** | **100%** | **$850,000** |

## 17. Investor summary

| Item | USD | INR equivalent / comment |
|---|---:|---|
| Business model | $20 endpoint/month list | Multi-tenant SOC/EDR platform; MDR labor should be a separate tier |
| Target customer | 25–1,000+ endpoints/company | SMB through enterprise, preferably channel-led below 100 endpoints |
| Representative Year-1 gross cash requirement | $483,000 | ₹4.25 crore |
| Representative monthly burn | $40,250 | ₹35.42 lakh |
| Recommended 18-month raise | $750k–$850k | ₹6.60–₹7.48 crore |
| Break-even | ~2,026 agents / $40,520 MRR | ~₹35.66 lakh MRR; target 2,200–2,500 for safety |
| 2,500-agent run rate | $50,000 MRR / $600,000 ARR | ₹44 lakh MRR / ₹5.28 crore ARR |
| Gross margin at 2,500 | 80.6% | After infrastructure and shared/variable API allocation |
| Potential 2,500-agent annual net | ~$74,475 | ₹65.54 lakh; steady-state, illustrative 25% tax |
| Three-year base opportunity | 20k agents / $4.8M ARR | ₹42.24 crore ARR run rate |

Major cost drivers are SOC/engineering payroll, commercial threat-intelligence rights, telemetry retention/query architecture, enterprise compliance, customer onboarding and sales. The software can scale economically because there is no proven per-agent license embedded in the agent, but this advantage only holds if telemetry is bounded, expensive enrichment is cached/alert-triggered, raw logs/evidence are metered, and managed human coverage is priced separately.

Major risks are unmeasured endpoint event volume, breadth-versus-hardening, commercial-use restrictions for TI/data services, privileged IPS/firewall execution, multi-tenant isolation, 24×7 service expectations, long enterprise sales cycles, concentration, code-signing/release supply chain, and a production topology that is currently represented mainly through code/configuration rather than observed cloud bills and load-test evidence.

## 18. Required diligence before relying on this model

1. Run a 30-day pilot at 100/500/1,000 endpoint equivalents and record requests, compressed bytes, retained GB, Mongo/ClickHouse query load, Socket.IO concurrency and alert/enrichment rates.
2. Obtain written VirusTotal/Google TI, OTX, AbuseIPDB, IP/geolocation, Stytch, SMTP, Maps and cloud quotes plus commercial/redistribution rights.
3. Decide SaaS-only versus staffed MDR service hours; create separate COGS and price card for analyst coverage.
4. Approve log/evidence retention, RPO/RTO, data residency, support SLA, raw-log overage and archive retrieval fees.
5. Replace single-broker/dev assumptions with a costed HA bill of materials and complete restore/failover tests.
6. Validate salary, statutory benefits, GST/VAT/sales tax, corporate income tax, withholding and payment fees with local professionals.
7. Track actual CAC, activation, gross retention, net retention, DSO and support minutes per customer; replace all unit-economics assumptions quarterly.

## 19. Public pricing references consulted

- VirusTotal documents that the public API is limited to 4 requests/minute and 500/day and must not be used in commercial products; Premium is licensed by quota: https://docs.virustotal.com/reference/public-vs-premium-api
- Published Google Threat Intelligence package/API-slot reference used only as a planning anchor: https://assets.virustotal.com/google-ti-packages-pricing.pdf
- AbuseIPDB plan limits and pricing: https://www.abuseipdb.com/pricing
- Stytch pricing and included MAU/fingerprint/connection allowances: https://stytch.com/pricing
- IPinfo Lite current basic country/ASN allowance: https://support.ipinfo.io/hc/en-us/articles/30792535492626-What-Is-the-Usage-Limit-for-the-Free-Plan

Every external price remains subject to region, tax, usage, license rights and contract date. “$0” means no modeled cash fee under the stated allowance; it does not guarantee unrestricted commercial use.
