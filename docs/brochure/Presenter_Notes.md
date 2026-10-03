# AJNAT SOC — Presenter Notes

Slides use concise English. Notes below provide a short Hinglish speaking guide.

## 01. AJNAT SOC — Product overview

AJNAT SOC security team ko ek common workspace deta hai. Endpoint, network aur identity ke signals ko saath dekhkar analyst threat samajh sakta hai aur response coordinate kar sakta hai. Aage hum actual UI screens aur ek short incident example dekhenge. Screenshots mein sample data hai.

Visual: `company/src/pages/CorrelationPage.jsx`. Actual UI, sample data.

## 02. One workspace for the security team

SOC ka simple meaning hai security monitoring aur incident response ka central function. SIEM logs ko collect aur correlate karta hai. EDR endpoint ke andar ki activity dikhata hai. SOAR approved workflows se response coordinate karta hai. AJNAT in capabilities ko ek operational context mein laata hai.

## 03. From raw events to a clear next step

Pehle configured sources se events aate hain. Correlation related activity ko link karta hai. Analyst severity, timeline aur evidence review karke incident assess karta hai. Uske baad authorized response actions, approvals aur execution result case ke saath record hote hain. Har alert automatically confirmed attack nahi hota.

## 04. Start with operational priorities.

Yeh actual SOC Manager dashboard hai. Ismein assigned companies, IDS/IPS, firewall aur operational queues ka overview milta hai. Manager yahan se relevant module ya queue open kar sakta hai. Screen ke numbers sirf demonstration data hain; performance ya customer results nahi.

Visual: `company/src/pages/analyst/soc/RoleDashboardPage.jsx`. Actual UI, sample data.

## 05. Understand activity on the endpoint.

EDR page endpoint activity ko monitoring modules mein organize karta hai: process, file, network, authentication aur doosre security areas. Analyst required module open karke related telemetry inspect kar sakta hai. Coverage operating system, permissions, sensors aur configuration par depend karti hai. Shown counters are sample data; this is a cropped view of the existing monitoring-card grid.

Visual: `company/src/pages/EDRPage.jsx`. Actual UI, sample data.

## 06. Connect signals into an attack story.

Correlation page alag events ko ek possible attack chain ke andar dikhata hai. Sample case mein failed logins, PowerShell activity aur outbound connection FIN-WS-014 se linked hain. Analyst pattern, risk aur linked evidence check karta hai. Confidence score ek signal hai; final conclusion evidence review ke baad hota hai.

Visual: `company/src/pages/CorrelationPage.jsx`. Actual UI, sample data.

## 07. Read the evidence before taking action.

Investigation screen mein left side par events hain aur selected event ki detail right side par aati hai. Analyst host, user, process aur source/destination details ko inspect kar sakta hai. Timeline, correlated events, IOC intelligence, raw logs aur notes context dete hain. AI summaries jahan configured hon wahan assistance de sakti hain; analyst review zaroori hai.

Visual: `company/src/pages/ThreatInvestigationPage.jsx`. Actual UI, sample data.

## 08. Move from review to a managed response.

SOAR ka role response steps ko organize karna hai. Rules aur playbooks incident creation, assignment aur supported containment actions coordinate kar sakte hain. Pending approval queue sensitive actions par human control deti hai. Endpoint isolation ya blocking permissions, platform aur integrations par depend karta hai. Screen ke timings aur counts sample values hain, benchmarks nahi.

Visual: `company/src/pages/SoarPage.jsx`. Actual UI, sample data.

## 09. One endpoint. Three connected signals

Is example mein ek endpoint par teen signals milte hain: repeated failed logins, suspicious PowerShell execution aur unusual outbound connection. AJNAT in events ko link karne aur evidence inspect karne ka workflow deta hai. Analyst scope aur severity confirm karta hai, owner assign hota hai, phir supported response ko approve aur track kiya ja sakta hai. Yeh illustrative case hai; actual breach ya measured outcome nahi.

## 10. Clear ownership at every stage

SOC manager team priorities aur assignments manage karta hai. L1 initial triage karta hai; L2/L3 detailed investigation aur response coordination karte hain. L4 threat intelligence context par kaam karta hai. Company scope aur role permissions determine karte hain ki user kya dekh aur kar sakta hai. Case history, audit aur reports handover aur review ko support karte hain. Yeh compliance certification ka claim nahi hai.

## 11. Less switching. More connected context

Connected workflow ka benefit hai ki analyst ko assets, events, indicators aur response context ek jagah milta hai. Isse review aur handover structured ho sakte hain. Is slide mein operational benefits explain kiye gaye hain; time saving, detection rate ya ROI ke unverified percentage claims nahi diye gaye.

## 12. See AJNAT SOC in your environment

Next step ek focused pilot hai. Pehle critical assets, data sources aur user roles select karein. Phir ek realistic incident ko detection se investigation aur approved response tak walk through karein. Success criteria coverage, evidence quality, action support aur team handover ke around define karein. Deployment se pehle platform support, integrations aur agent permissions confirm karna hoga.
