"""Capture the repository's real React UI with browser-local sample API data.

No production backend, credentials, or product source edits are used.
All images are demonstration screenshots, not production telemetry.
"""
import asyncio
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).parent / 'assets'
OUT.mkdir(parents=True, exist_ok=True)
NOW = datetime(2026, 10, 3, 5, 0, tzinfo=timezone.utc)
def stamp(m=0): return (NOW-timedelta(minutes=m)).isoformat()
CO = {'_id':'demo-company', 'name':'AJNAT Demo Enterprise', 'status':'active'}
USER = {'_id':'demo-manager','name':'Demo SOC Manager','email':'analyst@example.com','role':'soc_manager','companyId':'demo-company'}
ALERTS = []
for i, (desc, cat, sev, mins) in enumerate([
    ('Suspicious PowerShell execution on FIN-WS-014','edr','critical',3),
    ('Outbound connection to threat-listed destination','network','high',4),
    ('Repeated failed logins for finance.user','system','high',6),
    ('New scheduled task created on FIN-WS-014','system','high',8),
    ('Unusual DNS query pattern observed','network','medium',12),
    ('Protected configuration file modified','file','medium',18),
]):
    ALERTS.append({'_id':f'demo-alert-{i}', 'description':desc, 'title':desc,'severity':sev,
        'eventCategory':cat,'createdAt':stamp(mins),'status':'investigating' if i<3 else 'open',
        'agentName':'FIN-WS-014','hostname':'FIN-WS-014','companyId':CO,
        'departmentId':{'name':'Finance'}, 'sourceType':'EDR' if cat!='network' else 'IDS',
        'sourceVendor':'AJNAT', 'srcip':'192.0.2.14','destip':'198.51.100.45',
        'processName':'powershell.exe' if i==0 else '', 'username':'finance.user',
        'riskScore':92-i*7,'confidenceScore':94-i*5,'assignedTo':{'name':'Demo Analyst'},
        'correlationId':'CORR-DEMO-014','sourceAlertCount':3,'iocMatched':i==1,
        'action':'detected','mitreTechnique':'T1059.001' if i==0 else '',
        'systemId':{'name':'FIN-WS-014','hostname':'FIN-WS-014'}})
CORR = [{'_id':'demo-chain-1','patternName':'Account compromise & suspicious execution',
    'description':'Repeated authentication failures, PowerShell activity and an outbound network connection are linked to the same endpoint.',
    'agentName':'FIN-WS-014','incidentId':'INC-DEMO-014','severity':'critical','status':'investigating',
    'confidence':94,'riskScore':92,'occurrenceCount':1,'patternId':'AUTH-EXEC-NET',
    'createdAt':stamp(8),'lastActivityAt':stamp(3),'windowStart':stamp(8),'windowEnd':stamp(3),
    'eventCount':3,'alertIds':ALERTS[:3], 'mitreTechniques':['T1110','T1059.001'],
    'mitreTactics':['Credential Access','Execution'], 'iocs':['198.51.100.45'],
    'timeline':[{'alertId':a['_id'],'timestamp':a['createdAt'],'category':a['eventCategory'],'description':a['description']} for a in ALERTS[:3]]
}]
CORRSTATS = {'eventsAnalyzed24h':12480,'active':1,'openCritical':1,'ruleCount':12,
    'edrCapabilityCoverage':18,'edrCapabilityTotal':31,'lastEventAt':stamp(3),
    'bySeverity':[{'_id':'critical','count':1}],'byPattern':[]}
PATHS = re.findall(r"to: '(/soc-manager/[^']+)'", (ROOT/'company/src/config/menuConfig.js').read_text())
SIDEBAR = dict(zip(dict.fromkeys(PATHS),[0,2,48,3,124,18,42,12,1,6,3,8,2,6,4,2,9,0,5,18,4,1]))
CAPNAMES = re.findall(r"  (\d+): '([^']+)'", (ROOT/'company/src/pages/EDRPage.jsx').read_text())[:31]
CAPS = [{'id':int(i),'name':n,'status':'implemented','description':n,
    'live':{'logs24h':[2480,630,124,96,80,42][(int(i)-1)%6], 'previous24h':320,
            'critical':1 if int(i)==1 else 0,'high':2,'medium':3,'low':8,
            'activeAgents':12,'lastEventAt':stamp(3)},'metrics':{'logs24h':124},
    'source':'AJNAT Agent','agentStatus':'active'} for i,n in CAPNAMES]
for cap in CAPS:
    cap['live'].update({'reportingAgents':12,'highCritical24h':3,'unauthorized24h':1,
        'lastSeenAt':stamp(3),'trendPct':8,
        'timeline24h':[{'hour':stamp((23-j)*60),'count':v} for j,v in enumerate([5,9,7,14,11,18,14,8,16,19,23,18,22,14,28,35,23,19,36,42,30,25,38,44])]})
CONNECTIONS=[{'_id':f'conn-{i}','systemId':'demo-system','hostname':'FIN-WS-014',
    'createdAt':stamp(i*7+2),'srcip':'192.0.2.14','destip':'198.51.100.45',
    'sourcePort':50000+i,'destPort':443,'protocol':'TCP','eventType':'connection_opened',
    'severity':'high' if i<3 else 'low','description':'Outbound connection observed'} for i in range(24)]
EXECUTIONS=[{'_id':f'ex-{i}','ruleName':n,'ruleId':{'name':n},'triggerType':'new_alert',
    'status':'completed','durationMs':m,'createdAt':stamp(i*4+2)}
    for i,(n,m) in enumerate([('Enrich suspicious destination',820),('Create critical incident',1240),('Assign Finance SOC analyst',650),('Record investigation context',930)])]
APPROVALS=[{'_id':'approval-1','status':'pending','requestedAction':'Isolate endpoint',
    'targetSummary':'FIN-WS-014 · Analyst review required','createdAt':stamp(1)}]
PLAYBOOKS=[{'_id':f'pb-{i}','name':n,'description':d,'enabled':True,'isBuiltIn':True,
    'executionMode':'approval_required','steps':[{'type':'action'}]*4} for i,(n,d) in enumerate([
    ('Endpoint containment','Review, approve, isolate a supported host and retain the outcome.'),
    ('Suspicious destination response','Enrich the indicator, review evidence and apply supported controls.'),
    ('Credential compromise triage','Link authentication evidence, assign an owner and track follow-up.')])]

def payload(path):
    return {
      '/auth/me':{'user':USER,'company':CO},
      '/soc-dashboard/notifications':{'items':[],'notifications':[],'unread':0,'unreadCount':0},
      '/soc-manager/dashboard':{'sidebarSummary':SIDEBAR,'refreshedAt':stamp(),
        'companySecurity':[{'companyId':'demo-company','companyName':CO['name'],'companyStatus':'active',
          'idsIpsEventsToday':124,'ipsActiveBlocks':18,'firewallEventsToday':42,'criticalAlertsToday':1}],
        'recentAlerts':ALERTS,'severity':{'critical':1,'high':3,'medium':2,'low':0},
        'recentAudit':[{'_id':'au1','action':'Incident assigned','targetType':'INC-DEMO-014','createdAt':stamp(2)}]},
      '/alerts':{'alerts':ALERTS,'total':len(ALERTS)},
      '/correlation':{'events':CORR,'total':1,'totalPages':1},
      '/correlation/stats':CORRSTATS,
      '/correlation/companies':[CO],
      '/system':[{'_id':'demo-system','name':'FIN-WS-014','hostname':'FIN-WS-014','status':'online','os':'Windows'}],
      '/soc-edr/incidents':{'incidents':[],'total':0},
      '/soc-edr/endpoint-risk':{'endpoints':[]},
      '/soc-edr/mitre-coverage':{'tactics':[],'techniques':[]},
      '/soc-edr/live-telemetry':{'alerts':ALERTS},
      '/edr-cap/status':{'capabilities':CAPS,'summary':{'implemented':31,'total':31}},
      '/edr-cap/live-overview':{'capabilities':CAPS,'liveSummary':{'reporting':18,'idle':13,'total':31}},
      '/edr-cap/new-services':{'services':[]},'/edr-cap/service-status':{},
      '/network/connections':{'connections':CONNECTIONS},'/network/alerts':{'alerts':[]},
      '/soar/dashboard/summary':{'totalRules':12,'activeRules':10,'totalExecutions':4,
        'successfulExecutions':4,'failedExecutions':0,'pendingApprovals':1,'incidentsCreated':1,
        'ticketsAssigned':1,'alertsAutoResolved':0,'avgAutomationTimeMs':910,'analystHoursSaved':0},
      '/soar/rules':[], '/soar/playbooks':PLAYBOOKS,
      '/soar/executions':{'executions':EXECUTIONS,'total':4},'/soar/approvals':APPROVALS,
      '/soar/connectors':[], '/soar/credentials':[], '/soar/templates':[],
      '/soar/audit-logs':{'logs':[],'total':0,'page':1},'/department':[],
    }.get(path, {})

async def main():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    pem=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    async with async_playwright() as p:
      browser=await p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox'])
      ctx=await browser.new_context(viewport={'width':1600,'height':1020},device_scale_factor=1.5,timezone_id='Asia/Kolkata')
      await ctx.add_init_script('localStorage.setItem("co_token","brochure-demo-only");localStorage.setItem("co_user",'+json.dumps(json.dumps(USER))+');localStorage.setItem("co_company",'+json.dumps(json.dumps(CO))+');')
      requested=set()
      async def handler(route):
        u=urlparse(route.request.url)
        if u.path.startswith('/api/'):
          path=u.path.split('/api',1)[1];requested.add(path)
          headers={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'*','Access-Control-Allow-Methods':'*'}
          if route.request.method=='OPTIONS': await route.fulfill(status=204,headers=headers);return
          if path=='/transport/public-key': await route.fulfill(body=pem,content_type='application/x-pem-file',headers=headers);return
          await route.fulfill(json=payload(path),headers=headers);return
        if u.hostname not in ('localhost','127.0.0.1'): await route.abort();return
        await route.continue_()
      await ctx.route('**/*',handler)
      page=await ctx.new_page()
      errors=[]
      page.on('pageerror',lambda e:errors.append(str(e)))
      manifest=[]
      if len(sys.argv)>1 and (OUT/'capture-manifest.json').exists():
        manifest=[item for item in json.loads((OUT/'capture-manifest.json').read_text()) if item['name'] not in sys.argv[1:]]
      targets=[('dashboard','/soc-manager/dashboard'),('correlation','/soc-manager/correlation'),
        ('investigation','/soc-manager/investigate'),('soar','/soc-manager/soar'),
        ('playbooks','/soc-manager/playbooks'),('edr','/edr')]
      for name,path in targets:
        if len(sys.argv)>1 and name not in sys.argv[1:]: continue
        await page.goto('http://127.0.0.1:3000'+path,wait_until='networkidle')
        await page.wait_for_timeout(1600)
        if name=='investigation':
          # Select evidence in the actual product UI; no response action is invoked.
          item=page.get_by_text(ALERTS[0]['description'],exact=True)
          if await item.count(): await item.first.click();await page.wait_for_timeout(250)
        await page.screenshot(path=str(OUT/f'{name}-full.png'),full_page=False)
        main=page.locator('main')
        box=await main.bounding_box() if await main.count() else None
        if box:
          clip={'x':box['x']+24,'y':box['y']+18,'width':min(box['width']-48,1320),'height':min(820,1020-box['y']-24)}
          await page.screenshot(path=str(OUT/f'{name}.png'),clip=clip)
        else:
          await page.screenshot(path=str(OUT/f'{name}.png'))
        text=await page.locator('body').inner_text()
        if len(text.strip()) < 100:
          raise RuntimeError(f'{name}: UI did not render; refusing to save a blank capture.')
        (OUT/f'{name}.txt').write_text(text)
        manifest.append({'name':name,'route':path,'image':f'{name}.png','source':'Repository React UI, browser-local sample API fixtures','errors':errors[:]})
        print(name, 'captured', 'errors=',errors, 'body=',text[:100].replace('\n',' '),flush=True)
        errors.clear()
      (OUT/'capture-manifest.json').write_text(json.dumps(manifest,indent=2))
      (OUT/'requests.json').write_text(json.dumps(sorted(requested),indent=2))
      await browser.close()

if __name__=='__main__': asyncio.run(main())
