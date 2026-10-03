(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const escape = (value) => String(value).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const scenarios = {
    ransomware: {
      label: 'Critical ransomware behavior', kind: 'Incident', owner: 'L3 Analyst', initials: 'L3', reviewer: 'SOC Manager', audit: 'Standard',
      summary: 'Critical signal → L3 investigation → endpoint response → manager review.',
      signal: 'Process, file and suspicious encryption activity were correlated.',
      route: 'Non-TI critical incidents require L3. In this demo, the SOC Manager assigns an eligible L3 analyst.',
      investigation: 'L3 verifies the process chain, affected files, persistence and impact; forensic evidence and RCA are recorded.',
      response: 'Supported isolation / quarantine', outcome: 'Resolved',
      finding: 'Containment and recovery evidence were verified in the demo; L3 submits the closure note.',
      note: 'Critical severity routes to L3 when no preceding network-ticket or TI exception applies.'
    },
    login: {
      label: 'Medium suspicious login', kind: 'Incident', owner: 'L1 Analyst', initials: 'L1', reviewer: 'L2 Analyst', audit: 'Standard',
      summary: 'Medium signal → L1 triage → expected activity confirmed → L2 review.',
      signal: 'Authentication telemetry produced a medium-severity suspicious-login signal.',
      route: 'Non-TI low / medium work goes to L1. This example shows a correlated incident and a false-positive outcome.',
      investigation: 'L1 validates the user, device, source and timestamp. This demo confirms the activity was authorized.',
      response: null, outcome: 'False positive',
      finding: 'Supporting evidence for the expected login and the false-positive reason were recorded in the case.',
      note: 'If suspicion remains unresolved, L1 escalates to L2 with a reason, IOCs and asset context.'
    },
    intel: {
      label: 'Malicious domain / Threat Intelligence', kind: 'Incident', owner: 'L4 Analyst', initials: 'L4', reviewer: 'SOC Manager', audit: 'Threat',
      summary: 'IOC match → L4 intelligence analysis → authorized block → threat audit.',
      signal: 'Correlated TI evidence linked a malicious-domain IOC to an actual endpoint connection.',
      route: 'TI-classified incidents go to active assigned L4 analysts. Without an eligible L4, assignment may remain unresolved.',
      investigation: 'L4 verifies IOC source, confidence, freshness and the actual endpoint / network relationship.',
      response: 'Supported domain block', outcome: 'Resolved',
      finding: 'L4 closes the TI incident with indicator context and confirmed response results.',
      note: 'L4 follows a specialist path. The standard escalation mapping has no next level for L4.'
    },
    network: {
      label: 'IDS / IPS / Firewall SOAR ticket', kind: 'Ticket', owner: 'L4 Analyst', initials: 'L4', reviewer: null, audit: null,
      summary: 'Network-source alert → exclusive SOAR ticket → manager / L4 routing.',
      signal: 'A SOAR create_ticket condition matched an IDS / IPS / Firewall source alert.',
      route: 'A matching network SOAR source makes SOC Manager or L4 eligible before severity fallback. This demo selects an eligible L4.',
      investigation: 'The assigned L4 reviews source evidence, the rule and affected network activity, then coordinates response with the manager.',
      response: 'Supported network block', outcome: 'Resolved',
      finding: 'The ticket was closed with response evidence and its audit history was recorded.',
      note: 'Shared network ticket visibility does not grant edit ownership. Normal ticket closure does not create an incident review object.'
    }
  };

  const roles = [
    {id:'partner', name:'Partner Admin', code:'partner_admin', initials:'PA', section:4,
      intro:'Owns the partner’s companies and commercial operations.', scope:'Companies linked to the partner; no automatic access to unrelated partners / companies.',
      tasks:['Coordinates company registration invitations, plan / payment status and license readiness.','Manages scoped SOC Manager and L1–L4 invitations / assignments.','Can use assets, SOAR connectors and approval actions allowed by company-admin gates within valid company context.'],
      limit:'Excluded from Encryption Center and dedicated forensic hunt launch permissions. Commercial hierarchy does not confer inherited technical permissions.'},
    {id:'company', name:'Company Admin', code:'company_admin', initials:'CA', section:5,
      intro:'Keeps the company operationally ready and owns the business side of the security service.', scope:'Own company, departments, assets and authorized users.',
      tasks:['Manages departments, asset inventory, agent package / config and company settings.','Invites L1–L4 through the SOC flow; performs permitted staff / shift management.','Uses company-scope SOAR rules, connectors, credentials and approvals; reviews business impact and recovery.'],
      limit:'Encryption key management / decryption approval are not allowed. The dedicated SOC incident-action route differs from other EDR management APIs.'},
    {id:'department', name:'Department Admin', code:'department_admin', initials:'DA', section:5,
      intro:'Coordinates operations for the assigned department’s assets and security issues.', scope:'Assigned department within the company, on department-aware routes.',
      tasks:['Reviews department incidents, tickets, assets, users and reports.','Can use scoped isolation, network policy and SOAR rule / playbook actions allowed by manager gates.','Can launch dedicated forensic hunts and use scoped custom correlation rules.'],
      limit:'Company-wide user / asset CRUD, agent packages, SOC staff / shift management, SOAR approval, connector credentials and Encryption Center are not allowed.'},
    {id:'manager', name:'SOC Manager', code:'soc_manager', initials:'SM', section:6,
      intro:'Owns SOC coverage, analyst ownership, response decisions and case quality.', scope:'Active assigned companies; staff management and company / department resource checks apply.',
      tasks:['Coordinates L1–L4 staff, shifts, unassigned queues and workload.','Handles permitted response approvals, policies, forensics, correlation and Encryption Center administration.','Performs standard audits of L3 closures and threat audits of L4 closures; prepares reports and handovers.'],
      limit:'Cannot invite another SOC Manager through the SOC invitation flow. Excluded from company-admin gates for agent packages and SOAR connector / vault management.'},
    {id:'l1', name:'L1 Analyst', code:'l1_analyst', initials:'L1', section:7,
      intro:'Performs initial triage: validates low / medium actionable cases and defines the next step.', scope:'Assigned companies, applicable departments and personally assigned / eligible claimed cases.',
      tasks:['Acknowledges cases and validates source, rule, asset, timestamp and raw evidence.','Adds notes, investigates, resolves or marks owned cases as false positives.','Escalates unresolved cases to L2; own incident closures enter the L2 standard audit.'],
      limit:'New forensic hunts, Encryption Center, general SOAR administration / approval and network policy writes are not allowed.'},
    {id:'l2', name:'L2 Analyst', code:'l2_analyst', initials:'L2', section:7,
      intro:'Assesses timelines, evidence and impact for high-severity investigations and L1 escalations.', scope:'Assigned company / department scope and eligible owned cases; L2 and lower-tier route gates.',
      tasks:['Correlates process, file, network and auth evidence; launches dedicated forensic collection.','Audits L1 closures; own incident closures go to L3 review. Escalates complex issues to L3.','Views encrypted records / requests decryption; actual decryption requires an approved request and fresh MFA.'],
      limit:'Encryption, key management, crypto approval and SOAR approval are not allowed. Success from the L2 run-playbook handler does not prove real endpoint dispatch.'},
    {id:'l3', name:'L3 Analyst', code:'l3_analyst', initials:'L3', section:8,
      intro:'Leads technical work on critical incidents, advanced investigation, hunting and root-cause analysis.', scope:'Assigned companies / departments and owned cases, including L2 escalations.',
      tasks:['Performs RCA using persistence, lateral movement, impact and recovery evidence.','Uses dedicated forensic hunts, correlation rules / overrides / manual runs and permitted encryption operations.','Reviews L2 closures; own incidents enter manager standard audit. Escalates unresolved issues to the SOC Manager.'],
      limit:'General SOAR rule administration and SOAR approval are not allowed. The L3 playbook / detection-draft route does not automatically create active production rules.'},
    {id:'l4', name:'L4 · Threat Intelligence', code:'l4_analyst', initials:'L4', section:8,
      intro:'Specializes in Threat Intelligence incidents and malicious / suspicious indicators.', scope:'Assigned TI cases; shared IDS / IPS / Firewall ticket visibility within permitted scope.',
      tasks:['Verifies IOC source, freshness, confidence and endpoint relationships.','Investigates / closes owned TI incidents; the SOC Manager performs the threat audit review.','Uses dedicated forensic hunts and permitted encryption operations; coordinates network response with a manager / authorized admin.'],
      limit:'General SOC alerts list is blocked. No standard next-level escalation mapping. Shared read access does not grant edit ownership; network policy writes / SOAR approval are not allowed.'},
    {id:'legacy', name:'Legacy Analyst', code:'analyst', initials:'LA', section:8,
      intro:'Older general company monitoring role, separate from dedicated SOC tiers.', scope:'General company read scope; department / assignment filters on selected routes.',
      tasks:['Can use permitted generic monitoring / read endpoints.','Reviews general company monitoring context.','Tiered SOC work requires an explicit L1 / L2 / L3 / L4 role and assignments.'],
      limit:'Despite frontend L1 mapping, dedicated SOC dashboard and L1–L3 role gates do not accept legacy Analysts. Do not grant this role access equivalent to L1.'}
  ];

  let current = 0;
  let scenarioKey = 'ransomware';
  let running = !reducedMotion;
  let timer = null;
  let activePanel = 'workflow';
  const totalSteps = 12;
  const scenario = () => scenarios[scenarioKey];

  function stages() {
    const s = scenario();
    return [
      {title:'Company setup', owner:'Company Admin', initials:'CA', section:10, description:'Prepare the organization for monitoring.', action:'Company, department, subscription and asset records are configured.', output:'Valid company context and endpoint entitlements.', note:'The partner plan and company subscription / agent entitlement are separate checks.'},
      {title:'Team & scope', owner:'SOC Manager', initials:'SM', section:11, description:'The right analyst, company and shift.', action:'An authorized admin / manager sets roles, company assignments, optional departments and shifts.', output:'Scoped SOC team and monitoring coverage.', note:'Without department mappings, assigned-company scope may remain; a blank department does not mean zero access.'},
      {title:'Agent connects', owner:'Admin + operator', initials:'EP', section:12, description:'The endpoint agent is installed and authenticated.', action:'An authorized agent package is installed; endpoint identity, heartbeat and supported sensors are verified.', output:'Demo endpoint DEMO-PC-07 connected.', note:'A heartbeat does not prove that every sensor or security control is working.'},
      {title:'Telemetry flows', owner:'Agent / integrations', initials:'EV', section:12, description:'Events reach the backend from configured sources.', action:'After scope and subscription checks, process, file, network and auth events are normalized / stored.', output:'Normalized events and source evidence.', note:'Kafka, ClickHouse, Redis and external integrations depend on deployment configuration.'},
      {title:'Detection', owner:'Detection services', initials:'DT', section:15, description:'Security-relevant signals gain context.', action:s.signal, output:'Actionable alert + correlated evidence.', note:'Not every event is an attack. TI / AI output requires a configured and available service.'},
      {title:s.kind+' created', owner:'Case / SOAR service', initials:'CS', section:15, description:'Link evidence to a clearly defined work item.', action:s.kind==='Ticket'?'SOAR create_ticket checks the exclusive claim; the matching alert enters the manager queue.':'This demo creates a correlation-linked incident; case ownership of linked alerts is validated.', output:s.kind+' opened; analyst assignment pending.', note:'Tickets and incidents are alternative case paths. Not every alert becomes a ticket followed by an incident.'},
      {title:'Analyst assigned', owner:s.owner, initials:s.initials, section:16, description:'Scope and routing determine an eligible owner.', action:s.route, output:'Demo owner: '+s.owner+'.', note:s.kind==='Ticket'?'SOAR ticket routing prefers eligible on-shift users, then category / total load. Without an eligible user, the ticket remains unassigned in the manager queue.':'An eligible owner is available in this demo. Not every new EDR incident is automatically assigned immediately.'},
      {title:'Investigation', owner:s.owner, initials:s.initials, section:17, description:'Turn evidence into findings and next actions.', action:s.investigation, output:s.response?'Impact, supporting evidence and response recommendation.':'Authorized activity confirmed; false-positive evidence ready.', note:s.note},
      {title:s.response?'Response decision':'Decision recorded', owner:s.response?'SOC Manager':s.owner, initials:s.response?'SM':s.initials, section:20, description:s.response?'Check the mode and authority for the supported action.':'Expected activity does not require containment.', action:s.response?'Demo approval_required path: the SOC Manager approves '+s.response.toLowerCase()+'; the execution record is ready for dispatch.':'L1 records the reason and evidence for the expected login; endpoint response is skipped.', output:s.response?'Approved response → queued dispatch.':'No endpoint action requested.', note:'SOAR automatic mode can skip a human pause. Approval behavior depends on the selected mode / execution path.'},
      {title:s.response?'Endpoint result':'Evidence verified', owner:s.response?'Agent + response':s.owner, initials:s.response?'EP':s.initials, section:20, description:s.response?'Verify endpoint results after command acceptance.':'Check findings and supporting facts before closure.', action:s.response?'Demo response queued → sent → acknowledged → executing → successful. Endpoint confirmation and enforcement evidence are recorded.':'Supporting facts confirm expected activity. The dispatch / containment lifecycle does not apply to this branch.', output:s.response?'Simulated endpoint success + execution evidence.':'False-positive finding supported by evidence.', note:'This is a successful demo branch. Real execution can also fail, partially succeed or time out.'},
      {title:s.kind==='Ticket'?'Ticket closure':'Closure & review', owner:s.owner, initials:s.initials, section:18, description:s.kind==='Ticket'?'Close the ticket with its outcome and response history.':'The incident closes first; its review is then pending.', action:s.finding, output:s.kind==='Ticket'?'Resolved ticket + audit history.':s.outcome+' incident; '+s.audit.toLowerCase()+' review by '+s.reviewer+' pending.', note:s.kind==='Ticket'?'Plain ticket closure does not automatically create a higher-role incident audit object.':'If the reviewer requests changes, the incident returns to investigating and is reassigned to the original submitter.'},
      {title:'Report & improve', owner:s.reviewer||'SOC Manager', initials:s.reviewer==='L2 Analyst'?'L2':'SM', section:21, description:'Review, hand over and improve the next cycle.', action:s.kind==='Ticket'?'Ticket history, workload and response outcomes are included in the shift handover / report.':'The demo reviewer approves the evidence and closure decision; findings and follow-up are recorded in the report / handover.', output:s.kind==='Ticket'?'Completed ticket trail; no incident closure review.':'Approved '+s.audit.toLowerCase()+' review + handover context.', note:'Reports and outcomes are simulated; production SLAs, response times and real staff status are not shown.'}
    ];
  }

  const coordinates = Array.from({length:totalSteps}, (_, i) => {
    const row = Math.floor(i / 4);
    const column = row % 2 ? 3 - i % 4 : i % 4;
    return {x:25 + column * 207, y:43 + row * 137};
  });

  function buildMap() {
    const defs = '<defs>'+[['base','#4e6972'],['done','#81c4ae'],['active','#efa180']].map(([name,color]) => `<marker id="arrow-${name}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M 0 1 L 9 5 L 0 9" fill="none" stroke="${color}" stroke-width="1.5"/></marker>`).join('')+'</defs>';
    const edges = coordinates.slice(1).map((point, i) => {
      const previous = coordinates[i];
      const sameRow = previous.y === point.y;
      const forward = point.x > previous.x;
      const path = sameRow ? `M ${previous.x+(forward?180:-2)} ${previous.y+43} H ${point.x+(forward?-5:183)}` : `M ${previous.x+89} ${previous.y+88} V ${point.y-6}`;
      return `<path id="edge-${i}" class="flow-edge" d="${path}" marker-end="url(#arrow-base)"/>`;
    }).join('');
    const captions = ['01 / SET UP & CONNECT','02 / DETECT & INVESTIGATE','03 / RESPOND & IMPROVE'].map((t,i)=>`<text class="flow-caption" x="25" y="${24+i*137}">${t}</text>`).join('');
    const nodes = coordinates.map((p,i)=>`<g class="flow-node" id="node-${i}" data-step="${i}" tabindex="0" role="button" transform="translate(${p.x} ${p.y})"><title></title><rect class="node-bg" width="178" height="86" rx="10"/><rect class="node-number-bg" x="12" y="12" width="25" height="22" rx="6"/><text class="node-number" x="24.5" y="27" text-anchor="middle">${String(i+1).padStart(2,'0')}</text><text class="node-status" x="46" y="27"></text><circle class="node-pulse" cx="160" cy="22" r="3" style="display:none"/><text class="node-title" x="12" y="52"></text><text class="node-owner" x="12" y="71"></text></g>`).join('');
    $('workflow-map').innerHTML=defs+captions+edges+nodes;
    $('workflow-map').addEventListener('click', (event)=>{
      const node=event.target.closest('[data-step]');
      if(node) jumpTo(Number(node.dataset.step));
    });
    $('workflow-map').addEventListener('keydown', (event)=>{
      const node=event.target.closest('[data-step]');
      if(node && (event.key==='Enter'||event.key===' ')){event.preventDefault();jumpTo(Number(node.dataset.step));}
    });
  }

  function render() {
    const all = stages();
    const selected = all[current];
    const s = scenario();
    all.forEach((step,i)=>{
      const node=$('node-'+i);
      node.setAttribute('class','flow-node '+(i===current?'active':i<current?'done':''));
      node.setAttribute('aria-label',`Step ${i+1}: ${step.title}, ${step.owner}${i===current?', current step':''}`);
      if(i===current) node.setAttribute('aria-current','step'); else node.removeAttribute('aria-current');
      node.querySelector('title').textContent=step.title+' — '+step.owner;
      node.querySelector('.node-title').textContent=step.title;
      node.querySelector('.node-owner').textContent=step.owner;
      node.querySelector('.node-number').textContent=i<current?'✓':String(i+1).padStart(2,'0');
      node.querySelector('.node-status').textContent=i===current?'IN FOCUS':i<current?'COMPLETED':'UP NEXT';
      node.querySelector('.node-pulse').style.display=i===current?'':'none';
      if(i<11){
        const status=i===current-1?'active':i<current?'done':'';
        $('edge-'+i).setAttribute('class','flow-edge '+status);
        $('edge-'+i).setAttribute('marker-end','url(#arrow-'+(status||'base')+')');
      }
    });
    $('scenario-summary').textContent=s.summary;
    $('stage-counter').textContent=`STEP ${String(current+1).padStart(2,'0')} / 12`;
    $('map-owner').textContent=selected.owner;
    $('detail-number').textContent=String(current+1).padStart(2,'0');
    for(const [id,key] of [['detail-title','title'],['detail-description','description'],['detail-owner','owner'],['detail-action','action'],['detail-output','output'],['detail-note','note']]) $(id).textContent=selected[key];
    $('owner-avatar').textContent=selected.initials;
    $('step-reference').href='#guide-'+selected.section;
    $('step-reference').textContent='Read section '+String(selected.section).padStart(2,'0')+' ↗';
    $('progress-fill').style.width=((current+1)/totalSteps*100)+'%';
    document.querySelector('.playback-progress').setAttribute('aria-valuenow',current+1);
    document.querySelector('.map-card').classList.toggle('paused',!running);
    $('play-toggle').textContent=running?'Ⅱ Pause':current===11?'↺ Replay':'▶ Play';
    $('play-toggle').setAttribute('aria-label',running?'Pause demo':current===11?'Replay demo':'Play demo');
    $('playback-state').innerHTML='<span class="tiny-dot"></span>'+ (running?'Running':current===11?'Complete':'Paused');
    $('previous').disabled=current===0;
    $('next').disabled=current===11;
    $('case-kind').textContent=s.kind.toUpperCase();
    $('case-owner').textContent=current<6?'Awaiting assignment':s.owner;
    $('case-status').textContent=current<5?'Not created':current<6?'Open / unassigned':current<7?'Assigned':current<10?'Investigating':s.outcome;
    $('case-response').textContent=current<8?'Not requested':!s.response?'Not required':current===8?'Approved / queued':'Successful (demo)';
    $('case-review').textContent=s.kind==='Ticket'?'Not applicable · ticket':current<10?'Not submitted':current===10?'Pending · '+s.reviewer:'Approved · '+s.reviewer;
    $('routing-reason').textContent=s.route;
    $('event-stream').innerHTML=all.slice(0,current+1).reverse().map((step,offset)=>{
      const index=current-offset;
      return `<li><span class="event-dot"></span><span class="event-copy"><strong>${escape(step.title)}</strong>${escape(step.output)}</span><span class="event-time">STEP ${String(index+1).padStart(2,'0')}</span></li>`;
    }).join('');
    const diagram=document.querySelector('.diagram-scroll');
    const isScrollable=diagram.scrollWidth>diagram.clientWidth;
    document.querySelector('.map-hint').textContent=isScrollable?'Swipe ↔ or click a step to explore':'Click a step to explore ↗';
    if(isScrollable&&activePanel==='workflow'){
      const nodeRect=$('node-'+current).getBoundingClientRect();
      const containerRect=diagram.getBoundingClientRect();
      diagram.scrollLeft+=nodeRect.left-containerRect.left+(nodeRect.width-diagram.clientWidth)/2;
    }
  }

  function schedule() {
    clearTimeout(timer);
    timer=null;
    if(!running||activePanel!=='workflow'||document.hidden) return;
    timer=setTimeout(()=>{
      if(current<11) current++;
      else if($('loop').checked) current=0;
      else running=false;
      if(current===11&&!$('loop').checked) running=false;
      render();schedule();
    },3200/Number($('speed').value));
  }

  function jumpTo(index) {
    current=Math.max(0,Math.min(totalSteps-1,index));
    running=false;
    render();schedule();
  }

  function showRole(id) {
    const role=roles.find((item)=>item.id===id)||roles[3];
    document.querySelectorAll('.role-button').forEach((button)=>{
      const selected=button.dataset.role===role.id;
      button.classList.toggle('selected',selected);
      button.setAttribute('aria-pressed',selected);
    });
    $('role-detail').innerHTML=`<p class="eyebrow">ROLE SPOTLIGHT</p><h2>${escape(role.name)}</h2><code class="role-code">${role.code}</code><p class="role-intro">${escape(role.intro)}</p><div class="role-scope"><span class="eyebrow">DATA SCOPE</span><p>${escape(role.scope)}</p></div><h3>Daily responsibility</h3><ul>${role.tasks.map((task)=>'<li>'+escape(task)+'</li>').join('')}</ul><div class="detail-note"><strong>Access boundary</strong><br>${escape(role.limit)}</div><a href="#guide-${role.section}" class="text-link">Read full role workflow ↗</a>`;
  }

  function filterGuide() {
    const query=$('guide-search').value.trim().toLocaleLowerCase();
    const words=query.split(/\s+/).filter(Boolean);
    let count=0;
    document.querySelectorAll('.guide-section').forEach((section)=>{
      const match=words.every((word)=>section.textContent.toLocaleLowerCase().includes(word));
      section.hidden=!match;
      document.querySelector(`[data-guide="${section.id.slice(6)}"]`).hidden=!match;
      if(match) count++;
    });
    document.querySelector('.guide-intro').hidden=Boolean(query);
    $('search-empty').hidden=count>0;
    $('search-count').textContent=query?`${count} / 24 sections`:'24 sections';
  }

  function navigate() {
    const hash=location.hash.slice(1);
    const guideMatch=/^guide-(\d+)$/.exec(hash);
    activePanel=hash==='roles'?'roles':hash==='guide'||guideMatch?'guide':'workflow';
    for(const name of ['workflow','roles','guide']) $('panel-'+name).hidden=name!==activePanel;
    document.querySelectorAll('[data-panel]').forEach((link)=>{
      const selected=link.dataset.panel===activePanel;
      link.classList.toggle('active',selected);
      if(selected) link.setAttribute('aria-current','page'); else link.removeAttribute('aria-current');
    });
    $('breadcrumb').textContent={workflow:'Workflow demo',roles:'Roles & access',guide:'Complete guide'}[activePanel];
    if(activePanel!=='workflow'){running=false;render();}
    document.querySelectorAll('[data-guide]').forEach((link)=>link.classList.toggle('selected',guideMatch&&link.dataset.guide===guideMatch[1]));
    if(guideMatch){
      $('guide-search').value='';filterGuide();
      requestAnimationFrame(()=>{
        const target=$('guide-'+guideMatch[1]);
        if(target){target.focus({preventScroll:true});target.scrollIntoView({behavior:'instant',block:'start'});}
      });
    } else window.scrollTo({top:0,behavior:'instant'});
    schedule();
  }

  buildMap();
  $('role-list').innerHTML=roles.map((role)=>`<button class="role-button" type="button" data-role="${role.id}" aria-pressed="false"><span>${role.initials}</span><strong>${escape(role.name)}</strong><span class="role-chevron">↗</span></button>`).join('');
  $('role-list').addEventListener('click',(event)=>{const button=event.target.closest('[data-role]');if(button) showRole(button.dataset.role);});
  showRole('manager');
  $('scenario').addEventListener('change',()=>{
    scenarioKey=Object.hasOwn(scenarios,$('scenario').value)?$('scenario').value:'ransomware';
    current=0;running=!reducedMotion;render();schedule();
  });
  $('play-toggle').addEventListener('click',()=>{
    if(!running&&current===11) current=0;
    running=!running;render();schedule();
  });
  $('previous').addEventListener('click',()=>jumpTo(current-1));
  $('next').addEventListener('click',()=>jumpTo(current+1));
  $('restart').addEventListener('click',()=>{current=0;render();schedule();});
  $('speed').addEventListener('change',schedule);
  $('loop').addEventListener('change',schedule);
  $('guide-search').addEventListener('input',filterGuide);
  $('print-guide').addEventListener('click',()=>window.print());
  window.addEventListener('hashchange',navigate);
  document.addEventListener('visibilitychange',schedule);
  // Reopening the current source link should still work after a guide search hides it.
  document.addEventListener('click',(event)=>{
    const link=event.target.closest('a[href^="#"]');
    if(link&&link.getAttribute('href')===location.hash){event.preventDefault();navigate();}
  });
  render();navigate();
})();
