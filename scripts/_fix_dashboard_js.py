#!/usr/bin/env python3
"""Replace the JS section in dashboard.py with a fully fixed version."""
import re

NEW_JS = r"""<script>
const esc=s=>(s||'').toString().replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const $=id=>document.getElementById(id);
const scoreColor=v=>v>=80?'#ef4444':v>=60?'#f97316':v>=40?'#eab308':'#22c55e';
const priClass=p=>({P1:'b-p1',P2:'b-p2',P3:'b-p3',P4:'b-p4'}[p]||'b-p4');
const sevClass=s=>({critical:'b-critical',high:'b-high',medium:'b-medium',low:'b-low',info:'b-info'}[s]||'b-info');
const fmt=n=>typeof n==='number'?n.toLocaleString():n||'-';
const pct=n=>n!=null&&n!==''?`${(n*100).toFixed(1)}%`:'-';
const gridColor='rgba(255,255,255,.05)';
const cardCfg={plugins:{legend:{display:false}},maintainAspectRatio:false};
let apInited=false;
let HAS_CHART=false;

// Auth helpers
const API_TOKEN=localStorage.getItem('token')||'';
function apiHeaders(extra){
  const h=Object.assign({'Content-Type':'application/json'},extra||{});
  if(API_TOKEN)h['Authorization']='Bearer '+API_TOKEN;
  return h;
}
function apiFetch(url,opts){
  opts=opts||{};
  opts.headers=apiHeaders(opts.headers);
  return fetch(url,opts).then(function(r){
    if(r.status===401){localStorage.removeItem('token');window.location.href='/';return{};}
    return r.json();
  });
}
function updateControlStatus(msg,type){
  var el=$('control-status');if(!el)return;
  var colors={ok:'background:rgba(34,197,94,.15);color:#86efac;border:1px solid rgba(34,197,94,.3)',err:'background:rgba(239,68,68,.15);color:#fca5a5;border:1px solid rgba(239,68,68,.3)',info:'background:rgba(59,130,246,.15);color:#93c5fd;border:1px solid rgba(59,130,246,.3)',warn:'background:rgba(234,179,8,.15);color:#fde047;border:1px solid rgba(234,179,8,.3)'};
  el.innerHTML='<div style="padding:10px 16px;border-radius:8px;font-size:13px;'+(colors[type]||colors.info)+'">'+esc(msg)+'</div>';
}

// Tab switching
document.querySelectorAll('.tab-btn').forEach(function(btn){
  btn.addEventListener('click',function(){
    document.querySelectorAll('.tab-btn').forEach(function(b){b.classList.remove('active');});
    document.querySelectorAll('.page').forEach(function(p){p.classList.remove('active');});
    btn.classList.add('active');
    var page='page-'+btn.dataset.page;
    var pg=$(page);if(pg)pg.classList.add('active');
    if(btn.dataset.page==='attackpaths'&&!apInited){initD3();apInited=true;}
    if(btn.dataset.page==='control'){loadAppStatus();connectWebSocket();loadScannerJobs();}
  });
});

function animateCount(el,target){
  if(!el)return;
  var dur=1400,start=performance.now();
  var isFloat=String(target).includes('.');
  function tick(now){
    var p=Math.min((now-start)/dur,1);
    var ease=1-Math.pow(1-p,3);
    var val=ease*target;
    el.textContent=isFloat?val.toFixed(1):Math.round(val).toLocaleString();
    if(p<1)requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

// ─── Header ───
(function buildHeader(){
  try{
    var S=DASH.summary;var meta=$('run-meta');if(!meta)return;
    var pills=['<span class="meta-pill">'+esc(S.run_date.substring(0,16))+'</span>'];
    S.products.forEach(function(p){pills.push('<span class="meta-pill">'+esc(p)+'</span>');});
    if(S.p1>0)pills.push('<span class="meta-pill warning">P1: '+S.p1+'</span>');
    meta.innerHTML=pills.join('');
    var tc=$('tc-findings');if(tc)tc.textContent=S.final_findings;
    var tq=$('tc-quarantine');if(tq)tq.textContent=S.quarantined;
  }catch(e){console.error('buildHeader:',e);}
})();

// ─── Brief ───
(function buildBrief(){
  try{
    var brief=DASH.executive_brief;
    if(!brief){var bs=$('brief-section');if(bs)bs.style.display='none';return;}
    var bs2=$('brief-section');
    if(bs2)bs2.innerHTML='<div class="brief-card"><div class="brief-icon">&#x1f916;</div><div><div class="brief-label">AI Executive Brief</div><div class="brief-text">'+esc(brief)+'</div></div></div>';
  }catch(e){console.error('buildBrief:',e);}
})();

// ─── KPIs ───
(function buildKPIs(){
  try{
    var S=DASH.summary;
    var noiseRm=S.raw_findings>0?((S.raw_findings-S.final_findings)/S.raw_findings*100).toFixed(1):0;
    var cards=[
      {v:S.raw_findings,l:'Raw findings',sub:'before any processing',cls:'blue',icon:'&#x1f4e5;'},
      {v:S.unique_findings,l:'After dedup',sub:S.dedup_pct+'% duplicates removed',cls:'cyan',icon:'&#x1f500;'},
      {v:S.quarantined,l:'Quarantined',sub:'FP / accepted risk',cls:'',icon:'&#x1f6ab;'},
      {v:S.final_findings,l:'Active findings',sub:'prioritised & scored',cls:'warn',icon:'&#x1f3af;'},
      {v:S.p1+S.p2,l:'P1 + P2 urgent',sub:S.p1+' critical · '+S.p2+' high',cls:'danger',icon:'&#x1f6a8;'},
      {v:S.avg_score,l:'Avg risk score',sub:'top score: '+S.top_score,cls:'',icon:'&#x1f4ca;'},
      {v:noiseRm+'%',l:'Noise removed',sub:'raw to final reduction',cls:'success',icon:'&#x1f4c9;'}
    ];
    var grid=$('kpi-grid');if(!grid)return;
    grid.innerHTML=cards.map(function(c,i){
      return '<div class="kpi '+c.cls+'"><span class="kpi-accent">'+c.icon+'</span><div class="kpi-value" id="kv-'+i+'">'+(typeof c.v==='number'?'0':c.v)+'</div><div class="kpi-label">'+c.l+'</div><div class="kpi-sub">'+c.sub+'</div></div>';
    }).join('');
    cards.forEach(function(c,i){if(typeof c.v==='number')animateCount($('kv-'+i),c.v);});
  }catch(e){console.error('buildKPIs:',e);}
})();

// ─── Charts (wait for Chart.js to load) ───
function initCharts(){
  if(typeof Chart==='undefined')return;
  HAS_CHART=true;
  Chart.defaults.color='#94a3b8';
  Chart.defaults.font.family="'Inter',system-ui,sans-serif";
  Chart.defaults.font.size=11;
  try{
    var S=DASH.summary,F=DASH.findings,H=DASH.history;

    // Priority donut
    var priEl=$('c-priority');
    if(priEl){
      new Chart(priEl,{type:'doughnut',data:{labels:['P1 Critical (90+)','P2 High (70-89)','P3 Medium (40-69)','P4 Low (<40)'],datasets:[{data:[S.p1,S.p2,S.p3,S.p4],backgroundColor:['#ef4444','#f97316','#eab308','#64748b'],borderWidth:0,hoverOffset:6,borderRadius:4}]},options:{...cardCfg,cutout:'68%',plugins:{legend:{display:true,position:'bottom',labels:{color:'#94a3b8',boxWidth:10,boxHeight:10,padding:12}},tooltip:{callbacks:{label:function(ctx){return ctx.label+': '+ctx.raw+' findings';}}}}}});
    }

    // Severity bar
    var sevEl=$('c-severity');
    if(sevEl){
      var sevCounts={critical:0,high:0,medium:0,low:0,info:0};
      F.forEach(function(f){sevCounts[f.severity]=(sevCounts[f.severity]||0)+1;});
      var sevLabels=['critical','high','medium','low','info'];
      new Chart(sevEl,{type:'bar',data:{labels:sevLabels.map(function(s){return s.charAt(0).toUpperCase()+s.slice(1);}),datasets:[{data:sevLabels.map(function(s){return sevCounts[s]||0;}),backgroundColor:['rgba(239,68,68,.8)','rgba(249,115,22,.8)','rgba(234,179,8,.8)','rgba(34,197,94,.8)','rgba(100,116,139,.8)'],borderWidth:0,borderRadius:4}]},options:{...cardCfg,indexAxis:'y',scales:{x:{grid:{color:gridColor},ticks:{color:'#94a3b8'}},y:{grid:{display:false},ticks:{color:'#94a3b8'}}},plugins:{legend:{display:false},tooltip:{callbacks:{label:function(ctx){return ctx.raw+' findings';}}}}}});
    }

    // Scanner coverage
    var scanEl=$('c-scanner');
    if(scanEl){
      var scanMap={};F.forEach(function(f){scanMap[f.scanner]=(scanMap[f.scanner]||0)+1;});
      var scanKeys=Object.keys(scanMap).sort(function(a,b){return scanMap[b]-scanMap[a];});
      new Chart(scanEl,{type:'bar',data:{labels:scanKeys,datasets:[{data:scanKeys.map(function(k){return scanMap[k];}),backgroundColor:'rgba(6,182,212,.7)',borderWidth:0,borderRadius:4}]},options:{...cardCfg,indexAxis:'y',scales:{x:{grid:{color:gridColor},ticks:{color:'#94a3b8'}},y:{grid:{display:false},ticks:{color:'#94a3b8'}}},plugins:{legend:{display:false}}}});
    }

    // Noise reduction pipeline
    var noiseEl=$('c-noise');
    if(noiseEl){
      new Chart(noiseEl,{type:'bar',data:{labels:['Raw findings','After dedup','After filtering','Active'],datasets:[{label:'Findings',data:[S.raw_findings,S.unique_findings,S.unique_findings-S.quarantined,S.final_findings],backgroundColor:['rgba(59,130,246,.7)','rgba(6,182,212,.7)','rgba(234,179,8,.7)','rgba(34,197,94,.7)'],borderWidth:0,borderRadius:6}]},options:{...cardCfg,scales:{y:{grid:{color:gridColor},ticks:{color:'#94a3b8'}},x:{grid:{display:false},ticks:{color:'#94a3b8'}}},plugins:{legend:{display:false},tooltip:{callbacks:{label:function(ctx){return ctx.raw.toLocaleString()+' findings';}}}}}});
    }

    // Risk over time
    var histEl=$('c-history');
    if(histEl){
      var colors=['#3b82f6','#06b6d4','#6366f1','#22c55e','#f97316'];
      var products=Object.keys(H);
      var histDatasets=[];
      products.forEach(function(prod,idx){
        var runs=H[prod];
        if(!runs||runs.length<1)return;
        histDatasets.push({label:prod,data:runs.map(function(r){return {x:r.run_date,y:r.avg_score};}),borderColor:colors[idx%colors.length],backgroundColor:'transparent',tension:.4,pointRadius:4,pointHoverRadius:6,borderWidth:2});
      });
      if(histDatasets.length){
        new Chart(histEl,{type:'line',data:{datasets:histDatasets},options:{...cardCfg,scales:{x:{type:'category',grid:{color:gridColor},ticks:{color:'#94a3b8',maxRotation:30}},y:{grid:{color:gridColor},ticks:{color:'#94a3b8'},title:{display:true,text:'Avg score',color:'#64748b'}}},plugins:{legend:{display:products.length>1,position:'bottom',labels:{color:'#94a3b8'}}}}});
      }else{
        histEl.parentElement.innerHTML='<p class="empty-state">Need 2+ pipeline runs to show trend.</p>';
      }
    }

    // EPSS scatter
    var epssEl=$('c-epss');
    if(epssEl){
      var epssData=F.filter(function(f){return f.epss_score>0&&f.score>0;}).map(function(f){return {x:parseFloat((f.epss_score*100).toFixed(2)),y:f.score,label:f.title,kev:f.kev,sev:f.severity};});
      new Chart(epssEl,{type:'scatter',data:{datasets:[{label:'Findings',data:epssData,backgroundColor:epssData.map(function(p){return p.kev?'rgba(239,68,68,.75)':p.sev==='critical'?'rgba(239,68,68,.5)':p.sev==='high'?'rgba(249,115,22,.5)':p.sev==='medium'?'rgba(234,179,8,.5)':'rgba(34,197,94,.35)';}),pointRadius:5,pointHoverRadius:8}]},options:{...cardCfg,scales:{x:{title:{display:true,text:'EPSS score (%)',color:'#64748b'},grid:{color:gridColor},ticks:{color:'#94a3b8'}},y:{title:{display:true,text:'Risk score',color:'#64748b'},grid:{color:gridColor},ticks:{color:'#94a3b8'},min:0,max:100}},plugins:{legend:{display:false},tooltip:{callbacks:{label:function(ctx){var d=ctx.raw;return [d.label.substring(0,40),'EPSS: '+d.x+'%  Score: '+d.y,d.kev?'In CISA KEV':''];}}}}}});
    }

    // Threat intel coverage
    var threatEl=$('c-threat');
    if(threatEl){
      var kevCount=F.filter(function(f){return f.kev;}).length;
      var exploitCount=F.filter(function(f){return f.exploit_available&&!f.kev;}).length;
      var epssHighCount=F.filter(function(f){return f.epss_score>.3&&!f.kev&&!f.exploit_available;}).length;
      var noIntelCount=F.length-kevCount-exploitCount-epssHighCount;
      new Chart(threatEl,{type:'doughnut',data:{labels:['CISA KEV (confirmed exploit)','Exploit-DB match','EPSS > 30%','No active intel'],datasets:[{data:[kevCount,exploitCount,epssHighCount,noIntelCount],backgroundColor:['rgba(239,68,68,.85)','rgba(249,115,22,.8)','rgba(234,179,8,.7)','rgba(100,116,139,.4)'],borderWidth:0,hoverOffset:6,borderRadius:4}]},options:{...cardCfg,cutout:'60%',plugins:{legend:{display:true,position:'bottom',labels:{color:'#94a3b8',boxWidth:10,boxHeight:10,padding:10}}}}});
    }
  }catch(e){console.error('initCharts:',e);}
}

// Wait for Chart.js to load, then init charts
function waitForCharts(){
  if(typeof Chart!=='undefined'){initCharts();return;}
  var attempts=0;
  var check=setInterval(function(){
    attempts++;
    if(typeof Chart!=='undefined'){clearInterval(check);initCharts();}
    if(attempts>100){clearInterval(check);console.warn('Chart.js did not load');}
  },200);
}
if(document.readyState==='loading'){
  document.addEventListener('DOMContentLoaded',function(){waitForCharts();initTable();});
}else{
  waitForCharts();initTable();
}

// ─── Findings Table ───
function initTable(){
  try{
    var F=DASH.findings;
    var priorities=[...new Set(F.map(function(f){return f.priority;}))].sort();
    var severities=[...new Set(F.map(function(f){return f.severity;}))].sort();
    var scanners=[...new Set(F.map(function(f){return f.scanner;}))].sort();
    [['f-priority',priorities],['f-severity',severities],['f-scanner',scanners]].forEach(function(arr){
      var sel=$(arr[0]);if(!sel)return;
      arr[1].forEach(function(v){
        var o=document.createElement('option');o.value=v;o.textContent=v;sel.appendChild(o);
      });
    });
    var COLS=[
      {k:'rank',label:'#',w:'40px',sortable:true},
      {k:'score',label:'Score',w:'110px',sortable:true},
      {k:'priority',label:'Priority',w:'80px',sortable:true},
      {k:'sla_hours',label:'SLA',w:'60px',sortable:true},
      {k:'product',label:'Product',w:'100px',sortable:true},
      {k:'scanner',label:'Scanner',w:'80px',sortable:true},
      {k:'severity',label:'Severity',w:'80px',sortable:true},
      {k:'title',label:'Title',w:'',sortable:false},
      {k:'cve',label:'CVE',w:'140px',sortable:false},
      {k:'kev',label:'KEV',w:'60px',sortable:true},
      {k:'epss_score',label:'EPSS',w:'70px',sortable:true},
      {k:'cwe',label:'CWE',w:'90px',sortable:false}
    ];
    var thead=$('tbl-head');if(!thead)return;
    thead.innerHTML='<tr>'+COLS.map(function(c){
      return '<th style="'+(c.w?'width:'+c.w:'')+'" '+(c.sortable?'data-col="'+c.k+'"':'')+'>'+c.label+(c.sortable?'<span class="sort-arrow">&#x2195;</span>':'')+'</th>';
    }).join('')+'</tr>';
    var sortCol='score',sortDir=-1,search='',fPri='',fSev='',fScan='',fKev='';
    function getFiltered(){
      var q=search.toLowerCase();
      return F.filter(function(f){
        if(fPri&&f.priority!==fPri)return false;
        if(fSev&&f.severity!==fSev)return false;
        if(fScan&&f.scanner!==fScan)return false;
        if(fKev==='kev'&&!f.kev)return false;
        if(fKev==='exploit'&&!f.exploit_available)return false;
        if(q)return(f.title+f.cve+f.cwe+f.endpoint+f.product).toLowerCase().includes(q);
        return true;
      }).sort(function(a,b){
        var av=a[sortCol],bv=b[sortCol];
        if(typeof av==='number')return(av-bv)*sortDir;
        return String(av).localeCompare(String(bv))*sortDir;
      });
    }
    function renderRow(f){
      var sc=scoreColor(f.score);
      var epssStr=f.epss_score>0?(f.epss_score*100).toFixed(1)+'%':'-';
      return '<tr class="data-row" data-rank="'+f.rank+'" onclick="toggleDetail(this)"><td class="no-wrap mono dimmed">'+f.rank+'</td><td class="no-wrap"><div class="score-cell"><span class="score-num" style="color:'+sc+'">'+f.score+'</span><div class="score-track"><div class="score-fill" style="width:'+f.score+'%;background:'+sc+'"></div></div></div></td><td class="no-wrap"><span class="badge '+priClass(f.priority)+'">'+esc(f.priority)+'</span></td><td class="no-wrap dimmed mono" style="font-size:11px">'+f.sla_hours+'h</td><td class="truncate" style="max-width:100px">'+esc(f.product)+'</td><td class="no-wrap dimmed" style="font-size:11.5px">'+esc(f.scanner)+'</td><td class="no-wrap"><span class="badge '+sevClass(f.severity)+'">'+esc(f.severity)+'</span></td><td style="max-width:300px"><span class="truncate" style="display:block">'+esc(f.title)+'</span></td><td class="no-wrap">'+(f.cve?'<a class="cve-link" href="https://nvd.nist.gov/vuln/detail/'+esc(f.cve)+'" target="_blank" onclick="event.stopPropagation()">'+esc(f.cve)+'</a>':'-')+'</td><td class="no-wrap">'+(f.kev?'<span class="badge b-kev">KEV</span>':f.exploit_available?'<span class="badge b-exploit">Exploit</span>':'')+'</td><td class="no-wrap mono" style="font-size:11px"><span class="badge b-epss">'+epssStr+'</span></td><td class="no-wrap mono dimmed" style="font-size:11px">'+esc(f.cwe||'-')+'</td></tr><tr class="detail-row" id="detail-'+f.rank+'"><td colspan="12">'+renderDetail(f)+'</td></tr>';
    }
    function renderDetail(f){
      var sb=f.score_components||{};
      var comps=Object.entries(sb).map(function(kv){return '<span style="margin-right:10px"><span class="dimmed">'+kv[0]+':</span> <b>'+kv[1]+'</b></span>';}).join('');
      var drivers=(f.score_drivers||[]).map(function(d){return '<span style="margin-right:8px;color:#fde047">&#x26a1; '+esc(d)+'</span>';}).join('');
      var rems=(f.remediation||[]).map(function(r){return '<li><span class="rem-kind">'+esc(r.kind)+'</span> '+esc(r.text)+'</li>';}).join('');
      var aiRem=f.ai_remediation?'<div class="ai-box"><div class="ai-label">AI-generated remediation</div>'+esc(f.ai_remediation)+'</div>':'';
      return '<div class="detail-panel"><div><div class="detail-section-title">Finding details</div><div class="detail-row-item"><span class="detail-key">Endpoint</span><span class="detail-val">'+esc(f.endpoint||'-')+(f.parameter?' (param: '+esc(f.parameter)+')':'')+'</span></div><div class="detail-row-item"><span class="detail-key">EPSS score</span><span class="detail-val">'+pct(f.epss_score)+' (pct '+pct(f.epss_percentile)+', trend '+(f.epss_trend>0?'+':'')+f.epss_trend+')</span></div><div class="detail-row-item"><span class="detail-key">KEV status</span><span class="detail-val">'+(f.kev?'In CISA KEV ('+esc(f.kev_date)+')':'Not in KEV')+'</span></div><div class="detail-row-item"><span class="detail-key">Exploit</span><span class="detail-val">'+(f.exploit_available?'Yes - '+esc(f.exploit_source):'Not found')+'</span></div><div class="detail-row-item"><span class="detail-key">Escalation potential</span><span class="detail-val">'+f.escalation_potential+'</span></div><div class="detail-row-item"><span class="detail-key">Owner</span><span class="detail-val">'+esc(f.owner||'-')+' · SLA '+f.sla_hours+'h</span></div><div style="margin-top:12px;color:var(--text2);font-size:12px;line-height:1.6">'+esc(f.description)+'</div></div><div><div class="detail-section-title">Score breakdown</div><div style="font-size:12px;margin-bottom:10px;line-height:2">'+(comps||'<span class="dimmed">no breakdown</span>')+'</div><div style="margin-bottom:12px">'+drivers+'</div><div class="detail-section-title">Remediation steps</div><ul class="rem-list">'+(rems||'<li class="dimmed">No remediation data</li>')+'</ul></div>'+aiRem+'</div>';
    }
    function render(){
      var rows=getFiltered();
      var rb=$('result-badge');if(rb)rb.textContent=rows.length+' of '+F.length+' findings';
      var tb=$('tbl-body');if(tb)tb.innerHTML=rows.map(renderRow).join('');
    }
    document.querySelectorAll('#tbl-head th[data-col]').forEach(function(th){
      th.addEventListener('click',function(){
        if(sortCol===th.dataset.col){sortDir*=-1;}else{sortCol=th.dataset.col;sortDir=-1;}
        document.querySelectorAll('#tbl-head th').forEach(function(t){t.classList.remove('sorted');var a=t.querySelector('.sort-arrow');if(a)a.textContent='\u2195';});
        th.classList.add('sorted');
        var arrow=th.querySelector('.sort-arrow');if(arrow)arrow.textContent=sortDir===-1?'\u2193':'\u2191';
        render();
      });
    });
    var searchTimer;
    var sb=$('tbl-search');if(sb)sb.addEventListener('input',function(e){clearTimeout(searchTimer);searchTimer=setTimeout(function(){search=e.target.value;render();},200);});
    var fp=$('f-priority');if(fp)fp.addEventListener('change',function(e){fPri=e.target.value;render();});
    var fs=$('f-severity');if(fs)fs.addEventListener('change',function(e){fSev=e.target.value;render();});
    var fsc=$('f-scanner');if(fsc)fsc.addEventListener('change',function(e){fScan=e.target.value;render();});
    var fk=$('f-kev');if(fk)fk.addEventListener('change',function(e){fKev=e.target.value;render();});
    render();
  }catch(e){console.error('initTable:',e);}
}

function toggleDetail(tr){
  var rank=tr.dataset.rank;var detail=$('detail-'+rank);if(!detail)return;
  var isOpen=detail.classList.contains('open');
  document.querySelectorAll('.detail-row.open').forEach(function(r){r.classList.remove('open');});
  document.querySelectorAll('.data-row.expanded').forEach(function(r){r.classList.remove('expanded');});
  if(!isOpen){detail.classList.add('open');tr.classList.add('expanded');}
}

// ─── Quarantine ───
(function buildQuarantine(){
  try{
    var Q=DASH.quarantine;var qb=$('q-body');if(!qb)return;
    qb.innerHTML=Q.length?Q.map(function(q){return '<tr><td>'+esc(q.product)+'</td><td>'+esc(q.scanner)+'</td><td><span class="badge '+sevClass(q.severity)+'">'+esc(q.severity)+'</span></td><td>'+esc(q.title)+'</td><td>'+(q.cve?'<a class="cve-link" href="https://nvd.nist.gov/vuln/detail/'+esc(q.cve)+'" target="_blank">'+esc(q.cve)+'</a>':'-')+'</td><td class="dimmed" style="font-size:12px">'+esc(q.reason)+'</td></tr>';}).join(''):'<tr><td colspan="6" class="empty-state">No findings quarantined this run.</td></tr>';
  }catch(e){console.error('buildQuarantine:',e);}
})();

// ─── Products ───
(function buildProducts(){
  try{
    var P=DASH.products||{};var keys=Object.keys(P);
    var tp=$('tc-products');if(tp)tp.textContent=keys.length;
    if(!keys.length){var ptw=$('products-table-wrap');if(ptw)ptw.innerHTML='<p class="empty-state">No products configured. Add one below.</p>';return;}
    var rows=keys.map(function(k){
      var p=P[k];var findings=DASH.findings.filter(function(f){return f.product===k;});
      var p1c=findings.filter(function(f){return f.priority==='P1';}).length;
      var p2c=findings.filter(function(f){return f.priority==='P2';}).length;
      var repo=p.github_repo||'<span class="dimmed">not set</span>';
      return '<tr><td><b>'+esc(p.display_name||k)+'</b><br><span class="dimmed" style="font-size:11px">'+esc(k)+'</span></td><td class="mono" style="font-size:12px">'+esc(p.url||'-')+'</td><td style="font-size:12px">'+repo+'</td><td class="dimmed" style="font-size:12px">'+esc(p.owner||'-')+'</td><td class="mono" style="font-size:12px">'+(p.asset_criticality||5)+'/10</td><td class="mono" style="font-size:12px">'+findings.length+' findings</td><td>'+(p1c>0?'<span class="badge b-p1">'+p1c+' P1</span>':'')+(p2c>0?'<span class="badge b-p2">'+p2c+' P2</span>':'')+'</td><td><button class="ap-btn" onclick="scanProduct(\''+esc(k)+'\')">Scan</button></td></tr>';
    }).join('');
    var ptw=$('products-table-wrap');if(ptw)ptw.innerHTML='<table class="f-table"><thead><tr><th>Product</th><th>URL</th><th>GitHub Repo</th><th>Owner</th><th>Criticality</th><th>Findings</th><th>P1/P2</th><th>Actions</th></tr></thead><tbody>'+rows+'</tbody></table>';
  }catch(e){console.error('buildProducts:',e);}
})();

function addProduct(){
  var id=$('ap-id').value.trim();var name=$('ap-name').value.trim()||id;var url=$('ap-url').value.trim();
  var repo=$('ap-repo').value.trim();var owner=$('ap-owner').value.trim();
  var crit=parseInt($('ap-crit').value)||5;var sens=parseInt($('ap-sens').value)||5;
  var trivy=$('ap-trivy').value.trim();
  if(!id||!url){var m=$('ap-msg');if(m){m.textContent='Product ID and URL are required';m.style.color='#ef4444';}return;}
  var scanners={nuclei:url,zap:url,wapiti:url};if(trivy)scanners.trivy=trivy;
  var product={display_name:name,owner:owner||'unassigned',asset_criticality:crit,business_impact:crit,exposure:8,control_effectiveness:3,data_sensitivity:sens,url:url,github_repo:repo,scanners:scanners};
  // Save to server if logged in
  if(API_TOKEN){
    apiFetch('/api/products',{method:'POST',body:JSON.stringify({product_id:id,display_name:name,url:url,github_repo:repo,owner:owner||'unassigned',asset_criticality:crit,data_sensitivity:sens})}).then(function(data){
      var m2=$('ap-msg');if(m2){m2.textContent=data.status==='created'?'Product saved to server!':'Product updated';m2.style.color='#22c55e';}
    }).catch(function(e){
      // Fallback to local-only
      DASH.products=DASH.products||{};DASH.products[id]=product;
      var m3=$('ap-msg');if(m3){m3.textContent='Saved locally (server unavailable)';m3.style.color='#eab308';}
    });
  }else{
    DASH.products=DASH.products||{};DASH.products[id]=product;
    var m4=$('ap-msg');if(m4){m4.textContent='Product saved. Login to persist to server.';m4.style.color='#eab308';}
  }
  var tp2=$('tc-products');if(tp2)tp2.textContent=Object.keys(DASH.products||{}).length;
  ['ap-id','ap-name','ap-url','ap-repo','ap-owner','ap-trivy'].forEach(function(fid){var el=$(fid);if(el)el.value='';});
  buildProducts();
}

function scanProduct(id){
  if(!API_TOKEN){window.location.href='/';return;}
  updateControlStatus('Starting scan for '+id+'...','info');
  apiFetch('/api/scans/start',{method:'POST',body:JSON.stringify({product:id})}).then(function(data){
    updateControlStatus('Scan started for '+id+'. '+((data.jobs||[]).length)+' scanner(s) queued.','ok');
  }).catch(function(e){updateControlStatus('Scan failed: '+e.message,'err');});
}

// ─── Control Center ───
function loadAppStatus(){
  if(!API_TOKEN)return;
  apiFetch('/api/products').then(function(data){
    var el=$('app-status-list');if(!el)return;
    var products=data.products||{};var statuses=data.app_statuses||{};var keys=Object.keys(products);
    if(!keys.length){el.innerHTML='<p class="dimmed" style="font-size:12px">No products configured.</p>';return;}
    el.innerHTML=keys.map(function(k){
      var p=products[k];var s=statuses[k]||{};var isUp=s.status==='up';
      return '<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.03);font-size:12px"><span style="width:8px;height:8px;border-radius:50%;background:'+(isUp?'#22c55e':'#ef4444')+';flex-shrink:0"></span><span style="flex:1"><b>'+esc(p.display_name||k)+'</b> <span class="dimmed">'+esc(p.url||'')+'</span></span><span class="dimmed">'+(isUp?'UP ('+s.response_time_ms+'ms)':'DOWN')+'</span></div>';
    }).join('');
  }).catch(function(){});
}

var ws=null;
function connectWebSocket(){
  var token=API_TOKEN;if(!token||typeof WebSocket==='undefined')return;
  var proto=location.protocol==='https:'?'wss:':'ws:';
  try{
    ws=new WebSocket(proto+'//'+location.host+'/ws/live?token='+token);
    ws.onmessage=function(e){try{var msg=JSON.parse(e.data);if(msg.type==='scan_update')handleScanUpdate(msg.data);}catch(x){}};
    ws.onclose=function(){setTimeout(connectWebSocket,5000);};
    ws.onerror=function(){};
  }catch(x){}
}

function handleScanUpdate(job){
  var el=$('scanner-progress');if(!el)return;
  var existing=el.querySelector('[data-job="'+job.job_id+'"]');
  if(!existing){el.innerHTML='';existing=document.createElement('div');existing.setAttribute('data-job',job.job_id);el.appendChild(existing);}
  var statusColors={pending:'#64748b',running:'#3b82f6',completed:'#22c55e',failed:'#ef4444'};
  var sc=statusColors[job.status]||'#64748b';
  var elapsed=job.started_at?(job.finished_at||Date.now()/1000)-job.started_at:0;
  existing.innerHTML='<div style="display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,.03)"><span style="width:10px;height:10px;border-radius:50%;background:'+sc+';flex-shrink:0"></span><div style="flex:1"><div style="font-size:13px;font-weight:500">'+esc(job.product)+' / '+esc(job.scanner)+'</div><div class="dimmed" style="font-size:11px">'+esc(job.target_url)+'</div></div><div style="text-align:right"><span class="badge" style="background:'+sc+'22;color:'+sc+';border:1px solid '+sc+'44">'+job.status+'</span><div class="dimmed" style="font-size:10px;margin-top:2px">'+elapsed.toFixed(1)+'s</div></div></div>';
}

function triggerScanAll(){
  if(!API_TOKEN){window.location.href='/';return;}
  updateControlStatus('Starting scan for all products...','info');
  apiFetch('/api/products').then(function(data){
    var products=data.products||{};var promises=Object.keys(products).map(function(pid){
      return apiFetch('/api/scans/start',{method:'POST',body:JSON.stringify({product:pid})}).catch(function(){});
    });
    Promise.all(promises).then(function(){
      updateControlStatus('Scans started for all products. Watch Scanner Progress below.','ok');
      loadScannerJobs();
    });
  }).catch(function(e){updateControlStatus('Failed: '+e.message,'err');});
}

function loadScannerJobs(){
  if(!API_TOKEN)return;
  apiFetch('/api/scans/jobs').then(function(data){
    if(data.jobs&&data.jobs.length){
      var el=$('scanner-progress');if(!el)return;
      el.innerHTML=data.jobs.map(function(job){
        var statusColors={pending:'#64748b',running:'#3b82f6',completed:'#22c55e',failed:'#ef4444'};
        var sc=statusColors[job.status]||'#64748b';
        var elapsed=job.started_at?(job.finished_at||Date.now()/1000)-job.started_at:0;
        return '<div data-job="'+job.job_id+'" style="display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,.03)"><span style="width:10px;height:10px;border-radius:50%;background:'+sc+';flex-shrink:0"></span><div style="flex:1"><div style="font-size:13px;font-weight:500">'+esc(job.product)+' / '+esc(job.scanner)+'</div><div class="dimmed" style="font-size:11px">'+esc(job.target_url)+'</div></div><div style="text-align:right"><span class="badge" style="background:'+sc+'22;color:'+sc+';border:1px solid '+sc+'44">'+job.status+'</span><div class="dimmed" style="font-size:10px;margin-top:2px">'+elapsed.toFixed(1)+'s</div></div></div>';
      }).join('');
    }
  }).catch(function(){});
}

function runPipeline(){
  if(!API_TOKEN){window.location.href='/';return;}
  updateControlStatus('Running 8-stage pipeline...','info');
  apiFetch('/api/pipeline/run',{method:'POST',body:JSON.stringify({skip_enrich:true,skip_ai:true})}).then(function(){
    updateControlStatus('Pipeline started in background. Check status periodically.','ok');
    pollPipelineStatus();
  }).catch(function(e){updateControlStatus('Pipeline failed: '+e.message,'err');});
}

function pollPipelineStatus(){
  var check=function(){
    apiFetch('/api/pipeline/status').then(function(data){
      if(data.running){updateControlStatus('Pipeline is running...','info');setTimeout(check,3000);}
      else{updateControlStatus('Pipeline complete! Refresh to see updated results.','ok');}
    }).catch(function(){});
  };check();
}

function createTickets(){
  if(!API_TOKEN){window.location.href='/';return;}
  updateControlStatus('Creating GitHub Issues for findings above threshold...','info');
  apiFetch('/api/tickets/create?threshold=60',{method:'POST'}).then(function(data){
    var results=data.results||{};var total=0;Object.values(results).forEach(function(r){total+=(r.created||0);});
    updateControlStatus('Created '+total+' GitHub Issues across '+Object.keys(results).length+' products.','ok');
  }).catch(function(e){updateControlStatus('Ticket creation failed: '+e.message,'err');});
}

function checkDocker(){
  updateControlStatus('Checking Docker...','info');
  apiFetch('/api/scanners/status').then(function(data){
    if(data.docker_available){updateControlStatus('Docker is running. Active jobs: '+data.active_jobs,'ok');}
    else{updateControlStatus('Docker is not available. Install Docker Desktop.','err');}
  }).catch(function(e){updateControlStatus('Cannot connect to server: '+e.message,'err');});
}

// Auto-connect when Control Center tab is visible
document.querySelectorAll('.tab-btn').forEach(function(btn){
  if(btn.dataset.page==='control'){
    btn.addEventListener('click',function(){loadAppStatus();connectWebSocket();loadScannerJobs();});
  }
});

// ─── Attack Paths (D3) ───
var HIGH_IMPACT=['CWE-89','CWE-79','CWE-78','CWE-22','CWE-434','CWE-918','CWE-502','CWE-611','CWE-287','CWE-306'];
var apZoom,apSvgRoot;

function initD3(){
  if(typeof d3==='undefined'){var ap=$('ap-container');if(ap)ap.innerHTML='<div class="ap-no-data">D3.js not loaded. Check internet connection.</div>';return;}
  var AP=DASH.attack_paths;var products=Object.keys(AP);
  if(!products.length){$('ap-container').innerHTML='<div class="ap-no-data">No attack paths found in this run.</div>';return;}
  var sel=$('ap-product');if(!sel)return;
  sel.innerHTML=products.map(function(p){return '<option value="'+esc(p)+'">'+esc(p)+'</option>';}).join('');
  var tp=$('tc-paths');if(tp)tp.textContent=Object.values(AP).reduce(function(a,v){return a+v.length;},0);
  sel.addEventListener('change',function(){renderD3(sel.value);});
  renderD3(products[0]);
}

function renderD3(product){
  var paths=DASH.attack_paths[product]||[];
  var svgEl=$('ap-svg');var tooltip=$('ap-tooltip');var container=$('ap-container');
  if(!svgEl)return;
  svgEl.innerHTML='';
  if(!paths.length){svgEl.innerHTML='<text x="50%" y="50%" text-anchor="middle" fill="#64748b" dy=".3em">No paths for this product</text>';return;}
  var nodeSet=new Map();
  paths.forEach(function(p){
    if(!nodeSet.has(p.from_cwe))nodeSet.set(p.from_cwe,{id:p.from_cwe,group:HIGH_IMPACT.includes(p.from_cwe)?1:0});
    if(!nodeSet.has(p.to_cwe))nodeSet.set(p.to_cwe,{id:p.to_cwe,group:HIGH_IMPACT.includes(p.to_cwe)?2:0});
  });
  var nodes=[...nodeSet.values()];
  var links=paths.map(function(p){return {source:p.from_cwe,target:p.to_cwe,prob:p.probability,desc:p.description||''};});
  var W=svgEl.parentElement.clientWidth||900,H=540;
  svgEl.setAttribute('viewBox','0 0 '+W+' '+H);
  var svg=d3.select('#ap-svg');var g=svg.append('g');
  apZoom=d3.zoom().scaleExtent([.3,3]).on('zoom',function(e){g.attr('transform',e.transform);});
  svg.call(apZoom);apSvgRoot=svg;
  var defs=svg.append('defs');
  ['low','med','high'].forEach(function(t,i){
    defs.append('marker').attr('id','arr-'+t).attr('viewBox','0 -4 8 8').attr('refX',26).attr('refY',0).attr('markerWidth',6).attr('markerHeight',6).attr('orient','auto').append('path').attr('d','M0,-4L8,0L0,4').attr('fill',['rgba(34,197,94,.7)','rgba(234,179,8,.8)','rgba(239,68,68,.8)'][i]);
  });
  var probClass=function(p){return p>.6?'high':p>.3?'med':'low';};
  var probColor=function(p){return p>.6?'rgba(239,68,68,.7)':p>.3?'rgba(234,179,8,.7)':'rgba(34,197,94,.6)';};
  var link=g.append('g').selectAll('line').data(links).join('line').attr('stroke',function(d){return probColor(d.prob);}).attr('stroke-width',function(d){return 1+d.prob*3;}).attr('stroke-opacity',.7).attr('marker-end',function(d){return 'url(#arr-'+probClass(d.prob)+')';});
  var linkLabel=g.append('g').selectAll('text').data(links).join('text').text(function(d){return 'p='+d.prob;}).attr('font-size',9).attr('fill','#64748b').attr('text-anchor','middle');
  var nodeG=g.append('g').selectAll('g').data(nodes).join('g').call(d3.drag().on('start',function(e,d){if(!e.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y;}).on('drag',function(e,d){d.fx=e.x;d.fy=e.y;}).on('end',function(e,d){if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}));
  var filter=defs.append('filter').attr('id','glow');
  filter.append('feGaussianBlur').attr('stdDeviation','4').attr('result','blur');
  var feMerge=filter.append('feMerge');feMerge.append('feMergeNode').attr('in','blur');feMerge.append('feMergeNode').attr('in','SourceGraphic');
  nodeG.append('circle').attr('r',function(d){return d.group===2?32:d.group===1?28:22;}).attr('fill',function(d){return d.group===2?'rgba(239,68,68,.15)':d.group===1?'rgba(249,115,22,.12)':'rgba(59,130,246,.12)';}).attr('stroke',function(d){return d.group===2?'#ef4444':d.group===1?'#f97316':'#3b82f6';}).attr('stroke-width',2).attr('filter','url(#glow)');
  nodeG.append('text').text(function(d){return d.id.replace('CWE-','');}).attr('text-anchor','middle').attr('dy','-.2em').attr('font-size',10).attr('font-weight',700).attr('fill','#f1f5f9');
  nodeG.append('text').text('CWE').attr('text-anchor','middle').attr('dy','1em').attr('font-size',8).attr('fill','#64748b');
  nodeG.on('mouseover',function(e,d){if(tooltip){tooltip.style.display='block';tooltip.innerHTML='<b>'+d.id+'</b><br>'+(d.group===2?'High-impact exploitation target':d.group===1?'Attack entry point':'Intermediate escalation node');}}).on('mousemove',function(e){if(!container||!tooltip)return;var r=container.getBoundingClientRect();tooltip.style.left=(e.clientX-r.left+12)+'px';tooltip.style.top=(e.clientY-r.top-30)+'px';}).on('mouseout',function(){if(tooltip)tooltip.style.display='none';});
  link.on('mouseover',function(e,d){if(tooltip){tooltip.style.display='block';tooltip.innerHTML='<b>'+d.source.id+' to '+d.target.id+'</b><br>Probability: '+d.prob+'<br>'+esc(d.desc).substring(0,100);}}).on('mousemove',function(e){if(!container||!tooltip)return;var r=container.getBoundingClientRect();tooltip.style.left=(e.clientX-r.left+12)+'px';tooltip.style.top=(e.clientY-r.top-30)+'px';}).on('mouseout',function(){if(tooltip)tooltip.style.display='none';});
  var sim=d3.forceSimulation(nodes).force('link',d3.forceLink(links).id(function(d){return d.id;}).distance(function(d){return 100+d.prob*80;})).force('charge',d3.forceManyBody().strength(-420)).force('center',d3.forceCenter(W/2,H/2)).force('collision',d3.forceCollide(45));
  sim.on('tick',function(){
    link.attr('x1',function(d){return d.source.x;}).attr('y1',function(d){return d.source.y;}).attr('x2',function(d){return d.target.x;}).attr('y2',function(d){return d.target.y;});
    linkLabel.attr('x',function(d){return(d.source.x+d.target.x)/2;}).attr('y',function(d){return(d.source.y+d.target.y)/2-6;});
    nodeG.attr('transform',function(d){return 'translate('+d.x+','+d.y+')';});
  });
}

function apReset(){if(apSvgRoot)apSvgRoot.transition().duration(500).call(apZoom.transform,d3.zoomIdentity);}

// ─── Lifecycle Tab ─── (uses real data from DASH.lifecycle)
(function initLifecycle(){
  try{
    var LC=DASH.lifecycle||{};
    var tracked=LC.findings||[];
    var statusCounts=LC.status_counts||{};
    var overdueCount=LC.overdue_count||0;
    var statusColors={open:'#f97316',in_progress:'#3b82f6',fixed:'#22c55e',verified:'#06b6d4',accepted:'#64748b',false_positive:'#ef4444',risk_accepted:'#64748b'};
    var openCount=statusCounts.open||0;
    var inProgCount=statusCounts.in_progress||0;
    var fixedCount=(statusCounts.fixed||0)+(statusCounts.verified||0);
    var lckg=$('lc-kpi-grid');
    if(lckg)lckg.innerHTML=[
      {v:tracked.length,l:'Total tracked',cls:'blue',icon:'&#x1f50d;'},
      {v:openCount,l:'Open',cls:'warn',icon:'&#x1f513;'},
      {v:inProgCount,l:'In Progress',cls:'blue',icon:'&#x23f3;'},
      {v:fixedCount,l:'Fixed / Verified',cls:'success',icon:'&#x2705;'},
      {v:overdueCount,l:'SLA Breached',cls:'danger',icon:'&#x23f0;'},
    ].map(function(c,i){return '<div class="kpi '+c.cls+'"><span class="kpi-accent">'+c.icon+'</span><div class="kpi-value">'+c.v+'</div><div class="kpi-label">'+c.l+'</div></div>';}).join('');
    var tcl=$('tc-lifecycle');if(tcl)tcl.textContent=tracked.length;
    // Lifecycle table
    if(tracked.length>0){
      var rows=tracked.slice(0,100).map(function(f){
        var sc2=statusColors[f.status]||'#64748b';
        var isBreach=f.sla_deadline&&new Date(f.sla_deadline)<new Date()&&(f.status==='open'||f.status==='in_progress');
        return '<tr><td>'+esc(f.product)+'</td><td><span class="badge '+sevClass(f.severity)+'">'+esc(f.severity)+'</span></td><td style="max-width:200px" class="truncate">'+esc(f.title)+'</td><td class="no-wrap">'+(f.cve?esc(f.cve):'-')+'</td><td class="no-wrap"><span class="badge" style="background:'+sc2+'22;color:'+sc2+';border:1px solid '+sc2+'44">'+f.status.replace('_',' ')+'</span></td><td class="no-wrap '+(isBreach?'':'dimmed')+'" style="font-size:11px;'+(isBreach?'color:#ef4444;font-weight:600':'')+'">'+(isBreach?'BREACHED':'OK')+'</td><td class="no-wrap" style="font-size:11px">'+esc(f.owner||'-')+'</td><td class="no-wrap" style="font-size:11px">'+esc(f.sla_hours||0)+'h</td></tr>';
      }).join('');
      var lctw=$('lc-table-wrap');if(lctw)lctw.innerHTML='<table class="f-table"><thead><tr><th>Product</th><th>Severity</th><th>Title</th><th>CVE</th><th>Status</th><th>SLA</th><th>Owner</th><th>SLA Hours</th></tr></thead><tbody>'+rows+'</tbody></table>';
    }else{
      var lctw2=$('lc-table-wrap');if(lctw2)lctw2.innerHTML='<p class="empty-state">No findings tracked yet. Run the pipeline to start lifecycle tracking.</p>';
    }
    // Breached list
    var overdue=LC.overdue_findings||[];
    var lcbl=$('lc-breached-list');
    if(lcbl)lcbl.innerHTML=overdue.length?overdue.slice(0,20).map(function(f){
      return '<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.03);font-size:12px"><span style="color:#ef4444;font-weight:700">&#x23f0;</span><span style="flex:1"><b>'+esc((f.title||'').substring(0,60))+'</b> <span class="dimmed">'+esc(f.product)+'</span></span><span class="badge b-p1">SLA BREACHED</span></div>';
    }).join(''):'<p class="dimmed" style="font-size:12px">No SLA breaches detected.</p>';
  }catch(e){console.error('initLifecycle:',e);}
})();

// ─── Dedup Analytics Tab ─── (uses DASH.dedup_analytics)
(function initDedup(){
  try{
    var S=DASH.summary;
    var DA=DASH.dedup_analytics||{};
    var noiseRm=S.raw_findings>0?((S.raw_findings-S.final_findings)/S.raw_findings*100).toFixed(1):0;
    // KPIs
    var dkg=$('dedup-kpi-grid');
    if(dkg)dkg.innerHTML=[
      {v:S.raw_findings,l:'Raw findings',cls:'blue',icon:'&#x1f4e5;'},
      {v:S.unique_findings,l:'After dedup',cls:'cyan',icon:'&#x1f500;'},
      {v:S.dedup_pct+'%',l:'Dedup rate',cls:'success',icon:'&#x1f4c9;'},
      {v:noiseRm+'%',l:'Total noise removed',cls:'',icon:'&#x1f3af;'},
      {v:(DA.per_scanner_counts?Object.keys(DA.per_scanner_counts).length:0)+' scanners',l:'Scanner sources',cls:'blue',icon:'&#x1f50d;'},
      {v:(DA.cross_scanner_redundancy||[]).length,l:'Cross-scanner overlaps',cls:'warn',icon:'&#x1f517;'},
    ].map(function(c,i){return '<div class="kpi '+c.cls+'"><span class="kpi-accent">'+c.icon+'</span><div class="kpi-value">'+c.v+'</div><div class="kpi-label">'+c.l+'</div></div>';}).join('');
    // Scanner distribution chart — use per_scanner_counts from pipeline dedup
    var scannerCounts=DA.per_scanner_counts||{};
    // Fallback: compute from findings
    if(Object.keys(scannerCounts).length===0){
      var F=DASH.findings;var scanMap={};F.forEach(function(f){scanMap[f.scanner]=(scanMap[f.scanner]||0)+1;});
      scannerCounts=scanMap;
    }
    var scanKeys=Object.keys(scannerCounts).sort(function(a,b){return scannerCounts[b]-scannerCounts[a];});
    if(HAS_CHART&&$('c-dedup-scanner')){
      new Chart($('c-dedup-scanner'),{type:'bar',data:{labels:scanKeys,datasets:[{label:'Pre-dedup findings',data:scanKeys.map(function(k){return scannerCounts[k];}),backgroundColor:['rgba(59,130,246,.7)','rgba(6,182,212,.7)','rgba(234,179,8,.7)','rgba(239,68,68,.7)','rgba(99,102,241,.7)'],borderWidth:0,borderRadius:6}]},options:{...cardCfg,scales:{y:{grid:{color:gridColor},ticks:{color:'#94a3b8'}},x:{grid:{display:false},ticks:{color:'#94a3b8'}}},plugins:{legend:{display:false}}}});
    }
    // Cross-scanner overlap chart
    var overlaps=DA.cross_scanner_redundancy||[];
    if(HAS_CHART&&$('c-dedup-overlap')&&overlaps.length>0){
      var topOverlaps=overlaps.slice(0,10);
      new Chart($('c-dedup-overlap'),{type:'bar',data:{labels:topOverlaps.map(function(o){return(o.cve||o.vulnerability||'').substring(0,25);}),datasets:[{label:'Scanners detecting',data:topOverlaps.map(function(o){return(o.scanners_found_it||[]).length;}),backgroundColor:'rgba(249,115,22,.7)',borderWidth:0,borderRadius:6}]},options:{...cardCfg,indexAxis:'y',scales:{x:{grid:{color:gridColor},ticks:{color:'#94a3b8'},title:{display:true,text:'# scanners',color:'#64748b'}},y:{grid:{display:false},ticks:{color:'#94a3b8',font:{size:10}}}},plugins:{legend:{display:false}}}});
    }else if($('c-dedup-overlap')){
      var cel=$('c-dedup-overlap');if(cel&&cel.parentElement)cel.parentElement.innerHTML='<div class="card-title"><span>&#x1f517;</span> Cross-scanner redundancy</div><p class="empty-state">No cross-scanner overlaps detected in this run.</p>';
    }
    // Overlap table
    var overlapRows=overlaps.map(function(o){
      var scanners=(o.scanners_found_it||[]).map(function(s){return '<span class="badge" style="background:rgba(6,182,212,.1);color:#67e8f9;margin-right:4px">'+esc(s)+'</span>';}).join('');
      return '<tr><td class="no-wrap">'+(o.cve?'<a class="cve-link" href="https://nvd.nist.gov/vuln/detail/'+esc(o.cve)+'" target="_blank">'+esc(o.cve)+'</a>':'<span class="dimmed">-</span>')+'</td><td>'+scanners+'</td><td style="max-width:200px" class="truncate">'+esc(o.vulnerability||'-')+'</td><td class="no-wrap">'+esc(o.product||'-')+'</td><td class="no-wrap dimmed">'+esc(o.canonical_source||'-')+'</td></tr>';
    }).join('');
    var dot=$('dedup-overlap-table');
    if(dot)dot.innerHTML=overlapRows?'<table class="f-table"><thead><tr><th>CVE</th><th>Detecting Scanners</th><th>Vulnerability</th><th>Product</th><th>Canonical</th></tr></thead><tbody>'+overlapRows+'</tbody></table>':'<p class="dimmed" style="font-size:12px">No cross-scanner overlaps detected. This means each vulnerability was found by only one scanner.</p>';
  }catch(e){console.error('initDedup:',e);}
})();

// ─── Integrations Tab ───
async function testJira(){
  var el=$('jira-status');if(!el)return;
  el.innerHTML='<span class="dimmed">Testing connection...</span>';
  try{var data=await apiFetch('/api/jira/test');el.innerHTML=data.connected?'<span style="color:#22c55e">Connected to '+esc(data.url||'Jira')+'</span>':'<span style="color:#ef4444">'+esc(data.error||'Not configured')+'</span>';}catch(e){el.innerHTML='<span style="color:#ef4444">'+esc(e.message)+'</span>';}
}
async function createJiraIssues(){
  var el=$('jira-status');if(!el)return;
  el.innerHTML='<span class="dimmed">Creating issues...</span>';
  try{var data=await apiFetch('/api/jira/create?threshold=60',{method:'POST'});el.innerHTML='<span style="color:#22c55e">Created '+(data.created||0)+' issues</span>';}catch(e){el.innerHTML='<span style="color:#ef4444">'+esc(e.message)+'</span>';}
}
async function testDefectDojo(){
  var el=$('dd-status');if(!el)return;
  el.innerHTML='<span class="dimmed">Testing connection...</span>';
  try{var data=await apiFetch('/api/defectdojo/test');el.innerHTML=data.connected?'<span style="color:#22c55e">Connected to '+esc(data.url||'DefectDojo')+'</span>':'<span style="color:#ef4444">'+esc(data.error||'Not configured')+'</span>';}catch(e){el.innerHTML='<span style="color:#ef4444">'+esc(e.message)+'</span>';}
}
async function importDefectDojo(){
  var el=$('dd-status');if(!el)return;
  el.innerHTML='<span class="dimmed">Importing findings...</span>';
  try{var data=await apiFetch('/api/defectdojo/import?product_name=all',{method:'POST'});el.innerHTML='<span style="color:#22c55e">'+esc(data.message||'Imported')+'</span>';}catch(e){el.innerHTML='<span style="color:#ef4444">'+esc(e.message)+'</span>';}
}
async function saveApiKeys(){
  var el=$('apikey-status');if(!el)return;
  el.innerHTML='<span class="dimmed">Saving API keys...</span>';
  var keys={};
  var groq=$('ak-groq');if(groq&&groq.value.trim())keys.groq_api_key=groq.value.trim();
  var nvd=$('ak-nvd');if(nvd&&nvd.value.trim())keys.nvd_api_key=nvd.value.trim();
  var gh=$('ak-github');if(gh&&gh.value.trim())keys.github_token=gh.value.trim();
  var jurl=$('ak-jira-url');if(jurl&&jurl.value.trim())keys.jira_url=jurl.value.trim();
  var juser=$('ak-jira-user');if(juser&&juser.value.trim())keys.jira_user=juser.value.trim();
  var jtoken=$('ak-jira-token');if(jtoken&&jtoken.value.trim())keys.jira_token=jtoken.value.trim();
  var jproj=$('ak-jira-project');if(jproj&&jproj.value.trim())keys.jira_project=jproj.value.trim();
  var ddurl=$('ak-dd-url');if(ddurl&&ddurl.value.trim())keys.defectdojo_url=ddurl.value.trim();
  var ddkey=$('ak-dd-key');if(ddkey&&ddkey.value.trim())keys.defectdojo_api_key=ddkey.value.trim();
  try{await apiFetch('/api/config/keys',{method:'POST',body:JSON.stringify(keys)});el.innerHTML='<span style="color:#22c55e">API keys saved! Restart server to apply.</span>';}catch(e){el.innerHTML='<span style="color:#ef4444">'+esc(e.message)+'</span>';}
}
</script>
</body>
</html>"""

with open('pipeline/dashboard.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Find the old JS section boundaries
# It starts after the second <script> tag
old_start = content.find('<script>\r\nconst esc=')
if old_start == -1:
    # Try without \r
    old_start = content.find('<script>\nconst esc=')
if old_start == -1:
    print("ERROR: Could not find old JS start")
    exit(1)

# Find the end: </script>\n</body>
old_end = content.find('</script>\r\n</body>\r\n</html>"""')
if old_end == -1:
    old_end = content.find('</script>\n</body>\n</html>"""')
if old_end == -1:
    print("ERROR: Could not find old JS end")
    exit(1)

print(f"Found old JS at chars {old_start} to {old_end}")
print(f"Old JS length: {old_end - old_start} chars")

new_content = content[:old_start] + NEW_JS + content[old_end:]

with open('pipeline/dashboard.py', 'w', encoding='utf-8') as f:
    f.write(new_content)

print(f"SUCCESS: Replaced JS section ({old_end - old_start} -> {len(NEW_JS)} chars)")
