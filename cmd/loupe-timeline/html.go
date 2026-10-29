package main

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"strings"
)

// HTML view: the same report, with markers already downsampled by the
// builder and the syscall series already bucketed. Embedded as JSON and
// rendered client-side — one file, inline CSS/JS, no external requests.
func renderHTML(w io.Writer, rep *Report) error {
	data, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	// Keep the embedded JSON from closing the script element early.
	data = []byte(strings.ReplaceAll(string(data), "</", `<\/`))
	page := strings.Replace(htmlPage, "__DATA__", string(data), 1)
	page = strings.Replace(page, "__TITLE__", html.EscapeString("AgentLoupe timeline "+rep.CaptureStart), 1)
	_, err = fmt.Fprint(w, page)
	return err
}

// Categorical palette (fixed order, never cycled; "other" is grey):
// #2a78d6 #eb6834 #1baf7a #eda100 #e87ba4 #008300 #6250d6 #e34948.
const htmlPage = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
:root{--surface:#fcfcfb;--plane:#f9f9f7;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;--grid:#e1e0d9;--axis:#c3c2b7;--bar:#2a78d6}
@media (prefers-color-scheme:dark){:root{--surface:#1a1a19;--plane:#0d0d0d;--ink:#f0efec;--ink2:#c3c2b7;--grid:#2c2c2a;--axis:#383835;--bar:#3987e5}}
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--plane);color:var(--ink);margin:20px}
h1{font-size:20px} h2{font-size:16px;margin-top:28px} .sub{color:var(--ink2)}
.note{background:#eda10033;border:1px solid #eda100;padding:8px 12px;margin:8px 0;border-radius:4px}
.controls{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:12px 0;position:sticky;top:0;background:var(--plane);padding:8px 0;z-index:5}
select,button{font:inherit;padding:4px 8px}
svg{background:var(--surface);border:1px solid var(--grid);width:100%;height:auto;display:block}
#tip{position:fixed;pointer-events:none;background:var(--surface);color:var(--ink);border:1px solid var(--axis);padding:6px 8px;border-radius:4px;font-size:12px;max-width:480px;display:none;z-index:10;white-space:pre-wrap;word-break:break-all}
table{border-collapse:collapse;margin:8px 0 16px;font-size:13px} th,td{border:1px solid var(--grid);padding:3px 8px;text-align:left} td.n{text-align:right;font-variant-numeric:tabular-nums}
.legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--ink2)} .sw{display:inline-block;width:10px;height:10px;margin-right:4px;border-radius:2px}
text{fill:var(--ink)} .muted{fill:var(--muted)} .lbl{font-size:11px} .hdr{font-size:12px;font-weight:600}
</style></head><body>
<h1>AgentLoupe timeline</h1>
<div class="sub" id="cap"></div>
<div id="notes"></div>
<div class="controls">
<label>Agent / session <select id="filter"></select></label>
<button id="zin">Zoom in</button><button id="zout">Zoom out</button><button id="zreset">Reset zoom</button>
<label><input type="checkbox" id="showHidden"> show memory + sync/wait</label>
<label>Rate chart <select id="drill"><option value="categories">by category</option></select></label>
<span class="sub">wheel = zoom at cursor, drag = pan</span>
</div>
<div class="legend" id="legend"></div>
<svg id="tl" role="img" aria-label="Process swimlane timeline"></svg>
<div id="charts"></div>
<div id="tables"></div>
<div id="tip"></div>
<script type="application/json" id="data">__DATA__</script>
<script>
"use strict";
const DATA=JSON.parse(document.getElementById('data').textContent);
const COLORS=["#2a78d6","#eb6834","#1baf7a","#eda100","#e87ba4","#008300","#6250d6","#e34948"];
const OTHER="#898781";
const MARK={file_open:"#eb6834",file_unlink:"#e34948",file_rename:"#eda100",file_chmod:"#e87ba4",net_connect:"#1baf7a"};
const CATCOLORS={process:"#2a78d6",file:"#eb6834",network:"#1baf7a",memory:"#eda100","sync/wait":"#e87ba4",signals:"#008300",time:"#6250d6",other:"#898781"};
const HIDDEN={memory:1,"sync/wait":1};
let view=[0,Math.max(1,DATA.duration_ms||1)];
const esc=s=>String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fmtDur=ms=>ms>=1000?(ms/1000).toFixed(2)+"s":ms+"ms";
document.getElementById('cap').textContent=(DATA.capture_start||"")+" .. "+(DATA.capture_end||"")+"  ("+DATA.total_events+" events, "+DATA.sessions.length+" sessions)";
const notes=document.getElementById('notes');
(DATA.notes||[]).forEach(n=>{const d=document.createElement('div');d.className='note';d.textContent=n;notes.appendChild(d);});
if(!DATA.has_syscall_summary){const d=document.createElement('div');d.className='note';d.textContent='No syscall_summary events in this capture — syscall rate chart unavailable.';notes.appendChild(d);}
const filter=document.getElementById('filter');
filter.innerHTML='<option value="all">All sessions</option>'+DATA.sessions.map(s=>'<option value="'+s.session_id+'">'+esc(s.agent)+' · session '+s.session_id+' · '+esc(s.root_comm)+'</option>').join('');
document.getElementById('legend').innerHTML='<span><span class="sw" style="background:var(--bar)"></span>process</span>'+Object.keys(MARK).map(k=>'<span><span class="sw" style="background:'+MARK[k]+'"></span>'+k+'</span>').join('')+'<span style="color:#6250d6">◆ first-seen syscall</span>';
const drill=document.getElementById('drill');
{const cats=new Set(); DATA.sessions.forEach(s=>Object.keys(s.syscall_series_by_category||{}).forEach(c=>cats.add(c)));
 ['process','file','network','memory','sync/wait','signals','time','other'].forEach(c=>{if(cats.has(c)){const o=document.createElement('option');o.value=c;o.textContent='drill: '+c+' syscalls';drill.appendChild(o);}});}
const visible=()=>DATA.sessions.filter(s=>filter.value==='all'||String(s.session_id)===filter.value);
const tip=document.getElementById('tip');
function showTip(e){const t=e.target&&e.target.dataset?e.target.dataset.tip:null;if(!t){tip.style.display='none';return;}tip.textContent=t;tip.style.display='block';tip.style.left=(e.clientX+12)+'px';tip.style.top=(e.clientY+12)+'px';}
function render(){
 const W=1240,LBL=300,PW=W-LBL,ROW=18,HDR=22;
 const ss=visible(); let y=26, rows=[];
 const [v0,v1]=view, span=Math.max(1,v1-v0);
 const x=ms=>LBL+(ms-v0)/span*PW;
 let body='';
 // time axis
 for(let i=0;i<=6;i++){const ms=v0+span*i/6,xx=x(ms);body+='<line x1="'+xx+'" y1="18" x2="'+xx+'" y2="'+(26+ss.reduce((a,s)=>a+HDR+s.processes.length*ROW+8,0))+'" stroke="var(--grid)"/><text class="muted lbl" x="'+xx+'" y="12" text-anchor="middle">'+fmtDur(Math.round(ms))+'</text>';}
 ss.forEach(s=>{
  body+='<text class="hdr" x="4" y="'+(y+15)+'">'+esc(s.agent)+' · '+s.session_id+' · root '+esc(s.root_comm)+'</text>'; y+=HDR;
  const rowOfPid={};
  s.processes.forEach((p,i)=>{
   const yy=y+i*ROW; rowOfPid[p.pid]=yy;
   const indent=p.depth*12;
   body+='<text class="lbl" x="'+(4+indent)+'" y="'+(yy+13)+'">'+esc(p.label)+' · '+p.pid+(p.open_ended?' · still running':'')+'</text>';
   const x0=x(Math.max(p.start_ms,v0)),x1=x(Math.min(p.end_ms,v1));
   if(x1>x0&&p.end_ms>=v0&&p.start_ms<=v1){
    const tipText=p.label+'\npid '+p.pid+' ppid '+p.ppid+'\n'+(p.filename||'')+'\nargv: '+((p.argv||[]).join(' '))+'\ncwd: '+(p.cwd||'')+'\nstart +'+fmtDur(p.start_ms)+'  end +'+fmtDur(p.end_ms)+'  duration '+fmtDur(p.duration_ms)+(p.open_ended?'\nstill running at capture end':'');
    body+='<rect x="'+x0+'" y="'+(yy+3)+'" width="'+Math.max(2,x1-x0)+'" height="12" rx="3" fill="var(--bar)" opacity="'+(p.open_ended?0.55:0.9)+'" data-tip="'+esc(tipText)+'"><title>'+esc(tipText)+'</title></rect>';
   }
  });
  // markers on their process row (fall back to just below header)
  s.markers.forEach(m=>{
   if(m.offset_ms<v0||m.offset_ms>v1) return;
   const yy=(m.pid in rowOfPid)?rowOfPid[m.pid]:y-4;
   body+='<circle cx="'+x(m.offset_ms)+'" cy="'+(yy+9)+'" r="4" fill="'+(MARK[m.type]||OTHER)+'" stroke="var(--surface)" stroke-width="1" data-tip="'+esc(m.type+'\n'+m.detail+'\npid '+m.pid+'\nat +'+fmtDur(m.offset_ms))+'"><title>'+esc(m.type+' '+m.detail)+'</title></circle>';
  });
  // first-seen syscall diamonds (first interval this session used it)
  (s.first_seen_syscalls||[]).forEach(m=>{
   if(m.offset_ms<v0||m.offset_ms>v1) return;
   const yy=(m.pid in rowOfPid)?rowOfPid[m.pid]:y-4, cx=x(m.offset_ms), cy=yy+9;
   body+='<path d="M '+cx+' '+(cy-5)+' L '+(cx+5)+' '+cy+' L '+cx+' '+(cy+5)+' L '+(cx-5)+' '+cy+' Z" fill="#6250d6" stroke="var(--surface)" stroke-width="1" data-tip="'+esc('first seen: '+m.name+' ('+m.category+')\npid '+m.pid+'\nat +'+fmtDur(m.offset_ms))+'"><title>'+esc('first seen '+m.name)+'</title></path>';
  });
  y+=s.processes.length*ROW+8;
 });
 const svg=document.getElementById('tl');
 svg.setAttribute('viewBox','0 0 '+W+' '+y);
 svg.innerHTML=body;
 renderCharts(x,PW,LBL); renderTables();
}
function renderCharts(){
 const box=document.getElementById('charts'); box.innerHTML='';
 const [v0,v1]=view, span=Math.max(1,v1-v0);
 const showHidden=document.getElementById('showHidden').checked;
 const drillCat=drill.value;
 visible().forEach(s=>{
  const ser=drillCat==='categories'?s.syscall_series:(s.syscall_series_by_category||{})[drillCat];
  if(!ser){return;}
  // In category mode, memory + sync/wait stay hidden unless toggled.
  const idxs=ser.names.map((n,i)=>i).filter(i=>drillCat!=='categories'||showHidden||!HIDDEN[ser.names[i]]);
  if(!idxs.length){return;}
  const colorOf=i=>drillCat==='categories'?(CATCOLORS[ser.names[i]]||OTHER):(ser.names[i]==='other'?OTHER:COLORS[i%COLORS.length]);
  const h2=document.createElement('h2'); h2.textContent='Syscall rate — '+s.agent+' · '+s.session_id+' ('+(drillCat==='categories'?'by category':drillCat+' syscalls')+', per '+ser.bucket_ms+'ms bucket)'; box.appendChild(h2);
  const lg=document.createElement('div'); lg.className='legend';
  lg.innerHTML=idxs.map(i=>'<span><span class="sw" style="background:'+colorOf(i)+'"></span>'+esc(ser.names[i])+'</span>').join('');
  box.appendChild(lg);
  const W=1240,LBL=300,PW=W-LBL,H=180,PL=30;
  const x=ms=>LBL+(ms-v0)/span*PW;
  let max=1; ser.buckets.forEach(b=>{const t=idxs.reduce((a,i)=>a+(b.counts[i]||0),0); if(t>max)max=t;});
  let body='<line x1="'+LBL+'" y1="'+(H-PL)+'" x2="'+(LBL+PW)+'" y2="'+(H-PL)+'" stroke="var(--axis)"/><text class="muted lbl" x="4" y="16">max '+max+'/bucket</text>';
  ser.buckets.forEach(b=>{
   const bx=x(b.offset_ms), bw=Math.max(1,ser.bucket_ms/span*PW-1);
   if(b.offset_ms+ser.bucket_ms<v0||b.offset_ms>v1) return;
   let acc=0;
   idxs.forEach(i=>{
    const c=b.counts[i]||0; if(!c) return;
    const bh=c/max*(H-PL-10), yy=H-PL-acc/max*(H-PL-10)-bh;
    body+='<rect x="'+bx+'" y="'+yy+'" width="'+bw+'" height="'+bh+'" fill="'+colorOf(i)+'" data-tip="'+esc(ser.names[i]+': '+c+' at +'+fmtDur(b.offset_ms))+'"><title>'+esc(ser.names[i]+': '+c)+'</title></rect>';
    acc+=c;
   });
  });
  const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
  svg.setAttribute('viewBox','0 0 '+W+' '+H); svg.innerHTML=body; box.appendChild(svg);
 });
}
function table(title,head,rows){
 if(!rows||!rows.length) return '';
 return '<h3>'+esc(title)+'</h3><table><tr>'+head.map(h=>'<th>'+esc(h)+'</th>').join('')+'</tr>'+rows+'</table>';
}
function renderTables(){
 const box=document.getElementById('tables'); let out='';
 visible().forEach(s=>{
  out+='<h2>Breakdown — '+esc(s.agent)+' · '+s.session_id+' (root '+esc(s.root_comm)+')</h2>';
  out+=table('Top programs by exec count',['program','execs','wall time'],(s.top_programs_by_exec_count||[]).map(p=>'<tr><td>'+esc(p.name)+'</td><td class="n">'+p.exec_count+'</td><td class="n">'+fmtDur(p.total_ms)+'</td></tr>').join(''));
  out+=table('Top programs by wall time',['program','execs','wall time'],(s.top_programs_by_wall_time||[]).map(p=>'<tr><td>'+esc(p.name)+'</td><td class="n">'+p.exec_count+'</td><td class="n">'+fmtDur(p.total_ms)+'</td></tr>').join(''));
  if(s.syscall_distribution&&s.syscall_distribution.length){
   const tot=s.syscall_distribution.reduce((a,x)=>a+x.count,0);
   out+=table('Syscall distribution (total '+tot+')',['syscall','count','%'],s.syscall_distribution.map(x=>'<tr><td>'+esc(x.name)+'</td><td class="n">'+x.count+'</td><td class="n">'+x.percent.toFixed(1)+'%</td></tr>').join(''));
  } else { out+='<p class="sub">No syscall_summary data for this session.</p>'; }
  if(s.syscall_categories&&s.syscall_categories.length){
   out+='<h3>Syscall categories (expand to drill down)</h3>';
   s.syscall_categories.forEach(c=>{
    out+='<details><summary>'+esc(c.name)+' — '+c.count+' ('+c.percent.toFixed(1)+'%)</summary><table><tr><th>syscall</th><th>count</th><th>%</th></tr>'+(c.syscalls||[]).map(x=>'<tr><td>'+esc(x.name)+'</td><td class="n">'+x.count+'</td><td class="n">'+x.percent.toFixed(1)+'%</td></tr>').join('')+'</table></details>';
   });
  }
  out+=table('Notable syscalls (always shown)',['syscall','category','first seen','count'],(s.notable_syscalls||[]).map(n=>'<tr><td>'+esc(n.name)+'</td><td>'+esc(n.category)+'</td><td class="n">+'+fmtDur(n.first_seen_ms)+'</td><td class="n">'+n.count+'</td></tr>').join(''));
  out+=table('Syscalls by program',['program','pids','total','% of session','top categories'],(s.program_syscall_attribution||[]).map(p=>'<tr><td>'+esc(p.program)+'</td><td>'+esc((p.pids||[]).join(', '))+'</td><td class="n">'+p.total+'</td><td class="n">'+p.percent.toFixed(1)+'%</td><td>'+esc((p.categories||[]).slice(0,3).map(c=>c.name+' '+c.percent.toFixed(0)+'%').join(', '))+'</td></tr>').join(''));
  out+=table('Files touched (top paths)',['path','count'],(s.files_touched||[]).map(f=>'<tr><td>'+esc(f.path)+'</td><td class="n">'+f.count+'</td></tr>').join(''));
  out+=table('Network destinations',['destination','count','DNS'],(s.network_destinations||[]).map(n=>'<tr><td>'+esc(n.dest)+'</td><td class="n">'+n.count+'</td><td class="n">'+n.dns_count+'</td></tr>').join(''));
  if(s.marker_total>s.markers.length){out+='<p class="sub">Markers downsampled: showing '+s.markers.length+' of '+s.marker_total+' (evenly thinned). Breakdown counts above are exact.</p>';}
 });
 box.innerHTML=out;
}
filter.addEventListener('change',render);
document.getElementById('showHidden').addEventListener('change',render);
drill.addEventListener('change',render);
document.getElementById('zin').onclick=()=>{const c=(view[0]+view[1])/2,s=(view[1]-view[0])/4;view=[c-s,c+s];render();};
document.getElementById('zout').onclick=()=>{const c=(view[0]+view[1])/2,s=(view[1]-view[0]);view=[Math.max(0,c-s),c+s];render();};
document.getElementById('zreset').onclick=()=>{view=[0,Math.max(1,DATA.duration_ms||1)];render();};
const svgEl=document.getElementById('tl');
svgEl.addEventListener('mousemove',showTip);
svgEl.addEventListener('mouseleave',()=>tip.style.display='none');
document.getElementById('charts').addEventListener('mousemove',showTip);
let drag=null;
svgEl.addEventListener('mousedown',e=>{drag={x:e.clientX,v:view.slice()};});
window.addEventListener('mouseup',()=>drag=null);
window.addEventListener('mousemove',e=>{
 if(!drag) return;
 const rect=svgEl.getBoundingClientRect(), span=drag.v[1]-drag.v[0];
 const dms=-(e.clientX-drag.x)/rect.width*span;
 view=[Math.max(0,drag.v[0]+dms),Math.max(0,drag.v[0]+dms)+span]; render();
});
svgEl.addEventListener('wheel',e=>{
 e.preventDefault();
 const rect=svgEl.getBoundingClientRect();
 const frac=(e.clientX-rect.left)/rect.width, [v0,v1]=view, span=v1-v0;
 const at=v0+span*Math.min(1,Math.max(0,frac-300/1240)/(940/1240||1));
 const f=e.deltaY<0?0.8:1.25, ns=Math.max(10,span*f);
 view=[Math.max(0,at-(at-v0)/span*ns),Math.max(0,at-(at-v0)/span*ns)+ns]; render();
},{passive:false});
render();
</script>
</body></html>
`
