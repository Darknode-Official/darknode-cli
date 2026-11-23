"use strict";
// Nexus localhost dashboard (/open, /dashboard): a live, read-only window onto the
// running agent. It shows everything the TUI knows: the full conversation with
// thinking, every tool call with its input and output, a terminal log of every
// shell command (running ones stream), files read and changed with their diffs,
// sub-agents with their own conversations, background jobs with output, the
// per-turn cost ledger, the plan and the cowork pair.
//
// The server runs INSIDE the TUI process and reads closures, so it reflects real
// in-memory state. Bound to 127.0.0.1, Host and Origin checked, never framed.
// Read-only: there is no endpoint that changes anything.

const http = require("http");
const crypto = require("crypto");

const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nexus</title>
<style nonce="__NONCE__">
:root{--bg:#0b0e13;--panel:#11161d;--panel2:#161c25;--line:#232c38;--txt:#e5eaf0;--mut:#8a97a8;--acc:#5cc8ff;
  --ok:#4cc38a;--warn:#e8b54d;--bad:#f06b6b;--add:#16321f;--del:#3a1a1c;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;--sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.5 var(--sans)}
button,input{font:inherit;color:inherit}
header{position:sticky;top:0;z-index:5;background:var(--bg);border-bottom:1px solid var(--line)}
.hd{display:flex;align-items:center;gap:10px;padding:10px 20px;flex-wrap:wrap}
.brand{font-family:var(--mono);font-weight:700;letter-spacing:.08em}
.title{color:var(--mut);font-family:var(--mono);font-size:13px;max-width:36ch;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.chip{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border:1px solid var(--line);border-radius:6px;font:12px var(--mono);color:var(--mut);background:var(--panel);white-space:nowrap}
.chip b{color:var(--txt);font-weight:600}
.chip.work{border-color:#2c5a73;color:var(--acc)}.chip.work b{color:var(--acc)}
.sp{flex:1}
.dot{width:8px;height:8px;border-radius:50%;background:var(--bad)}.dot.on{background:var(--ok)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1px;background:var(--line);border-bottom:1px solid var(--line)}
.stat{background:var(--bg);padding:10px 20px}
.stat .k{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--mut)}
.stat .v{font:600 18px var(--mono)}.stat .v small{font-size:12px;color:var(--mut);font-weight:400}
nav{display:flex;gap:2px;padding:0 14px;border-bottom:1px solid var(--line);overflow-x:auto;background:var(--bg);position:sticky;top:var(--hdh,49px);z-index:4}
nav button{background:none;border:0;border-bottom:2px solid transparent;padding:10px 12px;color:var(--mut);cursor:pointer;white-space:nowrap;font-size:13px;font-weight:600}
nav button.on{color:var(--txt);border-bottom-color:var(--acc)}
nav button .n{font:11px var(--mono);color:var(--mut);margin-left:5px}
main{padding:16px 20px 60px;max-width:1500px;margin:0 auto}
.tools{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px;color:var(--mut);font-size:13px}
.tools input[type=search]{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:6px 10px;min-width:240px}
.tools label{display:inline-flex;gap:5px;align-items:center;cursor:pointer}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;margin-bottom:12px;overflow-x:auto}
.card>h3{margin:0;padding:10px 14px;font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--mut);border-bottom:1px solid var(--line)}
.card>.b{padding:12px 14px}
.empty{color:var(--mut);padding:10px 0}
.msg{margin:0 0 14px}
.who{font:600 11px var(--mono);letter-spacing:.06em;text-transform:uppercase;color:var(--mut);margin-bottom:4px}
.user .bubble{background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:10px 12px;white-space:pre-wrap;word-break:break-word}
.sys{color:var(--mut);font:12.5px var(--mono);white-space:pre-wrap;word-break:break-word;border-left:2px solid var(--line);padding-left:10px}
.text{white-space:pre-wrap;word-break:break-word;margin:4px 0 8px}
details.th,details.tl{border:1px solid var(--line);border-radius:6px;margin:6px 0;background:var(--panel)}
details>summary{cursor:pointer;padding:6px 10px;list-style:none;display:flex;gap:8px;align-items:center;font-size:13px;min-width:0}
details>summary::-webkit-details-marker{display:none}
details>summary .lb{font-family:var(--mono);font-size:12.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;min-width:0}
details.th>summary{color:var(--mut);font-style:italic}
details .in{padding:0 10px 10px}
.tag{font:11px var(--mono);padding:1px 7px;border-radius:4px;border:1px solid var(--line);color:var(--mut);flex:none}
.k-shell{color:#c9a3ff}.k-read{color:#7fb8ff}.k-edit{color:#ffb86b}.k-search{color:#8fd6c4}.k-web{color:#e6a6d8}.k-agent{color:#ffd76b}.k-mcp{color:#9fc4ff}
.st{font:11px var(--mono);flex:none}.st.done{color:var(--ok)}.st.running,.st.waiting{color:var(--acc)}.st.error{color:var(--bad)}.st.stopped{color:var(--warn)}
.dur{font:11px var(--mono);color:var(--mut);flex:none}
pre{margin:6px 0 0;font:12px/1.45 var(--mono);white-space:pre-wrap;word-break:break-word;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px 10px;max-height:480px;overflow:auto}
.sub{font:11px var(--mono);color:var(--mut);margin-top:8px;text-transform:uppercase;letter-spacing:.05em}
.diff{font:12px/1.4 var(--mono);background:var(--bg);border:1px solid var(--line);border-radius:6px;margin-top:6px;max-height:480px;overflow:auto}
.diff div{white-space:pre-wrap;word-break:break-word;padding:0 10px}
.diff .a{background:var(--add)}.diff .d{background:var(--del)}.diff .ln{color:var(--mut);display:inline-block;min-width:4ch;margin-right:8px;text-align:right}
.term{background:#07090c;border:1px solid var(--line);border-radius:8px;padding:12px 14px;font:12.5px/1.5 var(--mono)}
.term .cmd{color:#e5eaf0;margin-top:12px;white-space:pre-wrap;word-break:break-word}.term .cmd:first-child{margin-top:0}
.term .cmd .pr{color:var(--ok)}.term .cmd .by{color:var(--mut);font-size:11px;margin-left:8px}
.term .out{color:#aab4c2;white-space:pre-wrap;word-break:break-word;max-height:none}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--mut);font-weight:600}
td.num,th.num{text-align:right;font-family:var(--mono);white-space:nowrap}
td.mono{font-family:var(--mono);font-size:12.5px;word-break:break-all}
tr.pick{cursor:pointer}tr.pick:hover td{background:var(--panel2)}tr.sel td{background:var(--panel2)}
.ev{display:flex;gap:8px;align-items:center;padding:6px 0;border-bottom:1px solid var(--line);cursor:pointer;min-width:0}
.ev:last-child{border-bottom:0}.ev .lb{font:12.5px var(--mono);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ev .t{font:11px var(--mono);color:var(--mut);flex:none}
.grid2{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(0,1fr);gap:12px}
@media(max-width:900px){.grid2{grid-template-columns:minmax(0,1fr)}.hd,.stat,main{padding-left:12px;padding-right:12px}}
.plan div{padding:5px 0;border-bottom:1px solid var(--line)}.plan .done{color:var(--mut);text-decoration:line-through}
.flash{outline:2px solid var(--acc);outline-offset:2px}
</style>
</head>
<body>
<header><div class="hd" id="hd">
  <span class="brand">NEXUS</span><span class="title" id="title"></span>
  <span class="chip" id="status"><b>idle</b></span>
  <span class="chip" id="model"><span>model</span><b>-</b></span>
  <span class="chip" id="mode"><span>mode</span><b>-</b></span>
  <span class="chip" id="dir"><span>dir</span><b>-</b></span>
  <span class="sp"></span>
  <span class="chip"><span class="dot" id="dot"></span><span id="conn">connecting</span></span>
</div>
<div class="stats" id="stats"></div></header>
<nav id="tabs"></nav>
<main id="main"></main>
<script nonce="__NONCE__">
(function(){
var $=function(id){return document.getElementById(id)};
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]})}
function k(n){n=+n||0;return n<1000?String(n):n<1e6?(n/1e3).toFixed(n<1e4?1:0)+"k":(n/1e6).toFixed(1)+"m"}
function dur(ms){var s=Math.max(0,Math.round(ms/1000));if(s<60)return s+"s";var m=Math.floor(s/60);if(m<60)return m+"m "+(s%60)+"s";return Math.floor(m/60)+"h "+(m%60)+"m"}
function usd(n){n=+n||0;return "$"+(n<1?n.toFixed(4):n.toFixed(2))}
function clock(t){return t?new Date(t).toLocaleTimeString():""}
var TABS=[["live","Live"],["conversation","Conversation"],["terminal","Terminal"],["files","Files"],["agents","Agents"],["jobs","Jobs"],["cost","Cost"],["session","Plan & session"]];
var tab=(location.hash||"").slice(1);if(!TABS.some(function(t){return t[0]===tab}))tab="live";
var S=null,D=null,rev=null,open={},q="",showThink=true,showOut=true,follow=true,selFile="",selJob="",jobOut=null,lastFetch=0,pending=false;
function counts(){if(!D)return{};var tools=0;D.conversation.forEach(function(m){(m.items||[]).forEach(function(i){if(i.type==="tool")tools++})});return{conversation:tools,terminal:D.terminal.length,files:D.files.files.length,agents:D.agents.length,jobs:S&&S.jobs?S.jobs.length:0,cost:D.turns.length}}
function drawTabs(){var c=counts();$("tabs").innerHTML=TABS.map(function(t){var n=c[t[0]];return '<button data-t="'+t[0]+'" class="'+(t[0]===tab?"on":"")+'">'+t[1]+(n?'<span class="n">'+n+'</span>':"")+'</button>'}).join("")}
$("tabs").addEventListener("click",function(e){var b=e.target.closest("button");if(!b)return;tab=b.dataset.t;history.replaceState(null,"","#"+tab);window.scrollTo(0,0);drawTabs();draw()});
window.addEventListener("hashchange",function(){var t=location.hash.slice(1);if(TABS.some(function(x){return x[0]===t})){tab=t;drawTabs();draw()}});

function head(){if(!S)return;
  $("title").textContent=S.title||"";document.title=(S.busy?"Working · ":"")+(S.title?S.title+" · ":"")+"Nexus";
  var st=$("status");st.className="chip"+(S.busy?" work":"");st.innerHTML=S.busy?"<b>"+esc(S.busyWord||"Working")+"</b><span>"+dur(S.busyFor*1000)+"</span>":"<b>idle</b>";
  $("model").querySelector("b").textContent=S.engine+(S.model&&S.model!==S.engine?" · "+S.model:"");
  $("mode").querySelector("b").textContent=S.mode||"-";$("dir").querySelector("b").textContent=S.dir||"-";
  var pct=S.ctxWindow?Math.min(100,Math.round(S.ctxUsed/S.ctxWindow*100)):0,c=S.cache||{},cache="-";
  if(c.ttl&&c.lastAt){var left=c.lastAt+c.ttl-S.now;cache=left>0?dur(left)+" <small>warm</small>":"cold <small>rebuilds</small>"}
  var x=[["Turns",(S.turns||0)],["Tokens","&uarr;"+k(S.inTok)+" <small>&darr;"+k(S.outTok)+"</small>"],["Cost",S.paid?usd(S.cost):"free <small>local</small>"],["Context",pct+"<small>% of "+k(S.ctxWindow)+"</small>"],["Prompt cache",cache],["Tool calls",S.toolCalls||0],["Files changed",(S.files||[]).length],["Running",(S.running||0)+"<small> shell"+(S.running===1?"":"s")+"</small> "+(S.agents||0)+"<small> agent"+(S.agents===1?"":"s")+"</small>"],["Uptime",dur((S.elapsed||0)*1000)]];
  $("stats").innerHTML=x.map(function(a){return'<div class="stat"><div class="k">'+a[0]+'</div><div class="v">'+a[1]+'</div></div>'}).join("");
  document.documentElement.style.setProperty("--hdh",$("hd").offsetHeight+$("stats").offsetHeight+"px");
}
function stx(i){var d=i.end?i.end-i.start:i.start?S.now-i.start:0;return'<span class="st '+i.status+'">'+i.status+'</span>'+(d>0?'<span class="dur">'+dur(d)+'</span>':"")}
function diffHTML(d){return'<div class="diff">'+d.rows.map(function(r){return'<div class="'+(r[0]==="+"?"a":r[0]==="-"?"d":"")+'"><span class="ln">'+(r[2]||"")+'</span>'+esc(r[0]+" "+r[1])+'</div>'}).join("")+(d.more?'<div>… '+d.more+' more lines</div>':"")+'</div>'}
function toolHTML(i,key){var id=key+":"+i.id,body="";
  if(i.command)body+='<div class="sub">Command</div><pre>'+esc(i.command)+'</pre>';else if(i.input)body+='<div class="sub">Input</div><pre>'+esc(i.input)+'</pre>';
  if(i.diff)body+='<div class="sub">Change +'+i.diff.added+' -'+i.diff.removed+'</div>'+diffHTML(i.diff);
  if(showOut&&(i.output||i.live))body+='<div class="sub">'+(i.live?"Output so far":"Output")+'</div><pre>'+esc(i.output||"(nothing yet)")+'</pre>';
  return'<details class="tl" data-id="'+esc(id)+'"'+(open[id]||i.status==="running"&&i.live?" open":"")+'><summary><span class="tag k-'+i.kind+'">'+i.kind+'</span><span class="lb">'+esc(i.label)+'</span>'+stx(i)+'</summary><div class="in">'+body+'</div></details>'}
function itemsHTML(items,key){return items.map(function(i,n){
  if(i.type==="text")return'<div class="text">'+esc(i.text)+'</div>';
  if(i.type==="thinking"){if(!showThink)return"";var id=key+":th"+n;return'<details class="th" data-id="'+esc(id)+'"'+(open[id]?" open":"")+'><summary>Thinking ('+k(i.text.length)+' chars)</summary><div class="in"><pre>'+esc(i.text)+'</pre></div></details>'}
  return toolHTML(i,key)}).join("")}
function match(m){if(!q)return true;var s=JSON.stringify(m).toLowerCase();return s.indexOf(q)>=0}
function bar(extra){return'<div class="tools"><input type="search" id="q" placeholder="Search" value="'+esc(q)+'"><label><input type="checkbox" id="th"'+(showThink?" checked":"")+'>thinking</label><label><input type="checkbox" id="ou"'+(showOut?" checked":"")+'>tool output</label><label><input type="checkbox" id="fo"'+(follow?" checked":"")+'>follow newest</label>'+(extra||"")+'</div>'}

var V={};
V.live=function(){
  var run=[],ev=[];D.conversation.forEach(function(m){(m.items||[]).forEach(function(i){if(i.type==="tool"){ev.push({i:i,m:m.i});if(i.status==="running"||i.status==="waiting")run.push(i)}})});
  D.agents.forEach(function(a){a.items.forEach(function(i){if(i.type==="tool"&&(i.status==="running"))run.push(i)})});
  var last=null;for(var x=D.conversation.length-1;x>=0&&!last;x--){var m=D.conversation[x];if(m.role==="assistant")for(var y=m.items.length-1;y>=0;y--)if(m.items[y].type==="text"){last=m.items[y].text;break}}
  var now=run.length?run.map(function(i){return toolHTML(i,"now")}).join(""):'<div class="empty">'+(S.busy?esc(S.busyWord||"Working")+": thinking or writing.":"Idle. Nothing is running.")+'</div>';
  var lastPrompt="";for(var z=D.conversation.length-1;z>=0;z--)if(D.conversation[z].role==="user"){lastPrompt=D.conversation[z].text;break}
  return'<div class="grid2"><div><div class="card"><h3>Running now</h3><div class="b">'+now+'</div></div>'
    +(lastPrompt?'<div class="card"><h3>Last prompt</h3><div class="b"><div class="text">'+esc(lastPrompt.slice(0,1500))+'</div></div></div>':"")
    +'<div class="card"><h3>Latest answer</h3><div class="b">'+(last?'<div class="text">'+esc(last.slice(-4000))+'</div>':'<div class="empty">No answer yet.</div>')+'</div></div></div>'
    +'<div class="card"><h3>Activity, newest first</h3><div class="b">'+(ev.length?ev.slice(-150).reverse().map(function(e){return'<div class="ev" data-go="'+e.m+":"+esc(e.i.id)+'"><span class="tag k-'+e.i.kind+'">'+e.i.kind+'</span><span class="lb">'+esc(e.i.label)+'</span>'+stx(e.i)+'<span class="t">'+clock(e.i.start)+'</span></div>'}).join(""):'<div class="empty">No tool calls yet.</div>')+'</div></div></div>'};
V.conversation=function(){var ms=D.conversation.filter(match);
  return bar()+(ms.length?ms.map(function(m){
    if(m.role==="user")return'<div class="msg user" id="m'+m.i+'"><div class="who">You</div><div class="bubble">'+esc(m.text)+'</div></div>';
    if(m.role==="system")return'<div class="msg" id="m'+m.i+'"><div class="sys">'+esc(m.text)+'</div></div>';
    return'<div class="msg" id="m'+m.i+'"><div class="who">Nexus</div>'+itemsHTML(m.items,"m"+m.i)+'</div>'}).join(""):'<div class="empty">'+(q?"Nothing matches.":"No conversation yet.")+'</div>')};
V.terminal=function(){var rs=D.terminal.filter(match);
  return bar()+(rs.length?'<div class="term">'+rs.map(function(r){return'<div class="cmd"><span class="pr">$</span> '+esc(r.command)+'<span class="by">'+(r.by==="you"?"you, with !":"agent")+(r.status&&r.status!=="done"?" · "+r.status:"")+(r.end&&r.start?" · "+dur(r.end-r.start):"")+'</span></div>'+(showOut?'<div class="out">'+esc(r.output||(r.status==="running"?"(running)":"(no output)"))+'</div>':"")}).join("")+'</div>':'<div class="empty">'+(q?"Nothing matches.":"No shell commands yet.")+'</div>')};
V.files=function(){var f=D.files,rows=f.files.filter(function(x){return!q||x.path.toLowerCase().indexOf(q)>=0});var diffs="";
  if(selFile){D.conversation.forEach(function(m){(m.items||[]).forEach(function(i){if(i.type==="tool"&&i.file===selFile&&i.diff)diffs+='<div class="sub">'+esc(i.label)+' · '+clock(i.start)+'</div>'+diffHTML(i.diff)})})}
  return'<div class="tools"><input type="search" id="q" placeholder="Filter files" value="'+esc(q)+'"><span>'+f.files.length+' file'+(f.files.length===1?'':'s')+' touched · click one to see its changes</span></div>'
  +'<div class="grid2"><div class="card"><h3>Files</h3>'+(rows.length?'<table><thead><tr><th>Path</th><th class="num">Reads</th><th class="num">Edits</th><th class="num">Last</th></tr></thead><tbody>'+rows.map(function(x){return'<tr class="pick'+(x.path===selFile?" sel":"")+'" data-f="'+esc(x.path)+'"><td class="mono">'+esc(x.path)+'</td><td class="num">'+x.read+'</td><td class="num">'+x.edit+'</td><td class="num">'+clock(x.last)+'</td></tr>'}).join("")+'</tbody></table>':'<div class="b empty">No files read or changed yet.</div>')+'</div>'
  +'<div><div class="card"><h3>'+(selFile?esc(selFile):"Changes")+'</h3><div class="b">'+(selFile?(diffs||'<div class="empty">Read only: no edits to this file.</div>'):'<div class="empty">Pick a file.</div>')+'</div></div>'
  +'<div class="card"><h3>Searches</h3><div class="b">'+(f.searches.length?f.searches.slice().reverse().map(function(s){return'<div class="ev"><span class="lb">'+esc(s.label)+'</span><span class="st '+s.status+'">'+s.status+'</span></div>'}).join(""):'<div class="empty">None.</div>')+'</div></div>'
  +'<div class="card"><h3>Web</h3><div class="b">'+(f.web.length?f.web.slice().reverse().map(function(s){return'<div class="ev"><span class="lb">'+esc(s.label)+'</span><span class="st '+s.status+'">'+s.status+'</span></div>'}).join(""):'<div class="empty">None.</div>')+'</div></div></div></div>'};
V.agents=function(){return D.agents.length?D.agents.slice().reverse().map(function(a){var id="ag:"+a.id;return'<details class="tl" data-id="'+esc(id)+'"'+(open[id]?" open":"")+'><summary><span class="tag k-agent">agent</span><span class="lb">'+esc(a.task)+'</span>'+stx({status:a.status==="run"?"running":a.status==="ok"?"done":a.status==="fail"?"error":a.status,start:a.start,end:a.end})+'</summary><div class="in">'+(a.prompt?'<div class="sub">Brief</div><pre>'+esc(a.prompt)+'</pre>':"")+(a.items.length?'<div class="sub">Its work</div>'+itemsHTML(a.items,"a"+a.id):"")+(a.result?'<div class="sub">Result</div><pre>'+esc(a.result)+'</pre>':"")+'</div></details>'}).join(""):'<div class="empty">No sub-agents this session.</div>'};
V.jobs=function(){var js=(S&&S.jobs)||[];return js.length?'<div class="grid2"><div class="card"><h3>Background jobs</h3><table><thead><tr><th>Status</th><th>Command</th><th class="num">Output</th></tr></thead><tbody>'+js.map(function(j){return'<tr class="pick'+(j.id===selJob?" sel":"")+'" data-j="'+esc(j.id)+'"><td><span class="st '+(j.status==="running"?"running":j.status==="done"?"done":"error")+'">'+esc(j.status)+(j.code!=null?" "+j.code:"")+'</span></td><td class="mono">'+esc(j.command)+'</td><td class="num">'+k(j.bytes)+'B</td></tr>'}).join("")+'</tbody></table></div><div class="card"><h3>Output</h3><div class="b">'+(selJob?'<pre>'+esc(jobOut==null?"loading":jobOut||"(no output yet)")+'</pre>':'<div class="empty">Pick a job.</div>')+'</div></div></div>':'<div class="empty">No background jobs. The agent starts them with run_background.</div>'};
V.cost=function(){var t=D.turns;if(!t.length)return'<div class="empty">No finished turns yet.</div>';var ti=0,to=0,tc=0,tr=0;t.forEach(function(r){ti+=r.inTok;to+=r.outTok;tc+=r.cost;tr+=r.cacheRead||0});
  return'<div class="card"><h3>Per turn, at list prices</h3><table><thead><tr><th>Time</th><th>Prompt</th><th>Model</th><th class="num">In</th><th class="num">Cache read</th><th class="num">Out</th><th class="num">Took</th><th class="num">Cost</th></tr></thead><tbody>'+t.slice().reverse().map(function(r){return'<tr><td class="num">'+clock(r.t)+'</td><td>'+esc(r.label)+'</td><td class="mono">'+esc(r.model)+'</td><td class="num">'+k(r.inTok)+'</td><td class="num">'+k(r.cacheRead||0)+'</td><td class="num">'+k(r.outTok)+'</td><td class="num">'+dur((r.dt||0)*1000)+'</td><td class="num">'+(r.paid?usd(r.cost):"free")+'</td></tr>'}).join("")+'<tr><td></td><td><b>Total, '+t.length+' turns</b></td><td></td><td class="num">'+k(ti)+'</td><td class="num">'+k(tr)+'</td><td class="num">'+k(to)+'</td><td></td><td class="num"><b>'+usd(tc)+'</b></td></tr></tbody></table></div>'};
V.session=function(){var p=S.plan||[],cw=S.cowork||{},tl=S.tools||[];
  return'<div class="grid2"><div><div class="card"><h3>Plan '+(p.length?p.filter(function(x){return x.done}).length+"/"+p.length:"")+'</h3><div class="b plan">'+(p.length?p.map(function(x){return'<div class="'+(x.done?"done":"")+'">'+(x.running?"&rarr; ":"")+esc(x.text)+'</div>'}).join(""):'<div class="empty">No plan. /plan builds one.</div>')+'</div></div>'
  +'<div class="card"><h3>Cowork</h3><div class="b">'+(cw.on?'Strong <b>'+esc(cw.strong)+'</b> &rarr; worker <b>'+esc(cw.weak)+'</b> ('+esc(cw.weakKind)+'), '+((S.impact&&S.impact.delegated)||0)+' turns delegated, saved '+usd((S.impact&&S.impact.coworkSaved)||0):'<span class="empty">Off. /cowork &lt;strong&gt; &lt;weak&gt; pairs two models.</span>')+'</div></div>'
  +'<div class="card"><h3>Pipelines</h3><div class="b">'+(S.pipelines&&S.pipelines.text?'<pre>'+esc(S.pipelines.text)+'</pre>':'<div class="empty">No pipeline activity.</div>')+'</div></div></div>'
  +'<div class="card"><h3>Tools used</h3>'+(tl.length?'<table><tbody>'+tl.map(function(t){return'<tr><td class="mono">'+esc(t.name)+'</td><td class="num">'+t.n+'</td></tr>'}).join("")+'</tbody></table>':'<div class="b empty">None yet.</div>')+'</div></div>'};

function draw(){if(!S)return;head();var mn=$("main");if(!D){mn.innerHTML='<div class="empty">Loading the session.</div>';return}
  var atBottom=window.innerHeight+window.scrollY>=document.body.scrollHeight-80,y=window.scrollY,qf=document.activeElement&&document.activeElement.id==="q",cp=qf?document.activeElement.selectionStart:0;
  mn.innerHTML=V[tab]();
  if(qf){var qi=$("q");if(qi){qi.focus();try{qi.setSelectionRange(cp,cp)}catch(_){}}}
  if((tab==="conversation"||tab==="terminal")&&follow&&atBottom)window.scrollTo(0,document.body.scrollHeight);else window.scrollTo(0,y)}
var mn=$("main");
mn.addEventListener("toggle",function(e){var d=e.target;if(d.dataset&&d.dataset.id)open[d.dataset.id]=d.open},true);
mn.addEventListener("input",function(e){if(e.target.id==="q"){q=e.target.value.trim().toLowerCase();draw()}});
mn.addEventListener("change",function(e){var id=e.target.id;if(id==="th")showThink=e.target.checked;else if(id==="ou")showOut=e.target.checked;else if(id==="fo")follow=e.target.checked;else return;draw()});
mn.addEventListener("click",function(e){var f=e.target.closest("[data-f]");if(f){selFile=f.dataset.f;draw();return}
  var j=e.target.closest("[data-j]");if(j){selJob=j.dataset.j;jobOut=null;draw();loadJob();return}
  var g=e.target.closest("[data-go]");if(g){var p=g.dataset.go.split(":"),mi=p.shift(),tid=p.join(":");open["m"+mi+":"+tid]=true;tab="conversation";history.replaceState(null,"","#conversation");q="";drawTabs();draw();var el=document.querySelector('[data-id="m'+mi+':'+CSS.escape(tid)+'"]');if(el){el.scrollIntoView({block:"center"});el.classList.add("flash");setTimeout(function(){el.classList.remove("flash")},1200)}}});
function loadJob(){if(!selJob)return;fetch("/api/job?id="+encodeURIComponent(selJob)).then(function(r){return r.json()}).then(function(j){jobOut=j&&j.output!=null?j.output:"(job not found)";if(tab==="jobs")draw()}).catch(function(){})}
function loadDetail(){var t=Date.now();if(pending)return;if(t-lastFetch<600){setTimeout(loadDetail,600-(t-lastFetch));return}pending=true;lastFetch=t;
  fetch("/api/detail").then(function(r){return r.json()}).then(function(d){D=d;pending=false;drawTabs();draw()}).catch(function(){pending=false})}
function onState(s){S=s;$("dot").className="dot on";$("conn").textContent="live";if(s.rev!==rev){rev=s.rev;loadDetail()}else{head();if(tab==="live"||tab==="jobs"||tab==="session")draw()}if(selJob&&tab==="jobs")loadJob()}
drawTabs();
if(window.EventSource){var es=new EventSource("/api/stream");es.onmessage=function(e){try{onState(JSON.parse(e.data))}catch(_){}};es.onerror=function(){$("dot").className="dot";$("conn").textContent="reconnecting: is Nexus still open?"}}
else setInterval(function(){fetch("/api/state").then(function(r){return r.json()}).then(onState).catch(function(){})},1500);
})();
</script>
</body>
</html>`;

function sseFrame(obj) { return "data: " + JSON.stringify(obj).replace(/\n/g, "\\n") + "\n\n"; }

// opts.getState(): light snapshot sent every second (must include `rev`).
// opts.getDetail(): heavy snapshot (conversation, terminal, files, agents, turns),
//   fetched by the page only when rev changes.
// opts.getJob(id): { id, output } for one background job, or null.
// Returns a Promise<{ url, port, server, close }>.
function startDashboard(opts) {
  opts = opts || {};
  const call = (f, d, a) => { try { return (typeof f === "function" ? f(a) : null) || d; } catch (_) { return d; } };
  const host = "127.0.0.1", first = opts.port || 7979, tries = 25;

  const makeServer = () => http.createServer((req, res) => {
    const u = new URL(req.url || "/", "http://x"), url = u.pathname;
    if (req.method !== "GET") { res.writeHead(405); res.end(); return; }
    // Loopback stops other machines, not other pages in the user's own browser: any
    // site could read this session cross-origin or via DNS rebinding. Serve only
    // requests addressed to this loopback port, from this origin; no CORS.
    const port = req.socket.localPort, okHosts = ["127.0.0.1:" + port, "localhost:" + port];
    if (!okHosts.includes(String(req.headers.host || "").toLowerCase())) { res.writeHead(403); res.end(); return; }
    const origin = req.headers.origin;
    if (origin && !okHosts.some((h) => origin.toLowerCase() === "http://" + h)) { res.writeHead(403); res.end(); return; }
    const json = (obj) => { res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" }); res.end(JSON.stringify(obj)); };

    if (url === "/" || url === "/index.html") {
      const nonce = crypto.randomBytes(16).toString("base64");
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'none'; script-src 'nonce-" + nonce + "'; style-src 'nonce-" + nonce + "'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
      });
      res.end(PAGE.replace(/__NONCE__/g, nonce));
      return;
    }
    if (url === "/favicon.ico") {
      res.writeHead(200, { "Content-Type": "image/svg+xml", "Cache-Control": "max-age=86400" });
      res.end('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#11161d"/><path d="M9 23V9h3l8 10V9h3v14h-3l-8-10v10z" fill="#5cc8ff"/></svg>');
      return;
    }
    if (url === "/api/state") return json(call(opts.getState, {}));
    if (url === "/api/detail") return json(call(opts.getDetail, { conversation: [], terminal: [], files: { files: [], searches: [], web: [] }, agents: [], turns: [] }));
    if (url === "/api/job") return json(call(opts.getJob, { output: null }, String(u.searchParams.get("id") || "")));
    if (url === "/api/stream") {
      res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-store", "Connection": "keep-alive" });
      const tick = () => { try { res.write(sseFrame(call(opts.getState, {}))); } catch (_) {} };
      tick();
      const iv = setInterval(tick, 1000);
      req.on("close", () => clearInterval(iv));
      return;
    }
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end('{"error":"not found"}');
  });

  return new Promise((resolve, reject) => {
    let attempt = 0;
    const tryListen = (port) => {
      const server = makeServer();
      server.on("error", (e) => { if (e && e.code === "EADDRINUSE" && attempt < tries) { attempt++; tryListen(first + attempt); } else reject(e); });
      server.listen(port, host, () => resolve({ url: "http://" + host + ":" + port, port, server, close: () => { try { server.close(); } catch (_) {} } }));
    };
    tryListen(first);
  });
}

module.exports = { startDashboard, PAGE };
