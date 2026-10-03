"use strict";
// Nexus localhost dashboard — a live web view of the running agent: pipelines,
// background jobs, the cowork pair, the current plan, and token/cost telemetry.
//
// Unlike lib/cli/api-server.js (a separate process that shells out and therefore
// cannot see live state), this server is started FROM INSIDE the TUI process and
// reads a getState() closure, so every request reflects the real in-memory jobs,
// cowork pairing, plan and counters. Bound to 127.0.0.1 only (private, no auth).

const http = require("http");

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// ---- the page (self-contained: no external fonts, scripts or network) ----
const PAGE = `<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nexus Dashboard</title>
<style>
  :root{
    --bg:#070a0f; --panel:#0e141c; --panel2:#111a24; --line:#1d2a38;
    --txt:#e6edf5; --mut:#8595a8; --acc:#32d6ff; --acc2:#a176ff;
    --ok:#3ad29f; --warn:#ffcc66; --bad:#ff6b6b; --run:#32d6ff;
    --mono:ui-monospace,"SFMono-Regular",Menlo,Consolas,"Liberation Mono",monospace;
    --sans:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
  }
  *{box-sizing:border-box}
  html,body{margin:0;background:var(--bg);color:var(--txt);font-family:var(--sans);
    font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
  body{padding:0 0 48px}
  a{color:var(--acc);text-decoration:none}
  .wrap{max-width:1180px;margin:0 auto;padding:0 20px}
  header{position:sticky;top:0;z-index:5;background:linear-gradient(180deg,rgba(7,10,15,.96),rgba(7,10,15,.86));
    backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
  .hd{display:flex;align-items:center;gap:14px;padding:14px 0}
  .logo{font-family:var(--mono);font-weight:800;letter-spacing:.14em;font-size:15px;
    background:linear-gradient(90deg,var(--acc),var(--acc2));-webkit-background-clip:text;
    background-clip:text;-webkit-text-fill-color:transparent}
  .hd .sep{flex:1}
  .pill{display:inline-flex;align-items:center;gap:7px;padding:4px 11px;border:1px solid var(--line);
    border-radius:999px;font-family:var(--mono);font-size:12px;color:var(--mut);background:var(--panel)}
  .pill b{color:var(--txt);font-weight:600}
  .dot{width:8px;height:8px;border-radius:50%;background:var(--bad);box-shadow:0 0 0 0 rgba(58,210,159,.5)}
  .dot.live{background:var(--ok);animation:pulse 2s infinite}
  @keyframes pulse{0%{box-shadow:0 0 0 0 rgba(58,210,159,.45)}70%{box-shadow:0 0 0 7px rgba(58,210,159,0)}100%{box-shadow:0 0 0 0 rgba(58,210,159,0)}}
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}
  .stat{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
  .stat .k{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut)}
  .stat .v{font-family:var(--mono);font-size:22px;font-weight:700;margin-top:4px}
  .stat .v small{font-size:12px;color:var(--mut);font-weight:500}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  @media(max-width:860px){.grid{grid-template-columns:1fr}}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:14px;overflow:hidden}
  .card.span{grid-column:1 / -1}
  .card h2{margin:0;padding:13px 16px;font-size:13px;letter-spacing:.06em;text-transform:uppercase;
    color:var(--mut);border-bottom:1px solid var(--line);display:flex;align-items:center;gap:9px}
  .card h2 .tag{font-family:var(--mono);font-size:11px;color:var(--acc);text-transform:none;letter-spacing:0}
  .card .body{padding:14px 16px}
  .empty{color:var(--mut);font-size:13px;padding:8px 0}
  .row{display:flex;align-items:center;gap:10px;padding:9px 0;border-bottom:1px solid var(--line)}
  .row:last-child{border-bottom:0}
  .row .mono{font-family:var(--mono);font-size:12.5px}
  .row .grow{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .badge{font-family:var(--mono);font-size:11px;padding:2px 8px;border-radius:999px;border:1px solid var(--line);color:var(--mut)}
  .badge.ok{color:var(--ok);border-color:rgba(58,210,159,.4)}
  .badge.run{color:var(--run);border-color:rgba(50,214,255,.4)}
  .badge.killed,.badge.bad{color:var(--bad);border-color:rgba(255,107,107,.4)}
  .badge.warn{color:var(--warn);border-color:rgba(255,204,102,.4)}
  .plan-item{display:flex;gap:10px;align-items:flex-start;padding:8px 0;border-bottom:1px solid var(--line)}
  .plan-item:last-child{border-bottom:0}
  .chk{width:17px;height:17px;border-radius:5px;border:1.5px solid var(--line);flex:none;margin-top:1px;
    display:flex;align-items:center;justify-content:center;font-size:11px;color:var(--bg)}
  .chk.done{background:var(--ok);border-color:var(--ok)}
  .chk.run{border-color:var(--run);color:var(--run)}
  .plan-item.done .t{color:var(--mut);text-decoration:line-through}
  .cowork{display:flex;gap:12px;flex-wrap:wrap}
  .node{flex:1;min-width:140px;background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:12px}
  .node .role{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--mut)}
  .node .m{font-family:var(--mono);font-size:13px;margin-top:4px;word-break:break-all}
  .arrow{align-self:center;color:var(--acc2);font-family:var(--mono)}
  pre.log{margin:0;font-family:var(--mono);font-size:12px;color:var(--mut);white-space:pre-wrap;
    word-break:break-word;max-height:260px;overflow:auto}
  .bar{height:6px;border-radius:4px;background:var(--line);overflow:hidden;margin-top:8px}
  .bar>span{display:block;height:100%;background:linear-gradient(90deg,var(--acc),var(--acc2));transition:width .3s}
  footer{color:var(--mut);font-size:12px;text-align:center;margin-top:26px;font-family:var(--mono)}
</style>
</head>
<body>
<header><div class="wrap hd">
  <span class="logo">DARKNODE / NEXUS</span>
  <span class="pill" id="p-engine"><span>engine</span><b>&mdash;</b></span>
  <span class="pill" id="p-dir"><span>dir</span><b>&mdash;</b></span>
  <span class="sep"></span>
  <span class="pill"><span class="dot" id="live"></span><span id="conn">connecting</span></span>
</div></header>

<div class="wrap">
  <div class="stats" id="stats"></div>
  <div class="grid">
    <div class="card"><h2>Plan <span class="tag" id="plan-n"></span></h2><div class="body" id="plan"></div></div>
    <div class="card"><h2>Cowork <span class="tag" id="cowork-tag"></span></h2><div class="body" id="cowork"></div></div>
    <div class="card"><h2>Background jobs <span class="tag" id="jobs-n"></span></h2><div class="body" id="jobs"></div></div>
    <div class="card"><h2>Pipelines <span class="tag" id="pipe-tag"></span></h2><div class="body" id="pipelines"></div></div>
    <div class="card span"><h2>Recent activity</h2><div class="body"><pre class="log" id="activity"></pre></div></div>
  </div>
  <footer id="foot">Nexus dashboard &middot; localhost only</footer>
</div>

<script>
(function(){
  var $=function(id){return document.getElementById(id)};
  var liveDot=$("live"), conn=$("conn"); var misses=0;
  function fmtK(n){n=+n||0; if(n<1000)return String(n); if(n<1e6)return (n/1e3).toFixed(n<1e4?1:0)+"k"; return (n/1e6).toFixed(1)+"m";}
  function badge(s){s=(s||"").toLowerCase(); if(s==="done"||s==="ok")return "ok"; if(s==="running"||s==="run")return "run"; if(s==="killed"||s==="error"||s==="bad")return "killed"; return "";}
  function setLive(on){ liveDot.className="dot"+(on?" live":""); conn.textContent=on?"live":"reconnecting"; }

  function render(s){
    if(!s)return;
    $("p-engine").querySelector("b").textContent = s.engine + (s.model && s.model!==s.engine ? " · "+s.model : "");
    $("p-dir").querySelector("b").textContent = s.dir || "—";
    document.title = "Nexus · " + s.engine;

    // stats
    var ctxPct = s.ctxWindow ? Math.min(100, Math.round(s.ctxUsed/s.ctxWindow*100)) : 0;
    var cost = s.paid ? ("$"+(s.cost||0).toFixed(4)) : "free";
    var stats=[
      ["Tokens", "<span class=v>&uarr;"+fmtK(s.inTok)+" <small>&darr;"+fmtK(s.outTok)+"</small></span>"],
      ["Cost", "<span class=v>"+cost+" <small>"+(s.paid?"billed":"local")+"</small></span>"],
      ["Context", "<span class=v>"+ctxPct+"<small>% of "+fmtK(s.ctxWindow)+"</small></span><div class=bar><span style='width:"+ctxPct+"%'></span></div>"],
      ["Jobs running", "<span class=v>"+(s.jobsRunning||0)+" <small>of "+(s.jobs?s.jobs.length:0)+"</small></span>"],
      ["Agents", "<span class=v>"+(s.agents||0)+" <small>active</small></span>"],
      ["Saved by cowork", "<span class=v>$"+((s.impact&&s.impact.coworkSaved)||0).toFixed(3)+"</span>"]
    ];
    $("stats").innerHTML = stats.map(function(x){return "<div class=stat><div class=k>"+x[0]+"</div>"+x[1]+"</div>";}).join("");

    // plan
    var plan=s.plan||[];
    $("plan-n").textContent = plan.length ? (plan.filter(function(p){return p.done}).length+"/"+plan.length) : "";
    $("plan").innerHTML = plan.length ? plan.map(function(p){
      var cls=p.done?"done":(p.running?"run":""); var mark=p.done?"&#10003;":(p.running?"&bull;":"");
      return "<div class='plan-item "+(p.done?"done":"")+"'><span class='chk "+cls+"'>"+mark+"</span><span class=t>"+esc(p.text||p.title||"")+"</span></div>";
    }).join("") : "<div class=empty>No active plan. Use /plan in the agent to build one.</div>";

    // cowork
    var cw=s.cowork||{};
    $("cowork-tag").textContent = cw.on ? "active" : "off";
    $("cowork").innerHTML = cw.on
      ? "<div class=cowork><div class=node><div class=role>Strong (reasoning)</div><div class=m>"+esc(cw.strong||"—")+"</div></div>"
        +"<span class=arrow>&rarr;</span>"
        +"<div class=node><div class=role>Worker ("+esc(cw.weakKind||"")+")</div><div class=m>"+esc(cw.weak||"—")+"</div></div></div>"
        +"<div class=row><span class=grow>Delegated turns</span><span class=mono>"+((s.impact&&s.impact.delegated)||0)+"</span></div>"
      : "<div class=empty>Single model. Pair one with /cowork &lt;strong&gt; &lt;weak&gt; to offload cheap work.</div>";

    // jobs
    var jobs=s.jobs||[];
    $("jobs-n").textContent = jobs.length ? String(jobs.length) : "";
    $("jobs").innerHTML = jobs.length ? jobs.map(function(j){
      return "<div class=row><span class='badge "+badge(j.status)+"'>"+esc(j.status)+"</span>"
        +"<span class='grow mono' title='"+esc(j.command)+"'>"+esc(j.command)+"</span>"
        +"<span class=mono style='color:var(--mut)'>"+fmtK(j.bytes||0)+"b</span></div>";
    }).join("") : "<div class=empty>No background jobs. The agent starts these with run_background.</div>";

    // pipelines
    $("pipe-tag").textContent = s.pipelines&&s.pipelines.engine ? "glitch" : "";
    $("pipelines").innerHTML = (s.pipelines&&s.pipelines.text)
      ? "<pre class=log>"+esc(s.pipelines.text)+"</pre>"
      : "<div class=empty>"+(s.pipelines&&s.pipelines.engine===false ? "No pipeline engine detected (install glitch to orchestrate multi-stage runs)." : "No pipeline activity.")+"</div>";

    // activity
    $("activity").textContent = (s.activity||[]).join("\\n") || "Waiting for activity…";
    $("foot").textContent = "Nexus dashboard · localhost only · updated "+new Date().toLocaleTimeString();
  }
  function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];});}

  // Live via SSE, with a polling fallback.
  function poll(){ fetch("/api/state").then(function(r){return r.json()}).then(function(s){setLive(true);misses=0;render(s);}).catch(function(){misses++;if(misses>2)setLive(false);}); }
  if(window.EventSource){
    var es=new EventSource("/api/stream");
    es.onmessage=function(e){ try{setLive(true);render(JSON.parse(e.data));}catch(_){} };
    es.onerror=function(){ setLive(false); };
  } else { setInterval(poll,1500); }
  poll();
})();
</script>
</body>
</html>`;

// Build one SSE data frame.
function sseFrame(obj) {
  return "data: " + JSON.stringify(obj).replace(/\n/g, "\\n") + "\n\n";
}

// getState(): () => snapshot object (see darknode.js dashboardState()).
// Returns a Promise<{ url, port, server, close }>.
function startDashboard(opts) {
  opts = opts || {};
  const getState = typeof opts.getState === "function" ? opts.getState : () => ({});
  const host = "127.0.0.1";
  const first = opts.port || 7979;
  const tries = 25;

  const makeServer = () => http.createServer((req, res) => {
    const url = (req.url || "/").split("?")[0];
    if (req.method !== "GET") { res.writeHead(405); res.end(); return; }

    if (url === "/" || url === "/index.html") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      res.end(PAGE);
      return;
    }
    if (url === "/favicon.ico") {
      // Inline SVG favicon (cyan→violet "N" mark) so the tab has an icon and the
      // browser's automatic request doesn't 404 in the console.
      res.writeHead(200, { "Content-Type": "image/svg+xml", "Cache-Control": "max-age=86400" });
      res.end('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#32d6ff"/><stop offset="1" stop-color="#a176ff"/></linearGradient></defs><rect width="32" height="32" rx="7" fill="#0b1118"/><path d="M9 23V9h3l8 10V9h3v14h-3l-8-10v10z" fill="url(#g)"/></svg>');
      return;
    }
    if (url === "/api/state") {
      let state = {}; try { state = getState() || {}; } catch (_) {}
      res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*" });
      res.end(JSON.stringify(state));
      return;
    }
    if (url === "/api/stream") {
      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-store",
        "Connection": "keep-alive",
        "Access-Control-Allow-Origin": "*",
      });
      const tick = () => { let s = {}; try { s = getState() || {}; } catch (_) {} try { res.write(sseFrame(s)); } catch (_) {} };
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
      server.on("error", (e) => {
        if (e && e.code === "EADDRINUSE" && attempt < tries) { attempt++; tryListen(first + attempt); }
        else reject(e);
      });
      server.listen(port, host, () => {
        resolve({
          url: "http://" + host + ":" + port,
          port, server,
          close: () => { try { server.close(); } catch (_) {} },
        });
      });
    };
    tryListen(first);
  });
}

module.exports = { startDashboard };
