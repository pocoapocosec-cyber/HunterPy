"""Self-contained interactive HTML report.

Single file, no external deps. Filter by tier / severity / module, search
across titles, click a row to expand the PoC + remediation block.
Embeds the chains detected by ContextGraph as a separate panel.

All CSS + JS is inlined so it works inside our sandboxed iframe preview.
"""
from __future__ import annotations

import html
import json
from datetime import datetime
from typing import Any, Dict, List, Optional


def render_interactive_html(target: str,
                            metadata: Dict[str, Any],
                            findings: List[Dict[str, Any]],
                            pocs: Dict[str, Any],
                            impacts: Dict[str, Any],
                            chains: Optional[List[Dict[str, Any]]] = None,
                            baseline: Optional[Dict[str, Any]] = None) -> str:
    """Return a complete HTML document as a string."""
    chains = chains or []
    from reporting.poc_generator import _finding_key
    rows = []
    for f in sorted(findings, key=lambda x: -float(x.get("score") or 0)):
        fid = _finding_key(f)
        poc = pocs.get(fid) or {}
        impact = impacts.get(fid) or {}
        if hasattr(poc, "to_dict"): poc = poc.to_dict()
        if hasattr(impact, "to_dict"): impact = impact.to_dict()
        rows.append({
            "id": fid,
            "classification": f.get("classification", "COMMON"),
            "severity": f.get("severity", "INFO"),
            "score": float(f.get("score") or 0),
            "priority": impact.get("priority_tier", "P4"),
            "module": f.get("module", "?"),
            "title": f.get("title", ""),
            "url": f.get("url", ""),
            "details": f.get("details", ""),
            "reason": f.get("classification_reason", ""),
            "confidence": float(f.get("classification_confidence") or 0),
            "poc": poc,
            "impact": impact,
        })

    summary = {
        "INTERESTING": sum(1 for r in rows if r["classification"] == "INTERESTING"),
        "COMMON":      sum(1 for r in rows if r["classification"] == "COMMON"),
        "FALSE_ALARM": sum(1 for r in rows if r["classification"] == "FALSE_ALARM"),
    }

    data_blob = json.dumps({
        "rows": rows,
        "chains": chains,
        "baseline": baseline or {},
        "metadata": {**metadata, "target": target},
        "summary": summary,
    }, default=str)

    doc = _DOCUMENT.replace("__DATA_BLOB__", _escape_json_for_html(data_blob))
    return _inject_csp(doc)


def _escape_json_for_html(blob: str) -> str:
    # Prevent </script> injection inside the embedded JSON
    return blob.replace("</", "<\\/")


# --------------------------------------------------------------------------
_DOCUMENT = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"/>
__CSP_META__
<title>HunterPy — Interactive Report</title>
<style>
 :root{
   --bg:#0f172a; --panel:#1e293b; --row:#172033; --row-hi:#243049;
   --line:#334155; --text:#e5e7eb; --muted:#94a3b8;
   --red:#dc2626; --orange:#ea580c; --yellow:#d97706;
   --green:#16a34a; --grey:#6b7280; --blue:#3b82f6; --cyan:#06b6d4;
 }
 *{box-sizing:border-box}
 body{font:14px/1.45 -apple-system,Segoe UI,Roboto,sans-serif;
      background:var(--bg);color:var(--text);margin:0;padding:18px;}
 h1{margin:0 0 4px 0}
 .meta{color:var(--muted);margin-bottom:14px;font-size:13px}
 .card{background:var(--panel);border-radius:8px;padding:14px 18px;
       margin-bottom:14px;box-shadow:0 2px 6px rgba(0,0,0,.3)}
 .summary{display:flex;gap:10px;flex-wrap:wrap}
 .stat{flex:1;min-width:140px;padding:12px;border-radius:8px;text-align:center}
 .stat .n{font-size:1.7em;font-weight:700;display:block}
 .s-int{background:#3d0808;border:1px solid var(--red)}
 .s-com{background:#3d2a08;border:1px solid var(--yellow)}
 .s-fa {background:#08381f;border:1px solid var(--green)}
 .filters{display:flex;gap:8px;margin:10px 0;flex-wrap:wrap;align-items:center}
 .filters input,.filters select{background:#0b1220;color:var(--text);
      border:1px solid var(--line);padding:6px 8px;border-radius:6px;
      font:13px monospace}
 .filters input{min-width:240px}
 .pill{padding:2px 8px;border-radius:999px;color:#fff;font-size:11px;
       font-weight:600;white-space:nowrap}
 .p-INT{background:var(--red)} .p-COM{background:var(--yellow)}
 .p-FAL{background:var(--grey)}
 .sev-CRITICAL{background:var(--red)} .sev-HIGH{background:var(--orange)}
 .sev-MEDIUM{background:var(--yellow)} .sev-LOW{background:var(--green)}
 .sev-INFO{background:var(--grey)} .sev-UNKNOWN{background:var(--grey)}
 table{width:100%;border-collapse:collapse;font-size:13px}
 th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);
       vertical-align:top}
 th{background:#0b1220;cursor:pointer;user-select:none;position:sticky;top:0}
 th:hover{background:#0e1730}
 tr.findingrow{cursor:pointer}
 tr.findingrow:hover{background:var(--row-hi)}
 .detail{display:none;background:#0b1220;padding:14px 18px}
 .detail.open{display:table-row}
 .detail pre{background:#000;padding:10px;border-radius:6px;overflow:auto;
      font-size:12px;color:#a5e3ff}
 .detail h4{margin:8px 0 4px 0;color:var(--cyan)}
 .detail ol{margin:4px 0 8px 22px}
 .detail a{color:var(--blue)}
 .chains{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));
         gap:10px}
 .chain{background:#3d0808;border:1px solid var(--red);border-radius:8px;
        padding:12px}
 .chain h4{margin:0 0 4px 0;color:#fca5a5}
 .baseline pre{font-size:11px;background:#0b1220;padding:8px;border-radius:4px}
 footer{text-align:center;color:var(--muted);margin-top:20px;font-size:12px}
 .count{color:var(--muted);font-size:12px;margin-left:8px}
</style></head><body>

<div class="card">
  <h1>🛡️ HunterPy Interactive Report</h1>
  <div class="meta" id="metaline"></div>
</div>

<div class="card">
  <div class="summary">
    <div class="stat s-int"><span class="n" id="cInt">0</span>🔴 INTERESTING</div>
    <div class="stat s-com"><span class="n" id="cCom">0</span>🟡 COMMON</div>
    <div class="stat s-fa"> <span class="n" id="cFa">0</span> 🟢 FALSE_ALARM</div>
  </div>
</div>

<div class="card" id="chainsCard" style="display:none">
  <h3 style="margin-top:0">Detected Attack Chains</h3>
  <div class="chains" id="chains"></div>
</div>

<div class="card baseline" id="baselineCard" style="display:none">
  <h3 style="margin-top:0">Baseline Behavior</h3>
  <pre id="baselineBlock"></pre>
</div>

<div class="card">
  <div class="filters">
    <input id="search" placeholder="🔎 search title / URL / module"/>
    <select id="tier">
      <option value="">All tiers</option>
      <option value="INTERESTING">🔴 Interesting</option>
      <option value="COMMON">🟡 Common</option>
      <option value="FALSE_ALARM">🟢 False alarm</option>
    </select>
    <select id="sev">
      <option value="">All severities</option>
      <option>CRITICAL</option><option>HIGH</option>
      <option>MEDIUM</option><option>LOW</option><option>INFO</option>
    </select>
    <select id="mod"><option value="">All modules</option></select>
    <span class="count" id="rowcount"></span>
  </div>

  <table id="ft">
    <thead><tr>
      <th data-k="priority">Priority</th>
      <th data-k="classification">Tier</th>
      <th data-k="severity">Severity</th>
      <th data-k="score">Score</th>
      <th data-k="module">Module</th>
      <th data-k="title">Finding</th>
      <th data-k="url">URL</th>
    </tr></thead>
    <tbody id="tbody"></tbody>
  </table>
</div>

<footer>
  Generated by HunterPy. Click any row for PoC + remediation guidance.
  This report is for authorized testing only.
</footer>

<script id="data" type="application/json">__DATA_BLOB__</script>
<script>
(function(){
  const DATA = JSON.parse(document.getElementById('data').textContent);
  const rows = DATA.rows || [];
  const meta = DATA.metadata || {};
  document.getElementById('metaline').textContent =
    `Target: ${meta.target || '-'}  ·  Scan #${meta.scan_id || '-'}  ·  ` +
    `Mode: ${meta.mode || '-'}  ·  Duration: ${meta.duration || '-'}  ·  ` +
    `Modules: ${(meta.modules_run||[]).join(', ')}`;
  document.getElementById('cInt').textContent = DATA.summary.INTERESTING;
  document.getElementById('cCom').textContent = DATA.summary.COMMON;
  document.getElementById('cFa').textContent  = DATA.summary.FALSE_ALARM;

  // chains
  if ((DATA.chains||[]).length){
    const wrap = document.getElementById('chains');
    DATA.chains.forEach(c=>{
      const d = document.createElement('div');
      d.className='chain';
      d.innerHTML = `<h4>${esc(c.title||c.type||'chain')}</h4>
        <div>${esc(c.details||'')}</div>
        <div style="margin-top:6px;color:#fca5a5;font-size:12px">
        Linked: ${(c.evidence?.linked_findings||[]).map(esc).join(' · ')}</div>`;
      wrap.appendChild(d);
    });
    document.getElementById('chainsCard').style.display='block';
  }

  // baseline
  if (DATA.baseline && Object.keys(DATA.baseline).length){
    document.getElementById('baselineBlock').textContent =
      JSON.stringify(DATA.baseline, null, 2);
    document.getElementById('baselineCard').style.display='block';
  }

  // module select
  const mods = Array.from(new Set(rows.map(r=>r.module))).sort();
  const ms = document.getElementById('mod');
  mods.forEach(m=>{ const o=document.createElement('option'); o.value=m;
                    o.textContent=m; ms.appendChild(o); });

  const tbody = document.getElementById('tbody');
  let sortKey='score', sortDir=-1;

  function esc(s){return String(s==null?'':s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

  function pillSev(s){return `<span class="pill sev-${esc(s)}">${esc(s)}</span>`;}
  function pillTier(c){const m={'INTERESTING':'INT','COMMON':'COM','FALSE_ALARM':'FAL'};
      return `<span class="pill p-${m[c]||'COM'}">${esc(c)}</span>`;}

  function rowHTML(r){
    const u = r.url && r.url.length>50 ? r.url.slice(0,50)+'…' : (r.url||'');
    return `<tr class="findingrow" data-id="${esc(r.id)}">
      <td><b>${esc(r.priority)}</b></td>
      <td>${pillTier(r.classification)}</td>
      <td>${pillSev(r.severity)}</td>
      <td>${r.score.toFixed(2)}</td>
      <td>${esc(r.module)}</td>
      <td>${esc(r.title)}</td>
      <td><a href="${esc(r.url)}" target="_blank" rel="noopener">${esc(u)}</a></td>
    </tr>`;
  }

  function detailHTML(r){
    const p = r.poc||{}, i = r.impact||{};
    const refs = (p.references||[]).map(x=>
        `<li><a href="${esc(x)}" target="_blank" rel="noopener">${esc(x)}</a></li>`)
        .join('');
    const steps = (p.steps||[]).map(s=>`<li>${esc(s)}</li>`).join('');
    const comps = (i.compliance_hints||[]).join(', ') || 'none specifically';
    return `<tr class="detail open"><td colspan="7">
      <h4>Impact</h4>
      <div>Priority <b>${esc(i.priority_tier||'?')}</b> ·
           SLA: ${esc(i.suggested_sla||'-')} ·
           Data at risk: <i>${esc(i.data_at_risk||'unknown')}</i> ·
           Compliance hints: ${esc(comps)}</div>
      <div style="color:var(--muted);font-size:12px;margin-top:4px">
        ${esc(i.rationale||'')}</div>

      <h4>Description</h4>
      <div>${esc(p.description||r.details||'')}</div>

      ${steps ? `<h4>Verification Steps</h4><ol>${steps}</ol>` : ''}
      ${p.sample_command ? `<h4>Sample command</h4>
        <pre>${esc(p.sample_command)}</pre>` : ''}

      <h4>Remediation</h4>
      <div>${esc(p.remediation||'—')}</div>

      <h4>Classification reasoning</h4>
      <div style="color:var(--muted)">${esc(r.reason||'—')}
        (confidence ${(r.confidence*100).toFixed(0)}%)</div>

      ${refs ? `<h4>References</h4><ul>${refs}</ul>` : ''}
    </td></tr>`;
  }

  function applySort(arr){
    arr.sort((a,b)=>{
      const av=a[sortKey], bv=b[sortKey];
      if (av<bv) return -1*sortDir;
      if (av>bv) return  1*sortDir;
      return 0;
    });
    return arr;
  }

  function render(){
    const q = document.getElementById('search').value.toLowerCase();
    const tier = document.getElementById('tier').value;
    const sev = document.getElementById('sev').value;
    const mod = document.getElementById('mod').value;

    const filtered = rows.filter(r =>
      (!q || (r.title+' '+r.url+' '+r.module+' '+r.details).toLowerCase().includes(q)) &&
      (!tier || r.classification === tier) &&
      (!sev  || r.severity === sev) &&
      (!mod  || r.module === mod)
    );
    applySort(filtered);
    tbody.innerHTML = filtered.map(rowHTML).join('');
    document.getElementById('rowcount').textContent =
      `${filtered.length} of ${rows.length} findings`;

    // click handler
    tbody.querySelectorAll('tr.findingrow').forEach(tr=>{
      tr.addEventListener('click', ()=>{
        const next = tr.nextElementSibling;
        if (next && next.classList.contains('detail')){
          next.remove();
          return;
        }
        const r = rows.find(x=>x.id===tr.dataset.id);
        tr.insertAdjacentHTML('afterend', detailHTML(r));
      });
    });
  }

  document.getElementById('search').addEventListener('input', render);
  document.getElementById('tier').addEventListener('change', render);
  document.getElementById('sev').addEventListener('change', render);
  document.getElementById('mod').addEventListener('change', render);
  document.querySelectorAll('#ft th').forEach(th=>{
    th.addEventListener('click', ()=>{
      const k = th.dataset.k;
      if (sortKey===k) sortDir = -sortDir;
      else { sortKey = k; sortDir = (k==='score' || k==='priority') ? -1 : 1; }
      render();
    });
  });

  render();
})();
</script>
</body></html>
"""


# ---------------------------------------------------------------------------
# Content Security Policy
# ---------------------------------------------------------------------------
# The interactive report is a single self-contained HTML file. If opened
# from an attacker-controlled directory (e.g. `file:///tmp/exfil/report.html`)
# inline JS could otherwise be hijacked via DOM-clobbering tricks in the
# embedded data blob. Lock things down via a meta-tag CSP:
#
#   default-src 'none'   — block everything that isn't explicitly allowed
#   script-src  'sha256-…'  — only run the one inline script we shipped
#   style-src   'unsafe-inline'  — inline styles are unavoidable for a
#                                  single-file report; documented tradeoff
#   img-src     data:    — emoji / SVG data-URIs in the body only
#   connect-src 'none'   — no fetch/XHR/WebSocket at all
#   form-action 'none'   — no form posts ever
#
# We hash the inline `<script>` body at render time so any edit to it
# (including legitimate ones) requires re-computing — that's the point
# of SRI/CSP hashing.
import base64 as _b64
import hashlib as _hashlib
import re as _re


def _inline_script_hash(html: str) -> str:
    """Return the base64-encoded SHA-256 of the page's main inline script.

    Looks for a plain ``<script>...</script>`` block (excluding the
    ``type="application/json"`` data block). Returns "" if nothing found —
    the CSP injector will then fall back to a permissive policy with a
    clear comment, rather than silently breaking the report.
    """
    # Skip the data block (it's type="application/json" and CSP doesn't
    # restrict non-script types). Match the next <script> with no type
    # attribute or type="text/javascript".
    pattern = _re.compile(
        r'<script(?![^>]*type\s*=\s*"application/json")[^>]*>(.*?)</script>',
        _re.DOTALL)
    m = pattern.search(html)
    if not m:
        return ""
    body = m.group(1)
    digest = _hashlib.sha256(body.encode("utf-8")).digest()
    return _b64.b64encode(digest).decode("ascii")


def _inject_csp(html: str) -> str:
    """Replace ``__CSP_META__`` with a fully-formed CSP meta tag."""
    sha = _inline_script_hash(html)
    if sha:
        script_src = f"'sha256-{sha}'"
    else:
        # Fallback — better to render a working report with a permissive
        # policy than a broken locked-down one. Tests assert sha is found.
        script_src = "'unsafe-inline'"
    csp = (
        "default-src 'none'; "
        f"script-src {script_src}; "
        "style-src 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "connect-src 'none'; "
        "form-action 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'"
    )
    meta = f'<meta http-equiv="Content-Security-Policy" content="{csp}"/>'
    return html.replace("__CSP_META__", meta)
