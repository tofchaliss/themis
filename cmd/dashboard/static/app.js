/* Themis dashboard — vanilla JS, no dependencies.
   Every fact on screen is fetched live through the same-origin proxy
   (/api/<node>/...); nothing is stored here. Views are functions of API
   responses; the hash is the only client state that survives a refresh. */

"use strict";

/* ---------- tiny utilities ---------- */

const $ = (sel, el = document) => el.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[c]));

const asArray = (j) => Array.isArray(j) ? j : (j && typeof j === "object" ? (j.items || j.entries || []) : []);

function timeAgo(iso) {
  if (!iso) return "never";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (!isFinite(s)) return "—";
  if (s < 90) return "just now";
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 172800) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.hidden = true; }, 3500);
}

/* ---------- API ---------- */

class NodeDown extends Error { constructor(node) { super(`${node} unreachable`); this.node = node; } }

/* A 401 means the session expired or the key was revoked mid-use (D12): the only
   honest continuation is the login form — data fetched on a dead session would render
   as a broken page, not as "signed out". */
function sessionGone() { location.href = "/login"; }

async function apiGET(node, path) {
  const r = await fetch(`/api/${node}${path}`, { headers: { Accept: "application/json" } });
  if (r.status === 401) { sessionGone(); throw new Error("session expired"); }
  if (r.status === 502) throw new NodeDown(node);
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`${node} ${path} → ${r.status}`);
  if (r.status === 204) return null;
  return r.json();
}

async function apiPOST(node, path, body) {
  const r = await fetch(`/api/${node}${path}`, {
    method: "POST",
    headers: { Accept: "application/json", ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (r.status === 401) { sessionGone(); throw new Error("session expired"); }
  if (r.status === 502) throw new NodeDown(node);
  return r;
}

async function problemDetail(r) {
  const j = await r.json().catch(() => ({}));
  return j.detail || j.title || `status ${r.status}`;
}

/* ---------- theme: a two-position toggle (VM feedback #1) ---------- */

const THEMES = ["enterprise", "midnight"];

function applyTheme(name) {
  if (!THEMES.includes(name)) name = "enterprise"; // migrates retired theme names
  document.documentElement.dataset.theme = name;
  localStorage.setItem("themis-theme", name);
  const dark = name === "midnight";
  $("#theme-toggle .tt-icon", document).textContent = dark ? "☾" : "☀";
  $("#theme-toggle .tt-name", document).textContent = dark ? "Midnight" : "Enterprise";
}

$("#theme-toggle").addEventListener("click", () =>
  applyTheme(document.documentElement.dataset.theme === "midnight" ? "enterprise" : "midnight"));
applyTheme(localStorage.getItem("themis-theme") || "enterprise");

/* ---------- who is looking (the authenticated session, or config when auth is off) ---------- */

let WHO = "operator"; // filled by /whoami; becomes actor_id / proposer_id on decisions
let CAN_WRITE = true; // D11: the proxy is the enforcement; this greying is the courtesy

(async () => {
  try {
    const r = await fetch("/whoami");
    if (r.status === 401) { sessionGone(); return; }
    const j = await r.json();
    const user = j.user || "operator";
    WHO = user;
    CAN_WRITE = j.can_write !== false;
    if (!CAN_WRITE) document.body.classList.add("readonly");
    $("#user-name").textContent = user;
    $("#user-initials").textContent = user.split(/[\s._-]+/).map((w) => w[0]).join("").slice(0, 2).toUpperCase() || "·";
    if (Array.isArray(j.scopes)) {
      // Scopes only exist on an authenticated session — that is when sign-out means something.
      $("#user-chip").title = `Signed in as ${user} (${j.scopes.join(", ") || "no scopes"})`;
      $("#logout-form").style.display = "";
    }
  } catch { $("#user-name").textContent = "operator"; $("#user-initials").textContent = "OP"; }
})();

/* ---------- chips & mappings ---------- */

/* Exploitability band → the FIXED status palette. critical/high+/high are risk
   states; elevated is "notable" (sequential blue); informational is neutral.
   Color never carries alone: every chip pairs a dot with its label. */
const BANDS = [
  ["critical", "chip-crit", "var(--st-crit)"],
  ["high+", "chip-serious", "var(--st-serious)"],
  ["high", "chip-warn", "var(--st-warn)"],
  ["elevated", "chip-elevated", "var(--band-elevated)"],
  ["informational", "chip-info", "var(--band-info)"],
];
const bandChip = (band) => {
  const [, cls] = BANDS.find(([b]) => b === band) || ["", "chip-info"];
  return `<span class="chip ${cls}"><i></i>${esc(band || "unbanded")}</span>`;
};

const stanceChip = (stance, hasPosition) => {
  if (!hasPosition) return `<span class="chip"><i></i>undecided</span>`;
  const cls = { affected: "chip-crit", not_affected: "chip-good", accepted_risk: "chip-warn", mitigated: "chip-elevated" }[stance] || "";
  return `<span class="chip ${cls}"><i></i>${esc(stance || "decided")}</span>`;
};

const trustChip = (t) => t ? `<span class="chip ${t === "inferred" ? "chip-warn" : ""}" title="evidence trust (EDR-TRUST-01): an inferred proposal can never be auto-accepted">${esc(t)}</span>` : "";

const claimNote = (c) => c === "scope"
  ? ` <span class="chip chip-info" title="in the advisory's rebuild set; no evidence it carries the flaw">scope</span>`
  : (c === "carrier" ? ` <span class="chip" title="evidence says this package carries the flaw">carrier</span>` : "");

/* The X-Themis-AI-Reason taxonomy (AI-204-1), rendered instead of a vanishing
   toast: each no-answer states what KIND of no-answer it was. */
const AI_REASONS = {
  insufficient: ["declined honestly", "chip-accent", "Not enough grounded evidence to answer — the safety seam working, not a failure."],
  disabled: ["AI disabled", "chip-info", "The AI plane is switched off on this node."],
  unreachable: ["Intelligence unreachable", "chip-warn", "The Intelligence node did not answer — an operations problem, not an AI verdict."],
  provider_error: ["provider error", "chip-warn", "The model provider failed mid-call. A caller timeout shorter than the model's latency also lands here."],
  budget_exhausted: ["budget exhausted", "chip-warn", "This capability's token ceiling for the current window is spent; it resets when the window rolls."],
  business_invalid: ["failed grounding", "chip-crit", "The model answered but its citations failed Grounding Verification — the answer was refused rather than shown."],
};

function aiOutcomeHTML(reason) {
  const [label, cls, why] = AI_REASONS[reason]
    || ["no answer", "chip-info", "The Gateway returned no proposal and stated no reason."];
  return `<div class="ai-outcome"><span class="chip ${cls}"><i></i>${esc(label)}</span><span>${esc(why)}</span></div>`;
}

/* Provenance the wire already states (GUI-9): which plan step decided, and
   whether the enterprise's own decision history was consulted. */
const aiProvenance = (j) => [
  j.decided_by ? `<span class="chip" title="which plan step produced this — a deterministic rule or the model">${esc(j.decided_by)}</span>` : "",
  Number.isInteger(j.precedents_used) ? `<span class="chip" title="past Enterprise Positions that grounded this — the only visible evidence the retrieval plane contributed">${j.precedents_used} precedent${j.precedents_used === 1 ? "" : "s"} used</span>` : "",
].filter(Boolean).join(" ");

const LOCAL_ONLY_CHIP = `<span class="chip" title="the AI path is hard-marked local-only: prompts go to the on-prem model and nothing leaves the building">local-only</span>`;

/* TRUST-8 inline caveats stay in the prose; make them impossible to skim past. */
const aiProse = (t) => esc(t).replace(/\[UNVERIFIED MENTIONS[^\]]*\]/g,
  (m) => `<mark class="unverified" title="this identifier was NOT in the model's grounding — verify before acting on it">${m}</mark>`);

/* The signature mark: residual over effective. */
function pbar(effective, residual) {
  const eff = Math.max(0, Math.min(100, effective | 0));
  const res = Math.max(0, Math.min(100, residual | 0));
  const hot = res >= 70 ? " hot" : "";
  return `<div class="pbar" title="effective ${eff} → residual ${res} (what remains after the decision)">
    <div class="pbar-track"><span class="pbar-eff" style="width:${eff}%"></span><span class="pbar-res${hot}" style="width:${res}%"></span></div>
    <span class="pbar-num">${res}</span></div>`;
}

/* ---------- breadcrumbs ---------- */

function crumbs(parts) {
  $("#crumbs").innerHTML = parts.map((p, i) =>
    i === parts.length - 1
      ? `<span class="crumb-current">${esc(p.label)}</span>`
      : `<a href="${esc(p.href)}">${esc(p.label)}</a><span class="crumb-sep">/</span>`
  ).join("");
}

function setRail(view) {
  document.querySelectorAll(".rail-link").forEach((a) =>
    a.classList.toggle("active", a.dataset.view === view));
}

/* ---------- views ---------- */

const main = $("#main");
const loading = (what) => { main.innerHTML = `<div class="loading"><span class="spin"></span>Loading ${esc(what)}…</div>`; };
const nodeDownCard = (e) => `<div class="err">The ${esc(e.node)} node did not answer. Check its service and the proxy target URL, then click the node dots to re-probe.</div>`;

/* --- Overview --- */

async function viewOverview() {
  setRail("overview");
  crumbs([{ label: "Overview" }]);
  loading("overview");

  let products = null, feeds = null;
  try { products = asArray(await apiGET("registry", "/products")); } catch { /* tile shows dash */ }
  try { feeds = await apiGET("knowledge", "/feeds"); } catch { /* tiles show dash */ }

  const entries = feeds ? asArray(feeds.feeds) : [];
  const healthy = entries.filter((f) => f.status === "healthy").length;

  main.innerHTML = `
    <div class="grid-2">
      <div class="card hero">
        <div class="hero-word">Themis · Enterprise Security Decisions</div>
        <h1>Evidence in, positions out</h1>
        <p>SBOMs become Findings, Findings get governed Positions, Positions publish as VEX.
           Pick a release to see its posture — every number here is read live from the pipeline,
           and the AI only ever proposes.</p>
        <a class="btn btn-primary" href="#/estate">Browse the estate</a>
        <a class="btn" href="#/sbom">Upload an SBOM</a>
      </div>
      <div class="card">
        <h2 class="card-title">Estate risk</h2>
        <p class="card-sub">Every open Finding across every release, by exploitability band.</p>
        <div id="estate-pie"><div class="loading"><span class="spin"></span>Sweeping the estate…</div></div>
      </div>
    </div>

    <div class="grid-tiles">
      <div class="tile tile-a"><div class="tile-value">${products === null ? "—" : products.length}</div>
        <div class="tile-label">Products</div><div class="tile-note">registered in the estate</div></div>
      <div class="tile tile-b"><div class="tile-value">${feeds ? `${healthy}/${entries.length}` : "—"}</div>
        <div class="tile-label">Feeds healthy</div><div class="tile-note">enrichment sources reporting</div></div>
      <div class="tile ${feeds && feeds.signals_stale ? "tile-d" : "tile-c"}">
        <div class="tile-value">${feeds ? (feeds.signals_stale ? "STALE" : "OK") : "—"}</div>
        <div class="tile-label">Exploit signals</div><div class="tile-note">${feeds && feeds.signals_stale ? "a critical feed has gone quiet" : "tier-1 feeds current"}</div></div>
      <div class="tile tile-d"><div class="tile-value">${feeds ? asArray(feeds.degraded_feeds).length : "—"}</div>
        <div class="tile-label">Degraded feeds</div><div class="tile-note">failing, non-blocking</div></div>
    </div>

    <div class="card">
      <h2 class="card-title">Quick links</h2>
      <div class="grid-links">
        <a class="qlink" href="#/estate"><span class="qi">▦</span><span><b>Releases</b><span>Products → projects → releases, down to a posture</span></span></a>
        <a class="qlink" href="#/feeds"><span class="qi">⌁</span><span><b>Feed health</b><span>OSV, NVD, EPSS/KEV, Red Hat, CSAF-VEX — who is delivering</span></span></a>
      </div>
    </div>`;

  renderEstatePie(products);
}

/* Estate sweep: every posture in the estate, aggregated by band. One read per
   release (the DASH-2 rollup), fanned out in parallel — fine at estate scale;
   revisit if an estate ever holds hundreds of releases. */
async function sweepEstate(products) {
  const projects = (await Promise.all((products || []).map((p) =>
    apiGET("registry", `/products/${encodeURIComponent(p.id)}/projects`).then(asArray).catch(() => [])))).flat();
  const releases = (await Promise.all(projects.map((j) =>
    apiGET("registry", `/projects/${encodeURIComponent(j.id)}/releases`).then(asArray).catch(() => [])))).flat();
  const postures = (await Promise.all(releases.map((r) =>
    apiGET("governance", `/releases/${encodeURIComponent(r.id)}/posture`).then(asArray).catch(() => [])))).flat();
  return { releases: releases.length, findings: postures };
}

async function renderEstatePie(products) {
  const host = $("#estate-pie");
  if (products === null) { host.innerHTML = `<div class="err">Registry unreachable — the estate cannot be swept.</div>`; return; }
  let sweep;
  try { sweep = await sweepEstate(products); }
  catch (e) { host.innerHTML = `<div class="err">${esc(e.message)}</div>`; return; }
  const { findings } = sweep;
  if (!findings.length) {
    host.innerHTML = `<div class="empty"><b>No findings anywhere yet</b>Upload an SBOM and correlation fills this in.</div>`;
    return;
  }
  const counts = BANDS.map(([b]) => [b, findings.filter((f) => f.band === b).length]);
  const unb = findings.length - counts.reduce((t, [, n]) => t + n, 0);
  if (unb > 0) counts.push(["unbanded", unb]);
  host.innerHTML = donut(counts.filter(([, n]) => n > 0), findings.length);
  wireDonutTips(host);
}

/* One donut, band order fixed, fixed status colors, always-on legend with counts —
   identity never rides on hue alone; the center carries the total. */
function donut(slices, total) {
  const R = 74, r = 46, C = { x: 84, y: 84 };
  let a0 = -Math.PI / 2;
  const paths = slices.map(([band, n]) => {
    const a1 = a0 + (n / total) * Math.PI * 2;
    const large = a1 - a0 > Math.PI ? 1 : 0;
    const p = (ang, rad) => `${(C.x + rad * Math.cos(ang)).toFixed(2)} ${(C.y + rad * Math.sin(ang)).toFixed(2)}`;
    // 0.008 rad shaved per edge ≈ the 2px spacer between marks
    const s0 = a0 + 0.008, s1 = Math.max(s0 + 0.001, a1 - 0.008);
    const d = `M ${p(s0, R)} A ${R} ${R} 0 ${large} 1 ${p(s1, R)} L ${p(s1, r)} A ${r} ${r} 0 ${large} 0 ${p(s0, r)} Z`;
    a0 = a1;
    const fill = band === "unbanded" ? "var(--muted)" : BAND_FILL[band];
    return `<path d="${d}" fill="${fill}" data-band="${esc(band)}" data-n="${n}"><title>${esc(band)}: ${n}</title></path>`;
  }).join("");
  const legend = slices.map(([band, n]) =>
    `<div class="row">${band === "unbanded" ? `<span class="chip chip-info"><i></i>unbanded</span>` : bandChip(band)}<span class="n">${n}</span></div>`).join("");
  return `<div class="pie-wrap">
    <svg class="pie-svg" viewBox="0 0 168 168" role="img" aria-label="Findings by exploitability band">
      ${paths}
      <text class="pie-center" x="84" y="82" text-anchor="middle">${total}</text>
      <text class="pie-center-sub" x="84" y="98" text-anchor="middle">findings</text>
    </svg>
    <div class="pie-legend">${legend}</div></div>`;
}

function wireDonutTips(host) {
  let tip = null;
  host.querySelectorAll("path[data-band]").forEach((el) => {
    el.addEventListener("mousemove", (ev) => {
      if (!tip) { tip = document.createElement("div"); tip.className = "seg-tip"; document.body.appendChild(tip); }
      tip.textContent = `${el.dataset.band}: ${el.dataset.n} finding${el.dataset.n === "1" ? "" : "s"}`;
      tip.style.left = `${ev.clientX + 12}px`;
      tip.style.top = `${ev.clientY - 30}px`;
    });
    el.addEventListener("mouseleave", () => { if (tip) { tip.remove(); tip = null; } });
  });
}

/* --- Estate cascade --- */

const estate = { productId: null, projectId: null };

async function viewEstate() {
  setRail("estate");
  crumbs([{ label: "Overview", href: "#/" }, { label: "Estate" }]);
  loading("estate");
  try {
    const products = asArray(await apiGET("registry", "/products"));
    main.innerHTML = `
      <div class="cascade">
        <div class="card"><h2 class="card-title">Products</h2><div class="list" id="col-products"></div></div>
        <div class="card"><h2 class="card-title">Projects</h2><div class="list" id="col-projects"><div class="empty">Pick a product</div></div></div>
        <div class="card"><h2 class="card-title">Releases</h2><div class="list" id="col-releases"><div class="empty">Pick a project</div></div></div>
      </div>`;
    const col = $("#col-products");
    col.innerHTML = products.length ? products.map((p) =>
      `<div class="list-row" data-id="${esc(p.id)}" data-name="${esc(p.name)}">${esc(p.name)}<span class="mono">${esc(p.id.slice(0, 8))}</span></div>`
    ).join("") : `<div class="empty"><b>No products yet</b>Upload the first SBOM via the <a href="#/sbom">SBOM manager</a> (“＋ New product…” registers the chain), or run scripts/gf-upload-sbom.sh.</div>`;
    col.querySelectorAll(".list-row").forEach((row) => row.addEventListener("click", () => {
      col.querySelectorAll(".list-row").forEach((r) => r.classList.remove("active"));
      row.classList.add("active");
      loadProjects(row.dataset.id, row.dataset.name);
    }));
  } catch (e) {
    main.innerHTML = e instanceof NodeDown ? nodeDownCard(e) : `<div class="err">${esc(e.message)}</div>`;
  }
}

async function loadProjects(productId, productName) {
  const col = $("#col-projects");
  $("#col-releases").innerHTML = `<div class="empty">Pick a project</div>`;
  col.innerHTML = `<div class="loading"><span class="spin"></span></div>`;
  const projects = asArray(await apiGET("registry", `/products/${encodeURIComponent(productId)}/projects`));
  col.innerHTML = projects.length ? projects.map((p) =>
    `<div class="list-row" data-id="${esc(p.id)}" data-name="${esc(p.name)}">${esc(p.name)}<span class="mono">${esc(p.id.slice(0, 8))}</span></div>`
  ).join("") : `<div class="empty"><b>No projects</b>under ${esc(productName)}</div>`;
  col.querySelectorAll(".list-row").forEach((row) => row.addEventListener("click", () => {
    col.querySelectorAll(".list-row").forEach((r) => r.classList.remove("active"));
    row.classList.add("active");
    loadReleases(row.dataset.id, row.dataset.name);
  }));
}

async function loadReleases(projectId, projectName) {
  const col = $("#col-releases");
  col.innerHTML = `<div class="loading"><span class="spin"></span></div>`;
  const releases = asArray(await apiGET("registry", `/projects/${encodeURIComponent(projectId)}/releases`));
  col.innerHTML = releases.length ? releases.map((r) =>
    `<div class="list-row" data-id="${esc(r.id)}" data-v="${esc(r.version)}">v${esc(r.version)}<span class="mono">${esc(r.id.slice(0, 8))}</span></div>`
  ).join("") : `<div class="empty"><b>No releases</b>under ${esc(projectName)} — register one, then upload its SBOM.</div>`;
  col.querySelectorAll(".list-row").forEach((row) => row.addEventListener("click", () => {
    location.hash = `#/release/${row.dataset.id}?v=${encodeURIComponent(row.dataset.v)}`;
  }));
}

/* --- Release posture --- */

async function viewRelease(releaseId, version) {
  setRail("estate");
  crumbs([{ label: "Overview", href: "#/" }, { label: "Estate", href: "#/estate" },
          { label: version ? `Release v${version}` : "Release" }]);
  loading("release posture");

  let posture, blast = null, pubs = [], queue = [];
  try {
    posture = asArray(await apiGET("governance", `/releases/${encodeURIComponent(releaseId)}/posture`));
  } catch (e) {
    main.innerHTML = e instanceof NodeDown ? nodeDownCard(e) : `<div class="err">${esc(e.message)}</div>`;
    return;
  }
  try { blast = await apiGET("registry", `/releases/${encodeURIComponent(releaseId)}/blast-radius`); } catch { /* estate optional */ }
  try { pubs = asArray(await apiGET("communication", `/publications?release=${encodeURIComponent(releaseId)}`)); } catch { /* optional */ }
  try { queue = asArray(await apiGET("communication", "/publishable-positions")).filter((q) => q.release_id === releaseId); } catch { /* optional */ }
  let scans = [];
  try { scans = asArray(await apiGET("evidence", `/evidence?release=${encodeURIComponent(releaseId)}`)).filter((e) => e.kind === "scanner-report"); } catch { /* optional */ }

  posture.sort((a, b) => (b.residual_priority - a.residual_priority) || (b.effective_priority - a.effective_priority));

  const undecided = posture.filter((p) => !p.has_position).length;
  const suppressed = posture.filter((p) => p.has_position && ["not_affected", "accepted_risk"].includes(p.stance)).length;
  const mult = posture.length ? Math.max(...posture.map((p) => p.blast_multiplier || 1)) : 1;
  const bandCounts = BANDS.map(([b]) => [b, posture.filter((p) => p.band === b).length]);
  const unbanded = posture.length - bandCounts.reduce((s, [, n]) => s + n, 0);

  main.innerHTML = `
    <div class="grid-tiles">
      <div class="tile tile-b"><div class="tile-value">${posture.length}</div><div class="tile-label">Findings</div>
        <div class="tile-note">on this release</div></div>
      <div class="tile tile-d"><div class="tile-value">${undecided}</div><div class="tile-label">Undecided</div>
        <div class="tile-note">awaiting a Position</div></div>
      <div class="tile tile-c"><div class="tile-value">${suppressed}</div><div class="tile-label">Suppressed</div>
        <div class="tile-note">not_affected / accepted_risk — kept, not deleted</div></div>
      <div class="tile tile-a"><div class="tile-value">${blast ? blast.unique_customers : "—"}<span style="font-size:14px;color:var(--ink2)"> · ×${mult.toFixed(1)}</span></div>
        <div class="tile-label">Blast radius</div><div class="tile-note">unique customers · priority multiplier</div></div>
    </div>

    <div class="card">
      <h2 class="card-title">Exploitability bands</h2>
      <p class="card-sub">Knowledge's deterministic band, not raw CVSS — critical means CVSS ≥ 9 <em>and</em> KEV-listed.</p>
      ${segBar(bandCounts, unbanded, posture.length)}
    </div>

    <div class="card">
      <h2 class="card-title">Posture <span class="chip chip-accent">sorted by residual priority</span></h2>
      <p class="card-sub">Residual = effective × stance weight — what still deserves attention after decisions. The bar keeps the effective track visible: a suppressed Finding is dispositioned, not deleted.</p>
      ${postureTable(posture)}
    </div>

    ${scans.length ? `<div class="card">
      <h2 class="card-title">Scans</h2>
      <p class="card-sub">Each scanner report filed against this release. The stored document is the complete
        per-tool record — match recording is first-wins, so only the document can say what one tool asserted (D15).
        Open a report to see every claim beside its enterprise state.</p>
      ${scansTable(scans, releaseId, version)}
    </div>` : ""}

    <div class="card">
      <h2 class="card-title">Remediation plan <span class="chip chip-accent" title="Information class (T7): rendered now, stored nowhere — the worst outcome is you disagreeing with it">AI · ephemeral</span> ${LOCAL_ONLY_CHIP}</h2>
      <p class="card-sub">Groups this release's open findings into the package upgrades that clear them — the grouping is deterministic, the model only writes the narrative. Nothing is recorded; ask again any time.</p>
      <button class="btn btn-primary" id="btn-plan">Draft a remediation plan</button>
      <div id="plan-out" hidden></div>
    </div>

    <div class="card">
      <h2 class="card-title">Publications</h2>
      ${pubs.length ? pubTable(pubs) : `<div class="empty"><b>Nothing published for this release</b>Decide a Position, then POST /publications — publication is always human-triggered.</div>`}
      ${queue.length ? `<h2 class="card-title" style="margin-top:16px">Publishable queue</h2>${queueTable(queue)}` : ""}
    </div>`;

  segBarWireTips();
  main.querySelectorAll("tr.rowlink").forEach((tr) => tr.addEventListener("click", () => {
    if (tr.dataset.pubid) return openPublication(tr.dataset.pubid);
    const entry = posture.find((p) => p.finding_id === tr.dataset.id);
    openDrawer(entry);
  }));
  main.querySelectorAll(".q-preview").forEach((btn) => btn.addEventListener("click", (ev) => {
    ev.stopPropagation();
    openPreview(queue[Number(btn.dataset.qi)]);
  }));
  main.querySelectorAll("tr.scanlink").forEach((tr) => tr.addEventListener("click", () => {
    location.hash = `#/scan/${tr.dataset.id}?rel=${encodeURIComponent(releaseId)}&v=${encodeURIComponent(version || "")}`;
  }));
  fillScanCounts(scans);

  const planBtn = $("#btn-plan");
  planBtn.addEventListener("click", async () => {
    const out = $("#plan-out");
    planBtn.disabled = true;
    planBtn.innerHTML = `<span class="spin"></span> Drafting — local model, may take a minute…`;
    out.hidden = false;
    out.innerHTML = `<div class="empty"><b>Drafting…</b>Deterministic grouping first; the model writes only the narrative.</div>`;
    try {
      const r = await apiPOST("intelligence",
        "/capabilities/plan_remediation/invoke", // registry id is the bare name; @v1 is the ref notation
        { subject: { type: "release", ids: [releaseId] } });
      if (r.status === 200) {
        const j = await r.json();
        out.innerHTML = `<div class="plan-head">${aiProvenance(j)}</div>
          <div class="plan-text">${aiProse(j.information || "")}</div>`;
      } else if (r.status === 204) {
        out.innerHTML = aiOutcomeHTML(r.headers.get("X-Themis-AI-Reason"));
      } else {
        out.innerHTML = `<div class="err">plan_remediation returned ${r.status}: ${esc(await problemDetail(r))}</div>`;
      }
    } catch (e) {
      out.innerHTML = `<div class="err">${esc(e instanceof NodeDown ? "Intelligence node unreachable." : e.message)}</div>`;
    }
    planBtn.disabled = false;
    planBtn.textContent = "Draft a remediation plan";
  });
}

const BAND_FILL = {
  critical: "var(--st-crit)", "high+": "var(--st-serious)", high: "var(--st-warn)",
  elevated: "var(--band-elevated)", informational: "var(--band-info)",
};

function segBar(bandCounts, unbanded, total) {
  if (!total) return `<div class="empty"><b>No findings yet</b>Upload an SBOM to this release and correlation opens Findings here.</div>`;
  const segs = bandCounts.filter(([, n]) => n > 0).map(([band, n]) =>
    `<div class="seg" data-band="${esc(band)}" data-n="${n}" style="flex:${n};background:${BAND_FILL[band]}"><span class="seg-name">${esc(band)}</span>${n}</div>`);
  if (unbanded > 0) segs.push(`<div class="seg" data-band="unbanded" data-n="${unbanded}" style="flex:${unbanded};background:var(--muted)"><span class="seg-name">unbanded</span>${unbanded}</div>`);
  const legend = bandCounts.filter(([, n]) => n > 0).map(([band]) => bandChip(band)).join(" ")
    + (unbanded > 0 ? ` <span class="chip chip-info"><i></i>unbanded</span>` : "");
  return `<div class="seg-wrap"><div class="seg-bar">${segs.join("")}</div><div class="seg-legend">${legend}</div></div>`;
}

function segBarWireTips() {
  let tip = null;
  main.querySelectorAll(".seg").forEach((seg) => {
    seg.addEventListener("mousemove", (ev) => {
      if (!tip) { tip = document.createElement("div"); tip.className = "seg-tip"; document.body.appendChild(tip); }
      tip.textContent = `${seg.dataset.band}: ${seg.dataset.n} finding${seg.dataset.n === "1" ? "" : "s"}`;
      tip.style.left = `${ev.clientX + 12}px`;
      tip.style.top = `${ev.clientY - 30}px`;
    });
    seg.addEventListener("mouseleave", () => { if (tip) { tip.remove(); tip = null; } });
  });
}

function componentCell(components) {
  const cs = components || [];
  if (!cs.length) return `<span class="chip chip-info">none recorded</span>`;
  const carriers = cs.filter((c) => c.claim_class !== "scope");
  const head = carriers.length ? carriers[0] : cs[0];
  const more = cs.length - 1;
  return `<span class="mono">${esc(head.name)}${head.version ? "@" + esc(head.version) : ""}</span>`
    + claimNote(head.claim_class)
    + (more > 0 ? ` <span class="chip chip-info">+${more} more</span>` : "");
}

function postureTable(posture) {
  if (!posture.length) return `<div class="empty"><b>No findings</b>Either nothing correlates yet, or this release is genuinely clean.</div>`;
  return `<div class="tbl-wrap"><table class="tbl">
    <thead><tr><th>CVE</th><th>Band</th><th class="num">Base</th><th class="num">Blast</th>
    <th>Priority — residual over effective</th><th>Stance</th><th>Component</th><th>Fix</th></tr></thead>
    <tbody>${posture.map((p) => `
      <tr class="rowlink" data-id="${esc(p.finding_id)}" title="Open finding detail">
        <td class="cve"><span class="mono">${esc(p.cve)}</span>${p.reservation ? ` <span class="chip chip-warn" title="a reservation is recorded on this position">⚑ ${esc(p.reservation)}</span>` : ""}</td>
        <td>${bandChip(p.band)}</td>
        <td class="num">${p.base_score ?? "—"}</td>
        <td class="num">×${(p.blast_multiplier || 1).toFixed(1)}</td>
        <td>${pbar(p.effective_priority, p.residual_priority)}</td>
        <td>${stanceChip(p.stance, p.has_position)}</td>
        <td>${componentCell(p.components)}</td>
        <td>${(p.fixes || []).length ? `<span class="mono">${esc(p.fixes[0].version)}</span>${p.fixes.length > 1 ? ` <span class="chip chip-info">+${p.fixes.length - 1}</span>` : ""}` : `<span class="chip chip-info">none attributed</span>`}</td>
      </tr>`).join("")}</tbody></table></div>`;
}

function pubTable(pubs) {
  return `<div class="tbl-wrap"><table class="tbl">
    <thead><tr><th>Artifact</th><th>Format</th><th>CVE</th><th>Stance</th><th>Delivery</th><th>Superseded</th></tr></thead>
    <tbody>${pubs.map((p) => `<tr class="rowlink" data-pubid="${esc(p.id)}" title="open the recorded document">
      <td>${esc(p.artifact_type)}</td><td><span class="mono">${esc(p.format)}</span></td>
      <td><span class="mono">${esc(p.cve)}</span></td><td>${stanceChip(p.stance, true)}</td>
      <td>${esc(p.delivery_status)}</td><td>${p.superseded ? "yes" : "no"}</td></tr>`).join("")}</tbody></table></div>`;
}

/* Open a recorded Publication as the document it is. The payload is capped +
   regenerable server-side, so GET /publications/{id} always has content. */
/* docView is the shared document overlay: the published artifact and the D9 preview are
   the same reading surface, differing only in their chips and filename. */
function docView({ cve, format, stance, extraChips = "", payload }) {
  let text = payload || "";
  try { text = JSON.stringify(JSON.parse(text), null, 2); } catch { /* markdown/text formats stay as-is */ }
  const ext = { markdown: "md", text: "txt" }[format] || "json";
  const scrim = document.createElement("div");
  scrim.className = "docview-scrim";
  scrim.innerHTML = `<div class="docview" role="dialog" aria-label="publication document">
    <div class="docview-top">
      <span class="mono">${esc(cve)}</span>
      <span class="chip">${esc(format)}</span>
      ${stanceChip(stance, true)}
      ${extraChips}
      <a class="btn" id="docview-dl">Download</a>
      <button class="btn" id="docview-close">Close</button>
    </div>
    <pre class="docview-body">${esc(text)}</pre>
  </div>`;
  document.body.appendChild(scrim);
  const close = () => scrim.remove();
  scrim.addEventListener("click", (ev) => { if (ev.target === scrim) close(); });
  $("#docview-close", scrim).addEventListener("click", close);
  document.addEventListener("keydown", function onEsc(e) {
    if (e.key === "Escape") { close(); document.removeEventListener("keydown", onEsc); }
  });
  const dl = $("#docview-dl", scrim);
  dl.href = URL.createObjectURL(new Blob([payload || ""], { type: "text/plain" }));
  dl.download = `${cve || "publication"}.${format || "artifact"}.${ext}`;
}

async function openPublication(id) {
  let p;
  try { p = await apiGET("communication", `/publications/${encodeURIComponent(id)}`); }
  catch (e) { toast(e instanceof NodeDown ? "Communication unreachable." : e.message); return; }
  if (!p) { toast("Publication not found."); return; }
  docView({
    cve: p.cve, format: p.format, stance: p.stance, payload: p.payload,
    extraChips: p.superseded ? `<span class="chip chip-warn">superseded</span>` : "",
  });
}

/* The D9 preview: render the queue row's CURRENT Position as the artifact it would
   publish, without recording anything — the whole point is seeing the document before
   the decision to publish it exists anywhere. */
async function openPreview(q) {
  let r;
  try {
    r = await apiPOST("communication", "/previews",
      { finding_id: q.finding_id, artifact_type: "vex", format: "openvex" });
  } catch (e) { toast(e instanceof NodeDown ? "Communication unreachable." : e.message); return; }
  if (!r.ok) { toast(`Preview failed: ${await problemDetail(r)}`); return; }
  const { payload } = await r.json();
  docView({
    cve: q.cve, format: "openvex", stance: q.stance, payload,
    extraChips: `<span class="chip chip-warn" title="A non-recording render (D9): nothing was published or stored — this is what POST /publications WOULD produce">preview — not recorded</span>`,
  });
}

function queueTable(queue) {
  return `<div class="tbl-wrap"><table class="tbl">
    <thead><tr><th>CVE</th><th>Stance</th><th class="num">Version</th><th>Stale</th><th></th></tr></thead>
    <tbody>${queue.map((q, i) => `<tr>
      <td><span class="mono">${esc(q.cve)}</span></td><td>${stanceChip(q.stance, true)}</td>
      <td class="num">${esc(q.version)}</td><td>${q.stale ? `<span class="chip chip-warn"><i></i>stale</span>` : "current"}</td>
      <td><button class="btn q-preview" data-qi="${i}" title="Render this position as OpenVEX without recording anything (D9)">Preview</button></td></tr>`).join("")}</tbody></table></div>`;
}

/* --- Scans: the per-scan report is a VIEW — stored document ⋈ posture, joined by CVE
   in the browser (EDR-GUI-01 D15). No backend truth exists for this page: the verbatim
   per-tool document (immune to first-wins match dedup) and the posture are both already
   stored, and the join is presentation. --- */

const scanToolChip = (source) => source
  ? `<span class="chip chip-accent" title="who produced the document (D14) — labeling only, never authority">${esc(source)}</span>`
  : `<span class="chip chip-info" title="uploaded without a provenance_source — reports uploaded before Phase A, or hand-curated ones, have no tool label">unlabeled</span>`;

function scansTable(scans, releaseId, version) {
  return `<div class="tbl-wrap"><table class="tbl">
    <thead><tr><th>Tool</th><th>Filed</th><th class="num">Findings asserted</th><th>Evidence id</th></tr></thead>
    <tbody>${scans.map((s) => `<tr class="rowlink scanlink" data-id="${esc(s.id)}" title="Open the per-scan report">
      <td>${scanToolChip(s.provenance_source)}</td>
      <td title="${esc(s.filed_at || "")}">${esc(timeAgo(s.filed_at))}</td>
      <td class="num" data-scancount="${esc(s.id)}"><span class="spin"></span></td>
      <td><span class="mono">${esc(s.id)}</span></td></tr>`).join("")}</tbody></table></div>`;
}

/* Counts fill in AFTER the posture renders — one small document fetch per scan,
   never blocking the page (a missing document reads as "?", not as a broken view). */
function fillScanCounts(scans) {
  scans.forEach(async (s) => {
    const cell = main.querySelector(`[data-scancount="${CSS.escape(s.id)}"]`);
    if (!cell) return;
    try {
      const doc = await apiGET("evidence", `/evidence/${encodeURIComponent(s.id)}/document`);
      const report = doc ? JSON.parse(doc.document) : null;
      cell.textContent = report && Array.isArray(report.findings) ? report.findings.length : "?";
    } catch { cell.textContent = "?"; }
  });
}

async function viewScan(evidenceId, releaseId, version) {
  setRail("estate");
  const relHref = `#/release/${releaseId}?v=${encodeURIComponent(version || "")}`;
  crumbs([{ label: "Overview", href: "#/" }, { label: "Estate", href: "#/estate" },
          { label: version ? `Release v${version}` : "Release", href: relHref }, { label: "Scan report" }]);
  loading("scan report");

  let facts = null, doc = null, posture = [];
  try {
    [facts, doc, posture] = await Promise.all([
      apiGET("evidence", `/evidence/${encodeURIComponent(evidenceId)}`),
      apiGET("evidence", `/evidence/${encodeURIComponent(evidenceId)}/document`),
      apiGET("governance", `/releases/${encodeURIComponent(releaseId)}/posture`).then(asArray),
    ]);
  } catch (e) {
    main.innerHTML = e instanceof NodeDown ? nodeDownCard(e) : `<div class="err">${esc(e.message)}</div>`;
    return;
  }
  if (!doc) { main.innerHTML = `<div class="err">Evidence document not found.</div>`; return; }

  let report = null;
  try { report = JSON.parse(doc.document); } catch { /* handled below */ }
  const findings = report && Array.isArray(report.findings) ? report.findings : null;
  if (!findings) {
    main.innerHTML = `<div class="err">This document is not a curated scanner report ({findings:[…]}) — nothing to join.</div>`;
    return;
  }

  // The join: one Finding per (release, CVE) however many tools asserted it, so CVE is the key.
  const byCVE = new Map(posture.map((p) => [p.cve, p]));
  const rows = findings.map((f) => ({ f, entry: f && f.cve ? byCVE.get(f.cve) : undefined }));
  rows.sort((a, b) => ((b.entry ? b.entry.residual_priority : -1) - (a.entry ? a.entry.residual_priority : -1)));

  const asserted = findings.length;
  const matched = rows.filter((r) => r.entry).length;
  const decided = rows.filter((r) => r.entry && r.entry.has_position).length;
  const unmatched = asserted - matched;

  main.innerHTML = `
    <div class="grid-tiles">
      <div class="tile tile-b"><div class="tile-value">${asserted}</div><div class="tile-label">Asserted</div>
        <div class="tile-note">findings in this report</div></div>
      <div class="tile tile-a"><div class="tile-value">${matched}</div><div class="tile-label">Matched</div>
        <div class="tile-note">have a Finding on this release</div></div>
      <div class="tile tile-c"><div class="tile-value">${decided}</div><div class="tile-label">Decided</div>
        <div class="tile-note">carry an Enterprise Position</div></div>
      <div class="tile tile-d"><div class="tile-value">${unmatched}</div><div class="tile-label">No Finding</div>
        <div class="tile-note">filtered at ingestion — the claim stays in this report</div></div>
    </div>

    <div class="card">
      <h2 class="card-title">Scan report ${scanToolChip(facts ? facts.provenance_source : "")}
        <span class="chip" title="${esc(facts && facts.filed_at ? facts.filed_at : "")}">filed ${esc(timeAgo(facts && facts.filed_at))}</span></h2>
      <p class="card-sub">Every claim this tool asserted, beside what the enterprise did with it. "Ingested the
        report" and "ingested most of the report" must never look alike: a claim with no Finding was skipped in
        translation, out of the correlated range, or vendor-fixed — filtered, not lost.</p>
      ${rows.length ? `<div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>CVE</th><th>Claimed severity</th><th>Component as claimed</th><th>Claimed fix</th>
        <th>Band</th><th>Stance</th><th>Priority — residual over effective</th></tr></thead>
        <tbody>${rows.map(({ f, entry }) => entry ? `
          <tr class="rowlink" data-id="${esc(entry.finding_id)}" title="Open finding detail">
            <td class="cve"><span class="mono">${esc(f.cve)}</span></td>
            <td>${esc((f.severity || "").toLowerCase() || "—")}${f.cvss_score ? ` <span class="mono">${esc(String(f.cvss_score))}</span>` : ""}</td>
            <td><span class="mono">${esc(f.component && f.component.name ? f.component.name : "?")}${f.component && f.component.version ? "@" + esc(f.component.version) : ""}</span></td>
            <td>${(f.fixed || []).length ? `<span class="mono">${esc(f.fixed[0])}</span>` : "—"}</td>
            <td>${bandChip(entry.band)}</td>
            <td>${stanceChip(entry.stance, entry.has_position)}</td>
            <td>${pbar(entry.effective_priority, entry.residual_priority)}</td>
          </tr>` : `
          <tr class="dim">
            <td class="cve"><span class="mono">${esc(f && f.cve ? f.cve : "?")}</span></td>
            <td>${esc(((f && f.severity) || "").toLowerCase() || "—")}${f && f.cvss_score ? ` <span class="mono">${esc(String(f.cvss_score))}</span>` : ""}</td>
            <td><span class="mono">${esc(f && f.component && f.component.name ? f.component.name : "?")}${f && f.component && f.component.version ? "@" + esc(f.component.version) : ""}</span></td>
            <td>${(f && f.fixed || []).length ? `<span class="mono">${esc(f.fixed[0])}</span>` : "—"}</td>
            <td colspan="3"><span class="chip chip-info" title="skipped in translation, out of the correlated range, or vendor-fixed — the assertion is preserved verbatim in this stored report">no Finding — filtered at ingestion</span></td>
          </tr>`).join("")}</tbody></table></div>`
        : `<div class="empty"><b>Empty report</b>This document asserts no findings.</div>`}
      <p class="card-sub" style="margin-top:10px"><a href="${esc(relHref)}">← Back to the release posture</a></p>
    </div>`;

  main.querySelectorAll("tr.rowlink[data-id]").forEach((tr) => tr.addEventListener("click", () => {
    const entry = posture.find((p) => p.finding_id === tr.dataset.id);
    if (entry) openDrawer(entry);
  }));
}

/* --- Compare releases (IDEA-1): fixed / new / persisting by CVE.
   "Fixed" is deliberately ABSENCE PROVEN BY NEW EVIDENCE — the fix build registers as a
   new Release, its evidence correlates, and the CVE's Finding simply does not open there
   while the old release keeps its honest record. The diff comes from Governance's
   comparison read (EDR-GOVERNANCE-01 D16, GET /releases/{id}/compare/{candidate}) — the
   server owns the join, the buckets, the ordering AND the honesty guard (422 when a side
   has no evidence; 502 when Evidence cannot be asked), so the GUI and the AI consumers
   read one answer. This view used to compute the join client-side; it was the working
   spec for the endpoint and now merely renders it. --- */

async function viewCompare() {
  setRail("compare");
  crumbs([{ label: "Overview", href: "#/" }, { label: "Compare releases" }]);
  loading("compare");

  let products = [];
  try { products = asArray(await apiGET("registry", "/products")); }
  catch (e) { main.innerHTML = e instanceof NodeDown ? nodeDownCard(e) : `<div class="err">${esc(e.message)}</div>`; return; }

  main.innerHTML = `
    <div class="card">
      <h2 class="card-title">Compare two releases</h2>
      <p class="card-sub">Fix verification by absence: a CVE is <b>fixed</b> when the new release's evidence opens
        no Finding for it while the old release keeps its record. Pick a baseline (the release you shipped) and a
        candidate (the build that claims to fix things) from the same project.</p>
      <div class="form-grid">
        <label>Product
          <select id="cmp-product"><option value="">— pick a product —</option>
            ${products.map((p) => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join("")}</select></label>
        <label>Project
          <select id="cmp-project" disabled><option value="">—</option></select></label>
        <label>Baseline release
          <select id="cmp-a" disabled><option value="">—</option></select></label>
        <label>Candidate release
          <select id="cmp-b" disabled><option value="">—</option></select></label>
        <div><button class="btn btn-primary" id="cmp-run" disabled>Compare</button></div>
      </div>
    </div>
    <div id="cmp-out"></div>`;

  const sel = { product: $("#cmp-product"), project: $("#cmp-project"), a: $("#cmp-a"), b: $("#cmp-b") };
  const runBtn = $("#cmp-run"), out = $("#cmp-out");
  const gate = () => { runBtn.disabled = !(sel.a.value && sel.b.value && sel.a.value !== sel.b.value); };

  sel.product.addEventListener("change", async () => {
    sel.project.innerHTML = `<option value="">—</option>`; sel.project.disabled = true;
    for (const s of [sel.a, sel.b]) { s.innerHTML = `<option value="">—</option>`; s.disabled = true; }
    gate();
    if (!sel.product.value) return;
    const projects = asArray(await apiGET("registry", `/products/${encodeURIComponent(sel.product.value)}/projects`));
    sel.project.innerHTML = `<option value="">— pick a project —</option>` +
      projects.map((j) => `<option value="${esc(j.id)}">${esc(j.name)}</option>`).join("");
    sel.project.disabled = false;
  });

  sel.project.addEventListener("change", async () => {
    for (const s of [sel.a, sel.b]) { s.innerHTML = `<option value="">—</option>`; s.disabled = true; }
    gate();
    if (!sel.project.value) return;
    const releases = asArray(await apiGET("registry", `/projects/${encodeURIComponent(sel.project.value)}/releases`));
    const opts = releases.map((r) => `<option value="${esc(r.id)}">v${esc(r.version)}</option>`).join("");
    sel.a.innerHTML = `<option value="">— baseline —</option>` + opts;
    sel.b.innerHTML = `<option value="">— candidate —</option>` + opts;
    sel.a.disabled = sel.b.disabled = false;
  });

  sel.a.addEventListener("change", gate);
  sel.b.addEventListener("change", gate);

  runBtn.addEventListener("click", async () => {
    const aId = sel.a.value, bId = sel.b.value;
    const aVer = sel.a.selectedOptions[0].textContent, bVer = sel.b.selectedOptions[0].textContent;
    runBtn.disabled = true; runBtn.innerHTML = `<span class="spin"></span> Comparing…`;
    out.innerHTML = `<div class="loading"><span class="spin"></span></div>`;
    try {
      // The dedicated fetch (not apiGET): the endpoint's refusals carry their reason in the
      // Problem detail — 422 "a side has no evidence" and 502 "cannot verify evidence" are
      // honest answers to render, not transport failures to swallow.
      const r = await fetch(`/api/governance/releases/${encodeURIComponent(aId)}/compare/${encodeURIComponent(bId)}`,
        { headers: { Accept: "application/json" } });
      if (r.status === 401) { sessionGone(); return; }
      if (!r.ok) {
        let detail = await r.json().then((j) => [j.title, j.detail].filter(Boolean).join(" — ")).catch(() => "");
        // The Problem names releases by id; the operator picked them by version.
        detail = detail.replaceAll(aId, aVer).replaceAll(bId, bVer);
        out.innerHTML = `<div class="err">${esc(detail || `governance → ${r.status}`)}</div>`;
        return;
      }
      const cmp = await r.json();

      // Buckets arrive joined + sorted (residual then effective priority, descending);
      // fixed rows carry the baseline's state, new/persisting the candidate's.
      const bucketTable = (list, emptyMsg) => list.length ? postureTable(list) : `<div class="empty">${emptyMsg}</div>`;
      const fixed = asArray(cmp.fixed);
      const fresh = asArray(cmp.new);
      const persisting = asArray(cmp.persisting);

      out.innerHTML = `
        <div class="grid-tiles">
          <div class="tile tile-a"><div class="tile-value">${fixed.length}</div><div class="tile-label">Fixed</div>
            <div class="tile-note">on ${esc(aVer)}, no Finding on ${esc(bVer)}</div></div>
          <div class="tile tile-d"><div class="tile-value">${fresh.length}</div><div class="tile-label">New</div>
            <div class="tile-note">on ${esc(bVer)} only</div></div>
          <div class="tile tile-b"><div class="tile-value">${persisting.length}</div><div class="tile-label">Persisting</div>
            <div class="tile-note">open on both — the fix did not cover these</div></div>
          <div class="tile tile-c"><div class="tile-value">${persisting.filter((p) => p.has_position).length}</div><div class="tile-label">Decided</div>
            <div class="tile-note">of the persisting, carry a Position</div></div>
        </div>

        <div class="card">
          <h2 class="card-title">Fixed in ${esc(bVer)} <span class="chip chip-good"><i></i>${fixed.length}</span></h2>
          <p class="card-sub">These Findings exist on ${esc(aVer)} and open no Finding on ${esc(bVer)} — shown with
            their baseline state, which stays on record (a fix closes the question forward, it never rewrites history).
            A just-uploaded candidate may still be correlating; re-check once its posture settles.</p>
          <div data-cmp="fixed">${bucketTable(fixed, `<b>Nothing fixed</b>Every baseline Finding still opens on the candidate.`)}</div>
        </div>

        <div class="card">
          <h2 class="card-title">New in ${esc(bVer)} <span class="chip chip-crit"><i></i>${fresh.length}</span></h2>
          <p class="card-sub">No Finding on ${esc(aVer)} — introduced by new components, or published after the
            baseline's last correlation (the re-discovery sweep keeps old releases current).</p>
          <div data-cmp="fresh">${bucketTable(fresh, `<b>Nothing new</b>The candidate introduces no Finding the baseline did not already have.`)}</div>
        </div>

        <div class="card">
          <h2 class="card-title">Persisting <span class="chip chip-warn"><i></i>${persisting.length}</span></h2>
          <p class="card-sub">Open on both releases, shown with the candidate's state. Positions do not carry
            across releases — a persisting CVE on the candidate is decided there, or it is undecided.</p>
          <div data-cmp="persisting">${bucketTable(persisting, `<b>Nothing persists</b>No CVE is open on both releases.`)}</div>
        </div>`;

      const buckets = { fixed, fresh, persisting };
      for (const [key, list] of Object.entries(buckets)) {
        out.querySelectorAll(`[data-cmp="${key}"] tr.rowlink`).forEach((tr) => tr.addEventListener("click", () => {
          const entry = list.find((p) => p.finding_id === tr.dataset.id);
          if (entry) openDrawer(entry);
        }));
      }
    } catch (e) {
      out.innerHTML = e instanceof NodeDown ? nodeDownCard(e) : `<div class="err">${esc(e.message)}</div>`;
    } finally {
      runBtn.disabled = false; runBtn.textContent = "Compare";
      gate();
    }
  });
}

/* --- Feeds --- */

async function viewFeeds() {
  setRail("feeds");
  crumbs([{ label: "Overview", href: "#/" }, { label: "Feed health" }]);
  loading("feed health");
  try {
    const feeds = await apiGET("knowledge", "/feeds");
    const entries = feeds ? asArray(feeds.feeds) : [];
    main.innerHTML = `
      ${feeds && feeds.signals_stale ? `<div class="err">⚠ Signals are STALE — a tier-1 feed has gone quiet, so exploitability data may be out of date.</div>` : ""}
      <div class="card">
        <h2 class="card-title">Enrichment feeds</h2>
        <p class="card-sub">Tier 1 stale blocks trust in signals; tier 2 failures degrade quietly. OSV runs on every upload; the rest are opt-in schedulers.</p>
        ${entries.length ? `<div class="tbl-wrap"><table class="tbl">
          <thead><tr><th>Source</th><th class="num">Tier</th><th>Status</th><th class="num">Consecutive failures</th><th>Last success</th></tr></thead>
          <tbody>${entries.map((f) => `<tr>
            <td><b>${esc(f.source)}</b></td><td class="num">${esc(f.tier)}</td>
            <td><span class="chip ${f.status === "healthy" ? "chip-good" : (f.status === "stale" ? "chip-crit" : "chip-warn")}"><i></i>${esc(f.status)}</span></td>
            <td class="num">${f.consecutive_failures || 0}</td>
            <td>${timeAgo(f.last_success_at)}</td></tr>`).join("")}</tbody></table></div>`
        : `<div class="empty"><b>No feed activity recorded</b>Feeds record health per poll — enable one and it appears here.</div>`}
      </div>`;
  } catch (e) {
    main.innerHTML = e instanceof NodeDown ? nodeDownCard(e) : `<div class="err">${esc(e.message)}</div>`;
  }
}

/* --- Scanner-report translators (EDR-GUI-01 D16, multi-scanner Phase C).
   Tool dialects translate HERE, in the browser: one pure function per tool,
   auto-detected from the raw JSON's shape, all emitting the same curated
   {findings:[…]} document the CLI jq recipes emit (TESTING.md). The server
   never learns a vendor dialect — the curated shape stays the single wire
   contract and the scanner ACL the single interpretation point. Findings a
   translation cannot use are skipped and counted, never fatal: one malformed
   finding must not void a 400-finding report. --- */

/* Trivy speaks its own ecosystem vocabulary where the pipeline speaks purl
   types — unmapped values pass through (KN-SCAN-3 is the server-side net). */
const TRIVY_ECOSYSTEMS = {
  "python-pkg": "pypi", "node-pkg": "npm", "gobinary": "golang",
  "gomod": "golang", "jar": "maven", "pom": "maven", "gemspec": "gem",
};

function translateTrivy(j) {
  const findings = [];
  let skipped = 0;
  const observed = new Date().toISOString();
  for (const r of j.Results || []) {
    for (const v of (r && r.Vulnerabilities) || []) {
      if (!v || !v.VulnerabilityID || !v.PkgName) { skipped++; continue; }
      findings.push({
        cve: v.VulnerabilityID,
        observed_at: observed,
        scanner: "trivy",
        severity: v.Severity || "",
        cvss_score: (v.CVSS && v.CVSS.nvd && v.CVSS.nvd.V3Score) || 0,
        cvss_vector: (v.CVSS && v.CVSS.nvd && v.CVSS.nvd.V3Vector) || "",
        affected: [],
        fixed: v.FixedVersion ? [v.FixedVersion] : [],
        component: {
          purl: (v.PkgIdentifier && v.PkgIdentifier.PURL) || "",
          name: v.PkgName,
          version: v.InstalledVersion || "",
          ecosystem: TRIVY_ECOSYSTEMS[r.Type] || r.Type || "",
          source: "",
        },
      });
    }
  }
  return { findings, skipped };
}

/* Further tools (Grype/Xray/Black Duck/Cortex) register here by demand (D16). */
function detectTranslator(j) {
  if (j && Array.isArray(j.Results) && (j.SchemaVersion !== undefined || j.ArtifactName !== undefined)) {
    return { tool: "trivy", translate: translateTrivy };
  }
  return null;
}

/* --- SBOM manager (VM feedback #8 — the tab that will grow) --- */

async function viewSBOM() {
  setRail("sbom");
  crumbs([{ label: "Overview", href: "#/" }, { label: "SBOM manager" }]);
  loading("SBOM manager");
  let products = [];
  try { products = asArray(await apiGET("registry", "/products")); }
  catch (e) { main.innerHTML = e instanceof NodeDown ? nodeDownCard(e) : `<div class="err">${esc(e.message)}</div>`; return; }

  main.innerHTML = `
    <div class="card">
      <h2 class="card-title">Upload evidence</h2>
      <p class="card-sub">An SBOM (CycloneDX / SPDX), a VEX, or a scanner report, filed against a release.
        A build that is not registered yet is the normal case for a fresh SBOM — pick “＋ New…” and the
        release (and, if needed, its product/project) is registered on upload, the same
        Product→Project→Release chain scripts/gf-upload-sbom.sh drives. Format is detected from the file;
        raw Trivy JSON is translated to the curated shape in the browser (the server only ever sees the
        curated document — D16); byte-identical re-uploads dedup to the same evidence id.</p>
      <div class="form-grid">
        <label>Product
          <select id="sb-product"><option value="">— pick a product —</option>
            ${products.map((p) => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join("")}
            <option value="__new__">＋ New product…</option></select>
          <input type="text" id="sb-product-new" placeholder="new product name" style="display:none"></label>
        <label>Project
          <select id="sb-project" disabled><option value="">—</option></select>
          <input type="text" id="sb-project-new" placeholder="new project name" style="display:none"></label>
        <label>Release
          <select id="sb-release" disabled><option value="">—</option></select>
          <input type="text" id="sb-release-new" placeholder="version, e.g. 20.1.0.1-110" style="display:none"></label>
        <label>Kind
          <select id="sb-kind"><option value="sbom">SBOM</option><option value="vex">VEX</option><option value="scanner-report">Scanner report</option></select></label>
        <label>Document
          <input type="file" id="sb-file" accept=".json,application/json">
          <span class="file-note" id="sb-detect">Pick a .json file — CycloneDX, SPDX and scanner reports are detected automatically.</span></label>
        <div><button class="btn btn-primary" id="sb-upload" disabled>Upload</button></div>
      </div>
    </div>
    <div class="card">
      <h2 class="card-title">Evidence on the selected release</h2>
      <div id="sb-list"><div class="empty">Pick a release to list its evidence.</div></div>
    </div>`;

  const sel = { product: $("#sb-product"), project: $("#sb-project"), release: $("#sb-release") };
  const inp = { product: $("#sb-product-new"), project: $("#sb-project-new"), release: $("#sb-release-new") };
  const fileInput = $("#sb-file"), detect = $("#sb-detect"), uploadBtn = $("#sb-upload");
  let fileText = null, fileFormat = null, fileScanner = null;
  let loadedProjects = [], loadedReleases = []; // for reuse-not-duplicate guards on "＋ New"

  const NEW = "__new__";
  const showNew = (input, show) => { input.style.display = show ? "" : "none"; if (!show) input.value = ""; };
  const onlyNew = (select, label) => { select.innerHTML = `<option value="${NEW}" selected>＋ New ${label}…</option>`; select.disabled = false; };

  // Upload needs a release: an existing one, or a fully-named new chain (a "＋ New" pick
  // upstream forces "＋ New" downstream — a product that does not exist has no projects).
  const gate = () => {
    const relOK = sel.release.value && (sel.release.value !== NEW || (
      inp.release.value.trim() &&
      (sel.project.value !== NEW || inp.project.value.trim()) &&
      (sel.product.value !== NEW || inp.product.value.trim())));
    uploadBtn.disabled = !(relOK && fileText);
  };
  for (const input of Object.values(inp)) input.addEventListener("input", gate);

  sel.product.addEventListener("change", async () => {
    const isNew = sel.product.value === NEW;
    showNew(inp.product, isNew);
    loadedProjects = []; loadedReleases = [];
    if (isNew) { onlyNew(sel.project, "project"); onlyNew(sel.release, "release"); showNew(inp.project, true); showNew(inp.release, true); refreshEvidence(""); gate(); return; }
    sel.project.innerHTML = `<option value="">—</option>`; sel.project.disabled = true;
    sel.release.innerHTML = `<option value="">—</option>`; sel.release.disabled = true;
    showNew(inp.project, false); showNew(inp.release, false); refreshEvidence(""); gate();
    if (!sel.product.value) return;
    loadedProjects = asArray(await apiGET("registry", `/products/${encodeURIComponent(sel.product.value)}/projects`));
    sel.project.innerHTML = `<option value="">— pick a project —</option>` +
      loadedProjects.map((j) => `<option value="${esc(j.id)}">${esc(j.name)}</option>`).join("") +
      `<option value="${NEW}">＋ New project…</option>`;
    sel.project.disabled = false;
  });

  sel.project.addEventListener("change", async () => {
    const isNew = sel.project.value === NEW;
    showNew(inp.project, isNew);
    loadedReleases = [];
    if (isNew) { onlyNew(sel.release, "release"); showNew(inp.release, true); refreshEvidence(""); gate(); return; }
    sel.release.innerHTML = `<option value="">—</option>`; sel.release.disabled = true;
    showNew(inp.release, false); refreshEvidence(""); gate();
    if (!sel.project.value) return;
    loadedReleases = asArray(await apiGET("registry", `/projects/${encodeURIComponent(sel.project.value)}/releases`));
    sel.release.innerHTML = `<option value="">— pick a release —</option>` +
      loadedReleases.map((r) => `<option value="${esc(r.id)}">v${esc(r.version)}</option>`).join("") +
      `<option value="${NEW}">＋ New release…</option>`;
    sel.release.disabled = false;
  });

  sel.release.addEventListener("change", () => {
    const isNew = sel.release.value === NEW;
    showNew(inp.release, isNew);
    gate();
    if (isNew) { $("#sb-list").innerHTML = `<div class="empty"><b>A new release starts empty</b>Upload its first document above — it is registered on upload.</div>`; return; }
    refreshEvidence(sel.release.value);
  });

  fileInput.addEventListener("change", async () => {
    fileText = null; fileFormat = null; fileScanner = null;
    const f = fileInput.files[0];
    if (!f) { detect.textContent = "Pick a .json file — CycloneDX and SPDX are detected automatically."; gate(); return; }
    fileText = await f.text();
    let findings = null; // a curated scanner report ({findings:[…]} — TESTING.md's jq recipe)
    let translated = null; // a raw tool report a D16 translator recognized
    try {
      const j = JSON.parse(fileText);
      fileFormat = j.bomFormat === "CycloneDX" ? "cyclonedx" : (j.spdxVersion ? "spdx" : null);
      if (Array.isArray(j.findings)) {
        findings = j.findings.length;
        // The tool labels the evidence row (provenance_source — EDR-GUI-01 D14 / Phase A).
        const named = j.findings.find((x) => x && typeof x.scanner === "string" && x.scanner);
        fileScanner = named ? named.scanner : null;
      } else if (!fileFormat) {
        const tr = detectTranslator(j);
        if (tr) {
          // The curated shape stays the wire contract: what uploads is the translation,
          // never the vendor dialect (D16). Kind follows automatically — a translated
          // report uploaded as an SBOM would be a footgun, not a choice.
          const out = tr.translate(j);
          fileText = JSON.stringify({ findings: out.findings });
          fileScanner = tr.tool;
          findings = out.findings.length;
          translated = { tool: tr.tool, skipped: out.skipped };
          $("#sb-kind").value = "scanner-report";
        }
      }
    } catch { fileText = null; detect.textContent = "That file is not valid JSON — the trust gate would refuse it, so this form does too."; gate(); return; }
    detect.textContent = fileFormat
      ? `Detected ${fileFormat === "cyclonedx" ? "CycloneDX" : "SPDX"} · ${(f.size / 1024).toFixed(0)} KB`
      : (translated
        ? `Raw ${translated.tool} JSON — translated in-browser · ${findings} findings${translated.skipped ? ` (${translated.skipped} skipped: no CVE id or package name)` : ""} · Kind set to “Scanner report”.`
        : (findings !== null
          ? `Detected scanner report${fileScanner ? ` (${fileScanner})` : ""} · ${findings} findings — set Kind to “Scanner report”.`
          : `Format not recognized (${(f.size / 1024).toFixed(0)} KB) — uploading anyway lets Evidence decide.`));
    gate();
  });

  // regCreate registers one Registry entity and returns its id; a refusal surfaces verbatim.
  async function regCreate(path, body, what) {
    const r = await apiPOST("registry", path, body);
    if (r.status !== 201 && r.status !== 200) throw new Error(`cannot register ${what}: ${await problemDetail(r)}`);
    const j = await r.json();
    if (!j.id) throw new Error(`cannot register ${what}: the Registry returned no id`);
    return j.id;
  }

  // solidify turns a just-registered entity into a normal dropdown entry, selected — so a
  // follow-up upload (a scan against the build just filed) needs no re-typing.
  function solidify(select, input, id, label) {
    const opt = document.createElement("option");
    opt.value = id; opt.textContent = label;
    select.insertBefore(opt, select.querySelector(`option[value="${NEW}"]`));
    select.value = id;
    showNew(input, false);
  }

  // resolveRelease returns the release id to file against, registering the "＋ New" chain
  // first (product → project → release — the same order scripts/gf-upload-sbom.sh drives).
  // Typing a name that already exists in the dropdown is refused: reuse is a pick, never a
  // duplicate registration.
  async function resolveRelease() {
    if (sel.release.value !== NEW) return sel.release.value;
    let productId = sel.product.value;
    if (productId === NEW) {
      const name = inp.product.value.trim();
      const dup = products.find((p) => p.name.toLowerCase() === name.toLowerCase());
      if (dup) throw new Error(`A product named “${name}” already exists — pick it from the list instead.`);
      productId = await regCreate("/products", { name }, "product");
      products.push({ id: productId, name });
      solidify(sel.product, inp.product, productId, name);
    }
    let projectId = sel.project.value;
    if (projectId === NEW) {
      const name = inp.project.value.trim();
      const dup = loadedProjects.find((j) => j.name.toLowerCase() === name.toLowerCase());
      if (dup) throw new Error(`A project named “${name}” already exists here — pick it from the list instead.`);
      projectId = await regCreate("/projects", { product_id: productId, name }, "project");
      loadedProjects.push({ id: projectId, name });
      solidify(sel.project, inp.project, projectId, name);
    }
    const version = inp.release.value.trim();
    const dup = loadedReleases.find((r) => r.version === version);
    if (dup) throw new Error(`Release v${version} already exists — pick it from the list instead.`);
    const releaseId = await regCreate("/releases", { project_id: projectId, version }, "release");
    loadedReleases.push({ id: releaseId, version });
    solidify(sel.release, inp.release, releaseId, `v${version}`);
    toast(`Registered v${version} — new release id ${releaseId.slice(0, 8)}…`);
    return releaseId;
  }

  uploadBtn.addEventListener("click", async () => {
    uploadBtn.disabled = true; uploadBtn.innerHTML = `<span class="spin"></span> Uploading…`;
    try {
      const releaseId = await resolveRelease();
      const body = { kind: $("#sb-kind").value, subject_release_id: releaseId, document: fileText };
      // format names an SBOM standard; Evidence uses it only for the sbom kind, so a VEX or
      // scanner-report upload never sends one.
      if (fileFormat && body.kind === "sbom") body.format = fileFormat;
      // The report's own scanner field labels the row — provenance only, never authority (D14).
      if (fileScanner && body.kind === "scanner-report") body.provenance_source = fileScanner;
      const r = await fetch("/api/evidence/evidence", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const j = await r.json().catch(() => ({}));
      if (r.status === 201) {
        toast("Evidence registered — correlation runs in the background; check the release posture shortly.");
      } else if (r.status === 200 && j.created === false) {
        toast("Already registered — byte-identical content dedups to the same evidence id.");
      } else if (r.status === 422 || r.status === 400) {
        toast(`Rejected: ${j.detail || j.title || r.status} — check the release id and document.`);
      } else if (r.status === 502) {
        toast("Evidence node unreachable.");
      } else {
        toast(`Upload returned ${r.status}.`);
      }
      refreshEvidence(sel.release.value);
    } catch (e) { toast(e.message); }
    uploadBtn.disabled = false; uploadBtn.textContent = "Upload";
  });

  async function refreshEvidence(releaseId) {
    const host = $("#sb-list");
    if (!releaseId) { host.innerHTML = `<div class="empty">Pick a release to list its evidence.</div>`; return; }
    host.innerHTML = `<div class="loading"><span class="spin"></span></div>`;
    try {
      const ev = asArray(await apiGET("evidence", `/evidence?release=${encodeURIComponent(releaseId)}`));
      host.innerHTML = ev.length ? `<div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>Kind</th><th>Source</th><th>Evidence id</th><th>Fingerprint</th><th>Filed</th></tr></thead>
        <tbody>${ev.map((e) => `<tr><td>${esc(e.kind)}</td>
          <td>${e.provenance_source ? `<span class="chip chip-accent" title="who produced the document (D14) — labeling only, never authority">${esc(e.provenance_source)}</span>` : "—"}</td>
          <td><span class="mono">${esc(e.id)}</span></td>
          <td><span class="mono">${esc((e.fingerprint || "").slice(0, 16))}…</span></td>
          <td title="${esc(e.filed_at || "")}">${esc(timeAgo(e.filed_at))}</td></tr>`).join("")}</tbody></table></div>
        <p class="card-sub" style="margin-top:10px"><a href="#/release/${esc(releaseId)}">Open this release's posture →</a></p>`
        : `<div class="empty"><b>No evidence filed yet</b>Upload the first SBOM above.</div>`;
    } catch (e) { host.innerHTML = `<div class="err">${esc(e.message)}</div>`; }
  }
}

/* ---------- drawer: one Finding ---------- */

let drawerDirty = false; // a decision happened — the posture behind is stale
let highlightPid = null; // a proposal that just arrived — emphasized once on the next render

/* GUI-1, decided D1: the explanation AUTO-RUNS when the drawer opens. The three mitigations
   that make auto-run affordable: a SESSION CACHE (reopening the same drawer costs nothing —
   in-memory only, gone on refresh), a NON-BLOCKING load (the drawer renders its evidence first
   and never waits on the AI), and ENABLED-ONLY rendering (a disabled or unreachable AI plane
   leaves no dead placeholder — the section simply stays hidden). */
const explainCache = new Map(); // finding_id → rendered HTML (200s only)
const explainInflight = new Map(); // finding_id → pending request, so a reload never double-spends

function explainRequest(fid) {
  let p = explainInflight.get(fid);
  if (p) return p;
  p = (async () => {
    const r = await apiPOST("intelligence", "/capabilities/explain_vulnerability/invoke",
      { subject: { type: "finding", ids: [fid] } });
    if (r.status === 200) {
      const j = await r.json();
      const html = `<div class="plan-head">${aiProvenance(j)}</div>
        <div class="plan-text">${aiProse(j.information || "")}</div>`;
      explainCache.set(fid, html);
      return html;
    }
    if (r.status === 204) {
      const reason = r.headers.get("X-Themis-AI-Reason");
      if (reason === "disabled" || reason === "unreachable") return null; // enabled-only
      return aiOutcomeHTML(reason); // insufficient / budget / grounding — worth showing
    }
    if (r.status === 404) return null; // an older node without the capability — no placeholder
    return `<div class="err">explain returned ${r.status}: ${esc(await problemDetail(r))}</div>`;
  })();
  explainInflight.set(fid, p);
  p.catch(() => {}).then(() => explainInflight.delete(fid));
  return p;
}

async function loadExplain(fid, body) {
  const sec = $("#explain-sec", body), out = $("#explain-out", body);
  if (!sec || !fid) return;
  const show = (html) => { sec.hidden = false; out.innerHTML = html; };
  const cached = explainCache.get(fid);
  if (cached) return show(cached);
  show(`<div class="empty"><b>Explaining…</b>Local model — may take a minute; the drawer stays usable and the answer fills in here.</div>`);
  let html = null;
  try { html = await explainRequest(fid); } catch { /* NodeDown → no dead placeholder */ }
  if (!sec.isConnected) return; // the drawer re-rendered while we waited; the next render re-asks the cache
  if (html === null) { sec.hidden = true; out.innerHTML = ""; return; }
  show(html);
}

function closeDrawer() {
  $("#drawer").hidden = true; $("#drawer-scrim").hidden = true;
  if (drawerDirty) { drawerDirty = false; route(); }
}
$("#drawer-close").addEventListener("click", closeDrawer);
$("#drawer-scrim").addEventListener("click", closeDrawer);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

async function openDrawer(entry) {
  const d = $("#drawer"), body = $("#drawer-body");
  $("#drawer-title").innerHTML = `<span class="mono">${esc(entry.cve)}</span> ${bandChip(entry.band)} ${stanceChip(entry.stance, entry.has_position)}`;
  body.innerHTML = `<div class="loading"><span class="spin"></span>Loading assessment…</div>`;
  d.hidden = false; $("#drawer-scrim").hidden = false;

  let assessment = null, similar = null;
  try { assessment = await apiGET("governance", `/findings/${encodeURIComponent(entry.finding_id)}/assessment`); } catch { /* rendered below */ }
  try { similar = await apiGET("intelligence", `/findings/${encodeURIComponent(entry.finding_id)}/similar?k=5`); } catch { /* node optional */ }

  const k = assessment ? (assessment.knowledge || {}) : {};
  const f = assessment ? (assessment.finding || {}) : {};
  const ranges = (k.affected_ranges || []);
  const shownRanges = ranges.slice(0, 6);
  const proposals = (f.proposals || []);
  const precedents = similar ? (similar.precedents || []) : null;

  body.innerHTML = `
    <section>
      <h3 class="section-h">What Knowledge knows</h3>
      ${assessment && k.summary ? `<p class="cve-summary">${esc(k.summary)}${k.summary_source ? ` <span class="chip chip-info" title="which source's words these are">${esc(k.summary_source)}</span>` : ""}</p>` : ""}
      ${assessment ? `<dl class="kv">
        <dt>Severity</dt><dd>${esc(k.severity || "unknown")}${k.cvss_score ? ` · CVSS ${esc(k.cvss_score)}` : ""}</dd>
        <dt>Exploit signals</dt><dd>
          ${k.kev ? `<span class="chip chip-crit"><i></i>KEV</span> ` : ""}
          ${k.exploit_public ? `<span class="chip chip-serious"><i></i>public exploit</span> ` : ""}
          ${typeof k.epss === "number" ? `<span class="chip">EPSS ${(k.epss * 100).toFixed(1)}%</span>` : ""}
          ${!k.kev && !k.exploit_public && typeof k.epss !== "number" ? "none recorded" : ""}</dd>
        <dt>Affected ranges</dt><dd>${shownRanges.length ? shownRanges.map((r) => `<span class="mono">${esc(r)}</span>`).join(" ") : "none recorded"}${ranges.length > shownRanges.length ? ` <span class="chip chip-info">+${ranges.length - shownRanges.length} more (not shown)</span>` : ""}</dd>
        <dt>Fixes (attributed)</dt><dd>${(k.fixes || []).length ? k.fixes.map((x) => `<span class="mono">${esc(x.package ? x.package + " → " : "")}${esc(x.version)}</span>`).join(" ") : "none for these components"}</dd>
      </dl>` : `<div class="err">Assessment unavailable — Governance (or its Knowledge read) did not answer.</div>`}
    </section>

    <section id="explain-sec" hidden>
      <h3 class="section-h">What it means here <span class="chip chip-accent" title="Information (T7): ephemeral, never stored. The summary above is evidence; this is the AI's overlay on it — what the flaw means for THESE components">AI</span> ${LOCAL_ONLY_CHIP}</h3>
      <div id="explain-out"></div>
    </section>

    <section>
      <h3 class="section-h">Matched components</h3>
      ${(f.components || entry.components || []).map((c) =>
        `<div style="margin:3px 0"><span class="mono">${esc(c.purl || c.name)}</span>${claimNote(c.claim_class)}${c.source ? ` <span class="chip chip-info" title="source package a fix ships under">src: ${esc(c.source)}</span>` : ""}${c.detection_origin && c.detection_origin !== "discovery" ? ` <span class="chip chip-accent" title="which engine produced this match (KN-SCAN-2) — provenance only, never authority; unmarked components came from feed discovery">found by ${esc(c.detection_origin)}</span>` : ""}</div>`
      ).join("") || `<div class="empty">none recorded</div>`}
    </section>

    <section>
      <h3 class="section-h">Similar past decisions <span class="chip chip-accent" title="semantic precedent — retrieved, no model runs">no AI</span></h3>
      <div id="precedents">
        ${precedents === null ? `<div class="empty"><b>Precedent unavailable</b>The Intelligence node is not running, or has no retrieval plane (no store DSN).</div>`
          : precedents.length === 0 ? `<div class="empty"><b>No precedent found</b>Nothing decided so far resembles this Finding — the ordinary answer on a young deployment.</div>`
          : precedents.map((p) => `<div class="prec">
              <div class="prec-top"><span class="mono">${esc(p.source_cve || "same CVE")}</span>
                ${stanceChip(p.stance, true)}
                <span class="chip chip-info">release ${esc((p.release_id || "").slice(0, 8))}</span>
                <span class="prec-score"><span class="prec-score-bar"><i style="width:${Math.round((p.score || 0) * 100)}%"></i></span>${p.score ? (p.score).toFixed(2) : "exact"}</span></div>
              ${p.rationale ? `<div class="prec-rationale">${esc(p.rationale)}</div>` : ""}
            </div>`).join("")}
      </div>
      <p class="card-sub" style="margin-top:8px">Contradictory stances here are information, not an error — it is exactly when the AI declines and a human should look.</p>
    </section>

    <section>
      <h3 class="section-h">Decide</h3>
      ${f.current_position ? `<p class="card-sub" style="margin:0 0 10px">Current position:
        ${stanceChip(f.current_position.stance, true)} <span class="chip chip-info">v${esc(f.current_position.version ?? "?")}</span>
        — a new accepted proposal appends the next immutable version; nothing is ever overwritten.</p>` : ""}
      <div class="form-grid">
        <label>Stance
          <select id="dc-stance">
            <option value="affected">affected — it applies here</option>
            <option value="not_affected">not_affected — suppresses (with the premise recorded)</option>
            <option value="mitigated">mitigated — compensating control in place</option>
            <option value="accepted_risk">accepted_risk — suppresses until review</option>
            <option value="under_investigation">under_investigation</option>
            <option value="deferred">deferred</option>
          </select></label>
        <label>Rationale — why, in your words (this becomes the audit record)
          <textarea id="dc-rationale" rows="2" placeholder="e.g. vulnerable function unreachable; loader is SafeLoader throughout"></textarea></label>
        <label id="dc-review-wrap" hidden>Review by — when this suppression should resurface (optional; empty means no date was agreed)
          <input type="date" id="dc-review"></label>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn" id="dc-raise">Raise proposal</button>
          <button class="btn btn-primary" id="dc-raise-accept">Raise &amp; accept</button>
        </div>
        <p class="card-sub" style="margin:0">Raise records your view for someone else to decide; Raise &amp; accept performs both steps as ${esc(WHO)} — still two audit entries, never one.</p>
      </div>
    </section>

    <section>
      <h3 class="section-h">Proposals on record</h3>
      ${proposals.length ? proposals.map((p) => `<div class="prec" data-pid="${esc(p.id)}">
          <div class="prec-top">${stanceChip(p.stance, true)}
            <span class="chip">${esc(p.proposer_kind)}</span>${trustChip(p.evidence_trust)}
            <span class="chip ${p.status === "accepted" ? "chip-good" : (p.status === "rejected" ? "chip-crit" : "")}">${esc(p.status)}</span>
            <span class="act-when">${timeAgo(p.raised_at)}</span></div>
          ${p.rationale ? `<div class="prec-rationale">${esc(p.rationale)}</div>` : ""}
          ${p.status === "pending" ? `<div style="display:flex;gap:8px;margin-top:4px">
            <button class="btn dc-accept" data-pid="${esc(p.id)}" data-stance="${esc(p.stance)}">Accept</button>
            <button class="btn dc-reject" data-pid="${esc(p.id)}">Reject</button>
            ${p.evidence_trust === "inferred" ? `<span class="chip chip-warn" title="EDR-TRUST-01 T4: no policy may auto-accept inferred evidence — these buttons ARE the human decision it reserves">policy cannot auto-accept this; you can</span>` : ""}
          </div>` : ""}
        </div>`).join("") : `<div class="empty">No proposals yet — raise one above, or ask the AI below.</div>`}
    </section>

    ${entry.has_position ? `<section>
      <h3 class="section-h">Publish</h3>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <select id="pub-format" class="btn" style="padding:6px 10px">
          <option value="openvex">OpenVEX</option><option value="cyclonedx-vex">CycloneDX-VEX</option>
          <option value="csaf">CSAF</option><option value="markdown">Markdown advisory</option>
        </select>
        <button class="btn btn-primary" id="btn-publish">Publish this position</button>
      </div>
      <p class="card-sub" style="margin-top:8px">Human-triggered, always — materializes the current Position as an immutable artifact; a later revision supersedes, never edits.</p>
    </section>` : ""}

    <section>
      <h3 class="section-h">Ask the AI ${LOCAL_ONLY_CHIP}</h3>
      <button class="btn btn-primary" id="btn-recommend">Recommend a position</button>
      <div id="ai-outcome-wrap"></div>
      <p class="card-sub" style="margin-top:8px">Records an <b>advisory</b> proposal a human or policy must accept — it never decides. A quiet answer is a safe outcome, not an error.</p>
    </section>`;

  /* --- the human decision flow (DOM-0024: proposal -> accept -> Position) --- */

  const fid = entry.finding_id;
  const reload = () => { drawerDirty = true; openDrawer(entry); };

  const suppressing = (st) => st === "not_affected" || st === "accepted_risk";
  const stanceSel = $("#dc-stance");
  stanceSel.addEventListener("change", () => {
    $("#dc-review-wrap").hidden = !suppressing(stanceSel.value);
  });

  async function raiseProposal() {
    const body = {
      stance: stanceSel.value,
      rationale: $("#dc-rationale").value.trim(),
      proposer_kind: "human",
      proposer_id: WHO,
    };
    const r = await apiPOST("governance", `/findings/${encodeURIComponent(fid)}/proposals`, body);
    if (r.status !== 201 && r.status !== 200) throw new Error(`raise: ${await problemDetail(r)}`);
    const j = await r.json().catch(() => ({}));
    return j.proposal_id;
  }

  async function acceptProposal(pid, stance) {
    const body = { actor_id: WHO, actor_kind: "human" };
    if (suppressing(stance) && $("#dc-review").value) {
      body.review_by = new Date($("#dc-review").value + "T00:00:00Z").toISOString();
    }
    const r = await apiPOST("governance",
      `/findings/${encodeURIComponent(fid)}/proposals/${encodeURIComponent(pid)}/accept`, body);
    if (r.status === 403) throw new Error(`not authorized to decide: ${await problemDetail(r)}`);
    if (r.status !== 204) throw new Error(`accept: ${await problemDetail(r)}`);
  }

  $("#dc-raise").addEventListener("click", async (ev) => {
    const b = ev.currentTarget; b.disabled = true;
    try {
      await raiseProposal();
      toast("Proposal raised — pending a decision.");
      reload();
    } catch (e) { toast(e.message); b.disabled = false; }
  });

  $("#dc-raise-accept").addEventListener("click", async (ev) => {
    const b = ev.currentTarget; b.disabled = true;
    try {
      const pid = await raiseProposal();
      if (!pid) throw new Error("raise returned no proposal id");
      await acceptProposal(pid, stanceSel.value);
      toast(`Position established: ${stanceSel.value} (decided by ${WHO}).`);
      reload();
    } catch (e) { toast(e.message); b.disabled = false; }
  });

  body.querySelectorAll(".dc-accept").forEach((btn) => btn.addEventListener("click", async () => {
    btn.disabled = true;
    try {
      await acceptProposal(btn.dataset.pid, btn.dataset.stance);
      toast(`Position established: ${btn.dataset.stance} (decided by ${WHO}).`);
      reload();
    } catch (e) { toast(e.message); btn.disabled = false; }
  }));

  body.querySelectorAll(".dc-reject").forEach((btn) => btn.addEventListener("click", async () => {
    btn.disabled = true;
    try {
      const r = await apiPOST("governance",
        `/findings/${encodeURIComponent(fid)}/proposals/${encodeURIComponent(btn.dataset.pid)}/reject`,
        { actor_id: WHO, actor_kind: "human" });
      if (r.status !== 204) throw new Error(`reject: ${await problemDetail(r)}`);
      toast("Proposal rejected — the Finding keeps its current state.");
      reload();
    } catch (e) { toast(e.message); btn.disabled = false; }
  }));

  const pubBtn = $("#btn-publish");
  if (pubBtn) pubBtn.addEventListener("click", async () => {
    pubBtn.disabled = true;
    try {
      const r = await apiPOST("communication", "/publications", {
        finding_id: fid, artifact_type: "vex", format: $("#pub-format").value,
      });
      if (r.status !== 201 && r.status !== 200) throw new Error(`publish: ${await problemDetail(r)}`);
      toast("Published — see the Publications section on the release.");
      drawerDirty = true;
    } catch (e) { toast(e.message); }
    pubBtn.disabled = false;
  });

  $("#btn-recommend").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget;
    btn.disabled = true; btn.innerHTML = `<span class="spin"></span> Asking — local model, may take a minute…`;
    try {
      const r = await apiPOST("governance", `/findings/${encodeURIComponent(entry.finding_id)}/recommend`);
      if (r.status === 201) {
        const j = await r.json().catch(() => ({}));
        highlightPid = j.proposal_id || null;
        toast("Advisory proposal recorded.");
        reload();
        return; // the reload re-renders the drawer; this button no longer exists
      } else if (r.status === 204) {
        $("#ai-outcome-wrap").innerHTML = aiOutcomeHTML(r.headers.get("X-Themis-AI-Reason"));
      } else {
        toast(`Recommend returned ${r.status}.`);
      }
    } catch (e) {
      toast(e instanceof NodeDown ? "Governance unreachable." : e.message);
    }
    btn.disabled = false; btn.textContent = "Recommend a position";
  });

  if (highlightPid) {
    const el = body.querySelector(`.prec[data-pid="${CSS.escape(highlightPid)}"]`);
    highlightPid = null;
    if (el) {
      el.classList.add("prec-arrived");
      el.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }

  // Deliberately not awaited (D1: non-blocking) — the drawer is fully usable while it runs.
  loadExplain(entry.finding_id, body);
}

/* ---------- router ---------- */

function route() {
  closeDrawer();
  const h = location.hash || "#/";
  const rel = h.match(/^#\/release\/([^?]+)(?:\?v=([^&]*))?/);
  if (rel) return viewRelease(decodeURIComponent(rel[1]), rel[2] ? decodeURIComponent(rel[2]) : "");
  const scan = h.match(/^#\/scan\/([^?]+)\?rel=([^&]*)(?:&v=([^&]*))?/);
  if (scan) return viewScan(decodeURIComponent(scan[1]), decodeURIComponent(scan[2]), scan[3] ? decodeURIComponent(scan[3]) : "");
  if (h.startsWith("#/estate")) return viewEstate();
  if (h.startsWith("#/sbom")) return viewSBOM();
  if (h.startsWith("#/compare")) return viewCompare();
  if (h.startsWith("#/feeds")) return viewFeeds();
  return viewOverview();
}

window.addEventListener("hashchange", route);
route();
