const MODULES = {
  username: {
    eyebrow: "recon / username",
    title: "Username existence check",
    desc: "Checks whether a handle resolves across 30 platforms. Presence only — no bio/follower scraping.",
    placeholder: "mughal__hacker",
    endpoint: "/api/username",
  },
  email: {
    eyebrow: "recon / email",
    title: "Email security posture",
    desc: "Reputation, Gravatar, HIBP breach count (key required), disposable check, SPF/DKIM/DMARC.",
    placeholder: "you@yourdomain.com",
    endpoint: "/api/email",
  },
  phone: {
    eyebrow: "recon / phone",
    title: "Phone number metadata",
    desc: "Carrier block, region, line type, timezone — derived from the number format itself.",
    placeholder: "+92 300 1234567",
    endpoint: "/api/phone",
  },
  webscan: {
    eyebrow: "infrastructure / web scan",
    title: "Web scan — registration & expiry",
    desc: "Quick-glance card: when the domain was registered, when it expires, its age, and an expiry countdown. Same public WHOIS data as the domain module, just front and center.",
    placeholder: "example.com",
    endpoint: "/api/webscan",
  },
  domain: {
    eyebrow: "infrastructure / domain",
    title: "Domain intelligence",
    desc: "WHOIS, DNS, TLS certificate, subdomains via public CT logs, security header hygiene, and a domain-age trivia card.",
    placeholder: "example.com",
    endpoint: "/api/domain",
    showBirthYear: true,
  },
  ip: {
    eyebrow: "infrastructure / ip",
    title: "IP address intelligence",
    desc: "Geolocation, ASN/ISP, reverse DNS, DNSBL blacklist status, AbuseIPDB (key required).",
    placeholder: "8.8.8.8",
    endpoint: "/api/ip",
  },
  techstack: {
    eyebrow: "infrastructure / tech stack",
    title: "CMS & tech-stack fingerprint",
    desc: "One request to the homepage, matched against CMS/ecommerce/framework/CDN/analytics signatures — Wappalyzer-style. No crawling.",
    placeholder: "example.com",
    endpoint: "/api/techstack",
  },
  geo: {
    eyebrow: "place / geo scan",
    title: "Geo-OSINT mega scan",
    desc: "Weather, nearby amenities, Wikipedia summary, UK street-crime stats, recent earthquakes.",
    placeholder: "Lahore, Pakistan  or  31.5497,74.3436",
    endpoint: "/api/geo",
  },
  threat: {
    eyebrow: "threat intel / live feed",
    title: "Threat intelligence snapshot",
    desc: "Recent malware IOCs (ThreatFox), malicious URLs (URLhaus), published CVEs (NVD).",
    placeholder: "(no input needed — press run)",
    endpoint: "/api/threat",
    noInput: true,
  },
  fun: {
    eyebrow: "fun / realtime",
    title: "Fun realtime feeds",
    desc: "ISS position, planes overhead, ships overhead (needs free AISstream key), live weather-radar & night-lights links, NOAA space weather. Give it a place, or leave blank for global-only feeds (ISS + space weather).",
    placeholder: "Lahore, Pakistan  (optional)",
    endpoint: "/api/fun",
    optionalInput: true,
  },
  "hash-id": {
    eyebrow: "tools / hash identify",
    title: "Hash type identifier",
    desc: "Guesses the algorithm from a hash's length/format.",
    placeholder: "5d41402abc4b2a76b9719d911017c592",
    endpoint: "/api/tools/hash-id",
  },
  "hash-reputation": {
    eyebrow: "tools / hash reputation",
    title: "File hash reputation",
    desc: "VirusTotal lookup by file hash (key required).",
    placeholder: "sha256 or md5 of a file",
    endpoint: "/api/tools/hash-reputation",
  },
  "mac-vendor": {
    eyebrow: "tools / mac vendor",
    title: "MAC address vendor lookup",
    desc: "Resolves a MAC's OUI to the manufacturer via the public macvendors.com database.",
    placeholder: "F0:9F:C2:00:00:00",
    endpoint: "/api/tools/mac-vendor",
  },
  "url-reputation": {
    eyebrow: "tools / url reputation",
    title: "URL reputation check",
    desc: "Checks a URL against URLhaus's malicious-URL database.",
    placeholder: "https://example.com/path",
    endpoint: "/api/tools/url-reputation",
  },
  dorks: {
    eyebrow: "tools / dork generator",
    title: "Google dork generator",
    desc: "Builds standard recon search queries for a domain you're authorized to assess. Builds query strings only — nothing is executed.",
    placeholder: "example.com",
    endpoint: "/api/tools/dorks",
  },
  exif: {
    eyebrow: "tools / exif metadata",
    title: "EXIF metadata reader",
    desc: "Upload an image and see exactly what's embedded in it (camera, timestamp, GPS if present). Self-check tool — nothing leaves your machine, reads only the file you upload.",
    endpoint: "/api/tools/exif",
    fileUpload: true,
  },
  "live-dashboard": {
    eyebrow: "overview / live dashboard",
    title: "Live dashboard",
    desc: "Auto-refreshing overview: ISS position, space weather, latest threat-intel items, and this session's scan count. Updates on its own — no need to press run.",
    endpoint: "/api/live",
    live: true,
    pollMs: 15000,
  },
  "attack-map": {
    eyebrow: "overview / live attack map",
    title: "Live attack map",
    desc: "Recent malicious IPs from ThreatFox & URLhaus, geolocated and plotted on a world map. Dots pulse where the traffic is coming from — auto-refreshes.",
    endpoint: "/api/attack-map",
    live: true,
    pollMs: 20000,
  },
  radar: {
    eyebrow: "fun / radar",
    title: "ISS + planes mini radar",
    desc: "A sweeping radar view of the ISS's current bearing, plus any planes overhead if you give it a place. Optional — leave blank for a global ISS-only sweep.",
    placeholder: "Lahore, Pakistan  (optional — enables plane blips)",
    endpoint: "/api/radar",
    live: true,
    allowInput: true,
    pollMs: 6000,
  },
};

let currentMod = "username";
let lastResult = null;
let lastTarget = null;
let liveTimer = null;
let liveInputValue = "";
const LIVE_POLL_MS = 15000;

const $ = (sel) => document.querySelector(sel);
const consoleBody = $("#console-body");

function log(msg, cls = "") {
  const line = document.createElement("div");
  line.className = `console-line ${cls}`;
  const t = new Date().toLocaleTimeString([], { hour12: false });
  line.innerHTML = `<span class="t">${t}</span>${escapeHtml(msg)}`;
  consoleBody.appendChild(line);
  consoleBody.scrollTop = consoleBody.scrollHeight;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function stopLivePolling() {
  if (liveTimer) {
    clearInterval(liveTimer);
    liveTimer = null;
  }
}

function startLivePolling() {
  stopLivePolling();
  const m = MODULES[currentMod];
  runLiveSnapshot();
  liveTimer = setInterval(runLiveSnapshot, (m && m.pollMs) || LIVE_POLL_MS);
}

const LIVE_RENDERERS = {
  "live-dashboard": renderLiveDashboard,
  "attack-map": renderAttackMap,
  "radar": renderRadar,
};

async function runLiveSnapshot() {
  const requestedMod = currentMod;
  const m = MODULES[requestedMod];
  if (!m || !m.live) return;
  try {
    let url = m.endpoint;
    if (requestedMod === "radar" && liveInputValue) {
      url += `?place=${encodeURIComponent(liveInputValue)}`;
    }
    const resp = await fetch(url);
    const json = await resp.json();
    if (requestedMod !== currentMod) return; // user switched modules while this was in flight
    lastResult = json;
    lastTarget = requestedMod;
    const renderer = LIVE_RENDERERS[requestedMod] || renderLiveDashboard;
    renderer(json);
  } catch (err) {
    if (requestedMod === currentMod) log(`${requestedMod} poll failed: ${err.message}`, "err");
  }
}

function selectModule(name) {
  stopLivePolling();
  currentMod = name;
  liveInputValue = "";
  const m = MODULES[name];
  document.querySelectorAll(".modbtn").forEach((b) => b.classList.toggle("active", b.dataset.mod === name));
  $("#mod-eyebrow").textContent = m.eyebrow;
  $("#mod-title").textContent = m.title;
  $("#mod-desc").textContent = m.desc;

  const showQueryForm = !m.fileUpload && (!m.live || m.allowInput);
  $("#query-form").hidden = !showQueryForm;
  $("#file-form").hidden = !m.fileUpload;
  $("#file-run-btn").disabled = false;
  $("#file-run-btn").textContent = "read metadata";
  if (!m.fileUpload) $("#file-input").value = "";

  $("#query-input").value = "";
  $("#query-input").placeholder = m.placeholder || "";
  $("#query-input").disabled = !!m.noInput;

  $("#birth-year-input").hidden = !m.showBirthYear;
  $("#birth-year-input").value = "";

  $("#run-btn").disabled = false;
  $("#run-btn").textContent = m.live ? "start" : "run";

  $("#export-bar").hidden = true;

  if (m.live) {
    $("#results").innerHTML = `<div class="empty-state"><pre>connecting…</pre></div>`;
    startLivePolling();
  } else {
    $("#results").innerHTML = `<div class="empty-state"><pre>┌──────────────────────────────┐\n│  awaiting target...           │\n└──────────────────────────────┘</pre></div>`;
  }
}

document.querySelectorAll(".modbtn").forEach((btn) => {
  btn.addEventListener("click", () => selectModule(btn.dataset.mod));
});

$("#query-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const requestedMod = currentMod;
  const m = MODULES[requestedMod];

  if (m.live) {
    // Live modules (currently just radar) that accept an optional input:
    // update the live-poll parameter and refresh immediately instead of
    // doing a normal one-shot POST/render cycle.
    liveInputValue = $("#query-input").value.trim();
    log(`> ${requestedMod} ${liveInputValue || "(global)"}`);
    runLiveSnapshot();
    return;
  }

  const target = m.noInput ? "feed" : $("#query-input").value.trim();
  if (!m.noInput && !m.optionalInput && !target) {
    log("no target entered", "warn");
    return;
  }

  const btn = $("#run-btn");
  btn.disabled = true;
  btn.textContent = "running…";
  log(`> ${requestedMod} ${target}`);
  $("#results").innerHTML = `<div class="empty-state"><pre>scanning...</pre></div>`;

  try {
    const body = { target };
    if (m.showBirthYear) {
      const by = $("#birth-year-input").value.trim();
      if (by) body.birth_year = by;
    }
    const resp = await fetch(m.endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const json = await resp.json();
    if (requestedMod !== currentMod) return; // module was switched while this was in flight — discard
    lastResult = json;
    lastTarget = target;
    render(json);
    log(`✓ ${requestedMod} done (status: ${json.status})`, json.status === "ok" ? "ok" : "warn");
    $("#export-bar").hidden = false;
  } catch (err) {
    if (requestedMod !== currentMod) return;
    log(`✗ ${err.message}`, "err");
    $("#results").innerHTML = `<div class="card"><div class="card-head"><span class="pill error">error</span> network</div><div class="card-body">${escapeHtml(err.message)}</div></div>`;
  } finally {
    if (requestedMod === currentMod) {
      btn.disabled = false;
      btn.textContent = m.live ? "start" : "run";
    }
  }
});

$("#file-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const requestedMod = currentMod;
  const m = MODULES[requestedMod];
  const fileInput = $("#file-input");
  const file = fileInput.files[0];
  if (!file) {
    log("no image selected", "warn");
    return;
  }

  const btn = $("#file-run-btn");
  btn.disabled = true;
  btn.textContent = "reading…";
  log(`> ${requestedMod} ${file.name}`);
  $("#results").innerHTML = `<div class="empty-state"><pre>reading metadata...</pre></div>`;

  try {
    const fd = new FormData();
    fd.append("image", file);
    const resp = await fetch(m.endpoint, { method: "POST", body: fd });
    const json = await resp.json();
    if (requestedMod !== currentMod) return; // module was switched while this was in flight — discard
    lastResult = json;
    lastTarget = file.name;
    render(json);
    log(`✓ ${requestedMod} done (status: ${json.status})`, json.status === "ok" ? "ok" : "warn");
    $("#export-bar").hidden = false;
  } catch (err) {
    if (requestedMod !== currentMod) return;
    log(`✗ ${err.message}`, "err");
    $("#results").innerHTML = `<div class="card"><div class="card-head"><span class="pill error">error</span> network</div><div class="card-body">${escapeHtml(err.message)}</div></div>`;
  } finally {
    if (requestedMod === currentMod) {
      btn.disabled = false;
      btn.textContent = "read metadata";
    }
  }
});

function pill(status) {
  return `<span class="pill ${status}">${status}</span>`;
}

function renderValue(val) {
  if (val === null || val === undefined) return `<span style="color:var(--muted)">—</span>`;
  if (typeof val === "boolean") return val ? `<span style="color:var(--accent)">true</span>` : `<span style="color:var(--red)">false</span>`;
  if (Array.isArray(val)) {
    if (val.length === 0) return `<span style="color:var(--muted)">none</span>`;
    if (typeof val[0] === "object") return `<pre class="raw">${escapeHtml(JSON.stringify(val, null, 2))}</pre>`;
    return val.map(escapeHtml).join(", ");
  }
  if (typeof val === "object") return `<pre class="raw">${escapeHtml(JSON.stringify(val, null, 2))}</pre>`;
  const str = String(val);
  if (/^https?:\/\//.test(str)) return `<a class="link" href="${escapeHtml(str)}" target="_blank" rel="noopener">${escapeHtml(str)}</a>`;
  return escapeHtml(str);
}

function kvCard(title, status, obj, sourceLabel) {
  const rows = Object.entries(obj || {})
    .map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd>${renderValue(v)}</dd>`)
    .join("");
  return `<div class="card">
    <div class="card-head">${pill(status)} ${escapeHtml(title)} ${sourceLabel ? `<span style="margin-left:auto;color:var(--muted)">${escapeHtml(sourceLabel)}</span>` : ""}</div>
    <div class="card-body"><dl class="kv">${rows}</dl></div>
  </div>`;
}

function triviaCard(node) {
  if (!node) return "";
  if (node.status !== "ok") {
    return `<div class="card trivia"><div class="card-head">${pill(node.status)} domain age trivia</div><div class="card-body" style="color:var(--muted)">${escapeHtml(node.reason || "no data")}</div></div>`;
  }
  const facts = node.data.facts || [];
  const items = facts.map((f) => `<li>${escapeHtml(f)}</li>`).join("");
  return `<div class="card trivia">
    <div class="card-head">${pill("ok")} domain age trivia <span style="margin-left:auto;color:var(--muted)">registered ${escapeHtml(node.data.registered_on || "")}</span></div>
    <div class="card-body"><ul class="trivia-facts">${items}</ul></div>
  </div>`;
}

const _EXPIRY_LABEL = {
  healthy: "ok", warning: "warning", critical: "warning", expired: "error", unknown: "skipped",
};

function webscanCard(data) {
  const expiryPill = _EXPIRY_LABEL[data.expiry_status] || "skipped";
  const daysLeft = data.days_until_expiry;
  let expiryLine = "unknown";
  if (daysLeft !== null && daysLeft !== undefined) {
    expiryLine = daysLeft < 0
      ? `expired ${Math.abs(daysLeft)} days ago`
      : `${daysLeft} days left`;
  }
  const facts = (data.facts || []).map((f) => `<li>${escapeHtml(f)}</li>`).join("");
  return `<div class="card trivia">
    <div class="card-head">${pill("ok")} web scan — ${escapeHtml(data.domain)} <span style="margin-left:auto;color:var(--muted)">registrar: ${escapeHtml(data.registrar || "—")}</span></div>
    <div class="card-body">
      <dl class="kv">
        <dt>registered on</dt><dd>${escapeHtml(data.registered_on || "unknown")}</dd>
        <dt>expires on</dt><dd>${escapeHtml(data.expires_on || "unknown")} ${pill(expiryPill)} <span style="color:var(--muted)">${escapeHtml(expiryLine)}</span></dd>
        <dt>age</dt><dd>${data.age_years ?? "?"} years (${data.age_days ?? "?"} days)</dd>
        <dt>status codes</dt><dd>${renderValue(data.status_codes)}</dd>
        <dt>name servers</dt><dd>${renderValue(data.name_servers)}</dd>
      </dl>
      ${facts ? `<ul class="trivia-facts">${facts}</ul>` : ""}
    </div>
  </div>`;
}

function usernameTable(data) {
  const rows = data.results.map((r) => `
    <tr class="${r.exists ? "hit" : ""}">
      <td>${r.exists ? "●" : r.exists === false ? "○" : "?"}</td>
      <td>${escapeHtml(r.platform)}</td>
      <td>${r.exists ? `<a class="link" href="${escapeHtml(r.url)}" target="_blank" rel="noopener">${escapeHtml(r.url)}</a>` : escapeHtml(r.url)}</td>
    </tr>`).join("");
  return `<div class="card">
    <div class="card-head">${pill("ok")} ${data.found_count}/${data.checked} platforms matched</div>
    <div class="card-body"><table class="results-table"><thead><tr><th></th><th>platform</th><th>url</th></tr></thead><tbody>${rows}</tbody></table></div>
  </div>`;
}

function genericCard(title, node) {
  if (!node || typeof node !== "object") return "";
  if ("status" in node && "data" in node) {
    if (node.status !== "ok") {
      return `<div class="card"><div class="card-head">${pill(node.status)} ${escapeHtml(title)}</div><div class="card-body" style="color:var(--muted)">${escapeHtml(node.reason || "no data")}${node.source ? ` · ${escapeHtml(node.source)}` : ""}</div></div>`;
    }
    if (Array.isArray(node.data)) {
      return `<div class="card"><div class="card-head">${pill("ok")} ${escapeHtml(title)}</div><div class="card-body"><pre class="raw">${escapeHtml(JSON.stringify(node.data, null, 2))}</pre></div></div>`;
    }
    return kvCard(title, "ok", node.data, node.source);
  }
  return kvCard(title, "ok", node);
}

function render(result) {
  const container = $("#results");
  if (result.status !== "ok") {
    container.innerHTML = `<div class="card"><div class="card-head">${pill(result.status)} ${escapeHtml(currentMod)}</div><div class="card-body">${escapeHtml(result.reason || "no data")}</div></div>`;
    return;
  }

  const data = result.data;
  let html = "";

  if (currentMod === "username") {
    html = usernameTable(data);
  } else if (currentMod === "webscan") {
    html = webscanCard(data);
  } else if (typeof data === "object" && !Array.isArray(data)) {
    // Compose a card per sub-section (most modules return {field: envelope, ...})
    for (const [key, val] of Object.entries(data)) {
      if (key === "age_trivia") {
        html += triviaCard(val);
        continue;
      }
      if (val && typeof val === "object" && "status" in val) {
        html += genericCard(key, val);
      }
    }
    if (!html) html = kvCard(currentMod, "ok", data, result.source);
  } else {
    html = `<div class="card"><div class="card-head">${pill("ok")} ${escapeHtml(currentMod)}</div><div class="card-body"><pre class="raw">${escapeHtml(JSON.stringify(data, null, 2))}</pre></div></div>`;
  }

  container.innerHTML = html || `<div class="empty-state">no data returned</div>`;
}

function renderLiveDashboard(result) {
  const container = $("#results");
  if (result.status !== "ok") {
    container.innerHTML = `<div class="card"><div class="card-head">${pill(result.status)} live dashboard</div><div class="card-body">${escapeHtml(result.reason || "no data")}</div></div>`;
    return;
  }
  const data = result.data;
  const stamp = new Date().toLocaleTimeString([], { hour12: false });
  let html = `<div class="card"><div class="card-head">${pill("ok")} session <span style="margin-left:auto;color:var(--muted)">last updated ${stamp}</span></div>
    <div class="card-body"><dl class="kv">
      <dt>scans run</dt><dd>${data.session.scans_run}</dd>
      <dt>uptime</dt><dd>${data.session.uptime_seconds}s</dd>
    </dl></div></div>`;
  html += genericCard("ISS position", data.iss_position);
  html += genericCard("space weather", data.space_weather);
  html += genericCard("recent malware IOCs", data.recent_malware_iocs);
  html += genericCard("recent malicious URLs", data.recent_malicious_urls);
  container.innerHTML = html;
}

/* ============================================================
   Live attack map — dotted world-map SVG background + animated
   pulsing dots for geolocated ThreatFox/URLhaus IOCs.
   ============================================================ */

// Very simplified continent outlines (lon, lat) — decorative dotted
// background only, not cartographically precise.
const _CONTINENTS = [
  // North America
  [[-165,68],[-150,70],[-130,70],[-95,68],[-80,62],[-65,50],[-55,48],[-60,45],
   [-75,35],[-80,25],[-97,18],[-105,20],[-115,30],[-125,40],[-124,49],[-130,55],[-140,60],[-165,68]],
  // Central America land bridge
  [[-92,16],[-84,10],[-78,8],[-77,1],[-84,9],[-90,14],[-92,16]],
  // South America
  [[-80,10],[-77,0],[-70,-18],[-70,-30],[-73,-45],[-68,-55],[-65,-55],[-58,-38],
   [-48,-25],[-35,-8],[-50,5],[-60,10],[-73,10],[-80,10]],
  // Africa
  [[-17,15],[-10,5],[10,4],[15,-5],[12,-18],[18,-34],[30,-30],[40,-15],[50,-5],
   [45,10],[38,15],[32,22],[25,32],[10,37],[-6,35],[-10,30],[-17,15]],
  // Europe
  [[-10,43],[-5,50],[0,52],[5,58],[10,60],[20,60],[30,60],[40,55],[35,45],
   [28,42],[20,40],[15,38],[0,40],[-10,43]],
  // Asia (mainland)
  [[30,45],[40,40],[50,45],[60,50],[70,55],[80,50],[90,50],[100,50],[110,50],
   [120,45],[130,45],[140,50],[150,60],[160,65],[170,68],[180,68],[150,72],
   [120,73],[100,75],[80,73],[60,68],[50,60],[40,55],[30,45]],
  // Middle East / South-Central Asia / China band (closes gaps between the
  // Africa, Europe, and Asia-mainland polygons above)
  [[25,32],[35,30],[45,25],[55,25],[60,30],[70,25],[80,20],[90,22],[100,15],
   [105,10],[110,5],[120,10],[125,20],[130,25],[135,35],[125,40],[110,40],
   [95,40],[80,38],[65,40],[50,38],[35,38],[25,32]],
  // Australia
  [[113,-22],[122,-14],[132,-11],[142,-11],[147,-19],[153,-28],[150,-38],
   [140,-38],[131,-32],[122,-34],[114,-32],[113,-22]],
];

function _pointInPolygon(lon, lat, poly) {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const [xi, yi] = poly[i], [xj, yj] = poly[j];
    const intersect = ((yi > lat) !== (yj > lat)) &&
      (lon < (xj - xi) * (lat - yi) / (yj - yi) + xi);
    if (intersect) inside = !inside;
  }
  return inside;
}

function _isLand(lon, lat) {
  return _CONTINENTS.some((poly) => _pointInPolygon(lon, lat, poly));
}

const MAP_W = 1000, MAP_H = 500;
function _projectMap(lat, lon) {
  const x = ((lon + 180) / 360) * MAP_W;
  const y = ((90 - lat) / 180) * MAP_H;
  return [x, y];
}

let _landDotsCache = null;
function _landDotsSvg() {
  if (_landDotsCache) return _landDotsCache;
  let dots = "";
  for (let lat = -85; lat <= 85; lat += 4) {
    for (let lon = -180; lon <= 180; lon += 4) {
      if (_isLand(lon, lat)) {
        const [x, y] = _projectMap(lat, lon);
        dots += `<circle class="map-land-dot" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="1.4"/>`;
      }
    }
  }
  _landDotsCache = dots;
  return dots;
}

function renderAttackMap(result) {
  const container = $("#results");
  if (result.status !== "ok") {
    container.innerHTML = `<div class="card"><div class="card-head">${pill(result.status)} live attack map</div><div class="card-body">${escapeHtml(result.reason || "no data")}</div></div>`;
    return;
  }
  const points = result.data.points || [];
  const stamp = new Date().toLocaleTimeString([], { hour12: false });

  let dotsHtml = "";
  points.forEach((p, i) => {
    if (typeof p.lat !== "number" || typeof p.lon !== "number") return;
    const [x, y] = _projectMap(p.lat, p.lon);
    const delay = (i % 12) * 0.18;
    dotsHtml += `<g class="map-attack" data-idx="${i}" tabindex="-1">
      <circle class="map-attack-ring" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="6" style="animation-delay:${delay}s"/>
      <circle class="map-attack-dot" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="2.4"/>
    </g>`;
  });

  const svg = `<svg viewBox="0 0 ${MAP_W} ${MAP_H}" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet">
    ${_landDotsSvg()}
    ${dotsHtml}
  </svg>`;

  const html = `<div class="card">
      <div class="card-head">${pill("ok")} ${points.length} sources plotted <span style="margin-left:auto;color:var(--muted)">last updated ${stamp}</span></div>
      <div class="card-body">
        <div class="map-wrap" id="attack-map-wrap">${svg}<div class="map-tooltip" id="map-tooltip" hidden></div></div>
        <div class="map-legend">
          <span><span class="swatch" style="background:var(--line)"></span>landmass (reference)</span>
          <span><span class="swatch" style="background:var(--red)"></span>malicious IP (ThreatFox / URLhaus)</span>
        </div>
      </div>
    </div>`;
  container.innerHTML = html;

  const wrap = $("#attack-map-wrap");
  const tooltip = $("#map-tooltip");
  wrap.querySelectorAll(".map-attack").forEach((g) => {
    const p = points[Number(g.dataset.idx)];
    if (!p) return;
    g.addEventListener("mousemove", (e) => {
      const rect = wrap.getBoundingClientRect();
      tooltip.hidden = false;
      tooltip.style.left = `${e.clientX - rect.left}px`;
      tooltip.style.top = `${e.clientY - rect.top}px`;
      tooltip.textContent = `${p.ip} · ${p.label} · ${p.city ? p.city + ", " : ""}${p.country || "unknown"}`;
    });
    g.addEventListener("mouseleave", () => { tooltip.hidden = true; });
  });
}

/* ============================================================
   Mini radar — ISS bearing/distance ping + planes-overhead blips
   on a sweeping radar-style SVG.
   ============================================================ */

function _toRad(d) { return (d * Math.PI) / 180; }
function _toDeg(r) { return (r * 180) / Math.PI; }

function _haversineBearingDistance(lat1, lon1, lat2, lon2) {
  const R = 6371; // km
  const dLat = _toRad(lat2 - lat1);
  const dLon = _toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2 +
    Math.cos(_toRad(lat1)) * Math.cos(_toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  const distanceKm = 2 * R * Math.asin(Math.sqrt(a));

  const y = Math.sin(dLon) * Math.cos(_toRad(lat2));
  const x = Math.cos(_toRad(lat1)) * Math.sin(_toRad(lat2)) -
    Math.sin(_toRad(lat1)) * Math.cos(_toRad(lat2)) * Math.cos(dLon);
  const bearingDeg = (_toDeg(Math.atan2(y, x)) + 360) % 360;

  return { distanceKm, bearingDeg };
}

const RADAR_CX = 100, RADAR_CY = 100, RADAR_MAX_R = 88;
// Local range (km) for plotting nearby planes at true relative scale.
const RADAR_LOCAL_RANGE_KM = 160;

function _radarPoint(bearingDeg, distanceKm, rangeKm) {
  const r = Math.min(RADAR_MAX_R, (distanceKm / rangeKm) * RADAR_MAX_R);
  const angle = _toRad(bearingDeg - 90); // 0deg = North = up
  return [RADAR_CX + r * Math.cos(angle), RADAR_CY + r * Math.sin(angle)];
}

function renderRadar(result) {
  const container = $("#results");
  if (result.status !== "ok") {
    container.innerHTML = `<div class="card"><div class="card-head">${pill(result.status)} radar</div><div class="card-body">${escapeHtml(result.reason || "no data")}</div></div>`;
    return;
  }
  const data = result.data;
  const center = data.center || {};
  const hasCenter = typeof center.lat === "number" && typeof center.lon === "number";
  const refLat = hasCenter ? center.lat : 0;
  const refLon = hasCenter ? center.lon : 0;

  let blipsHtml = "";
  let issLabel = "ISS: unavailable";

  if (data.iss_position && data.iss_position.status === "ok") {
    const iss = data.iss_position.data;
    const { distanceKm, bearingDeg } = _haversineBearingDistance(refLat, refLon, Number(iss.lat), Number(iss.lon));
    // ISS is essentially always far outside the local range — ping it at
    // the edge along its true bearing, like a long-range radar contact.
    const [x, y] = _radarPoint(bearingDeg, Math.max(distanceKm, RADAR_LOCAL_RANGE_KM * 0.92), RADAR_LOCAL_RANGE_KM);
    blipsHtml += `<circle class="radar-blip-iss" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="3.2"/>
      <text class="radar-blip-label" x="${x.toFixed(1)}" y="${(y - 5).toFixed(1)}" text-anchor="middle">ISS</text>`;
    issLabel = `ISS bearing ${bearingDeg.toFixed(0)}° · ${Math.round(distanceKm).toLocaleString()} km ${hasCenter ? "from location" : "from equator/prime-meridian ref."}`;
  }

  let planesLabel = "planes overhead: no location set";
  if (data.planes_overhead) {
    if (data.planes_overhead.status === "ok") {
      const planes = data.planes_overhead.data.planes || [];
      planes.forEach((p) => {
        if (typeof p.lat !== "number" || typeof p.lon !== "number") return;
        const { distanceKm, bearingDeg } = _haversineBearingDistance(refLat, refLon, p.lat, p.lon);
        const [x, y] = _radarPoint(bearingDeg, distanceKm, RADAR_LOCAL_RANGE_KM);
        blipsHtml += `<circle class="radar-blip-plane" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="2"/>`;
      });
      planesLabel = `${planes.length} plane${planes.length === 1 ? "" : "s"} overhead`;
    } else if (data.planes_overhead.status === "skipped") {
      planesLabel = `planes overhead: ${data.planes_overhead.reason || "skipped"}`;
    }
  }

  const svg = `<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">
    <circle class="radar-ring" cx="${RADAR_CX}" cy="${RADAR_CY}" r="30"/>
    <circle class="radar-ring" cx="${RADAR_CX}" cy="${RADAR_CY}" r="58"/>
    <circle class="radar-ring" cx="${RADAR_CX}" cy="${RADAR_CY}" r="${RADAR_MAX_R}"/>
    <line class="radar-crosshair" x1="${RADAR_CX}" y1="${RADAR_CY - RADAR_MAX_R}" x2="${RADAR_CX}" y2="${RADAR_CY + RADAR_MAX_R}"/>
    <line class="radar-crosshair" x1="${RADAR_CX - RADAR_MAX_R}" y1="${RADAR_CY}" x2="${RADAR_CX + RADAR_MAX_R}" y2="${RADAR_CY}"/>
    <g class="radar-sweep">
      <path d="M ${RADAR_CX} ${RADAR_CY} L ${RADAR_CX} ${RADAR_CY - RADAR_MAX_R} A ${RADAR_MAX_R} ${RADAR_MAX_R} 0 0 1 ${(RADAR_CX + RADAR_MAX_R * Math.sin(_toRad(28))).toFixed(1)} ${(RADAR_CY - RADAR_MAX_R * Math.cos(_toRad(28))).toFixed(1)} Z"
            fill="var(--accent-dim)" opacity="0.18"/>
      <line x1="${RADAR_CX}" y1="${RADAR_CY}" x2="${RADAR_CX}" y2="${RADAR_CY - RADAR_MAX_R}" stroke="var(--accent)" stroke-width="1.2"/>
    </g>
    ${blipsHtml}
  </svg>`;

  const stamp = new Date().toLocaleTimeString([], { hour12: false });
  const html = `<div class="card">
    <div class="card-head">${pill("ok")} radar sweep <span style="margin-left:auto;color:var(--muted)">last updated ${stamp}</span></div>
    <div class="card-body">
      <div class="radar-wrap">${svg}</div>
      <div class="radar-caption">${escapeHtml(issLabel)}<br>${escapeHtml(planesLabel)}</div>
    </div>
  </div>`;
  container.innerHTML = html;
}

$("#export-bar").addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-fmt]");
  if (!btn || !lastResult) return;
  const fmt = btn.dataset.fmt;
  $("#export-status").textContent = "saving…";
  try {
    const resp = await fetch("/api/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: lastTarget, module: currentMod, data: lastResult.data, format: fmt }),
    });
    const json = await resp.json();
    $("#export-status").textContent = json.ok ? `saved → ${json.path}` : "failed";
    log(`report saved: ${json.path}`, "ok");
  } catch (err) {
    $("#export-status").textContent = "failed";
    log(`export failed: ${err.message}`, "err");
  }
});

const settingsOverlay = $("#settings-overlay");
const settingsList = $("#settings-list");

function keyRowHtml(k) {
  return `<div class="key-row" data-field="${k.field}">
    <div class="key-row-head">
      <span class="label">${escapeHtml(k.label)}</span>
      <span class="key-status ${k.configured ? "set" : "unset"}">${k.configured ? `set (${k.source})` : "not set"}</span>
    </div>
    <div class="key-help">${escapeHtml(k.help)}</div>
    <div class="key-input-row">
      <input type="password" placeholder="${k.configured ? "•••••••• (enter to replace)" : "paste key here"}" data-input="${k.field}">
      <button data-action="save" data-field="${k.field}">save</button>
      ${k.configured ? `<button class="clear-btn" data-action="clear" data-field="${k.field}">clear</button>` : ""}
    </div>
  </div>`;
}

async function loadSettings() {
  settingsList.innerHTML = `<div class="empty-state"><pre>loading…</pre></div>`;
  try {
    const resp = await fetch("/api/settings");
    const json = await resp.json();
    settingsList.innerHTML = json.keys.map(keyRowHtml).join("");
  } catch (err) {
    settingsList.innerHTML = `<div class="empty-state">could not load settings: ${escapeHtml(err.message)}</div>`;
  }
}

async function saveKey(field, value) {
  const resp = await fetch("/api/settings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ field, value }),
  });
  return resp.json();
}

settingsList.addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-action]");
  if (!btn) return;
  const field = btn.dataset.field;
  const row = settingsList.querySelector(`.key-row[data-field="${field}"]`);
  const input = row.querySelector("input");
  const value = btn.dataset.action === "clear" ? "" : input.value;
  btn.disabled = true;
  const result = await saveKey(field, value);
  if (result.ok) {
    log(`${field} ${value ? "saved" : "cleared"}`, "ok");
    loadSettings();
  } else {
    log(`settings save failed: ${result.error || "unknown error"}`, "err");
    btn.disabled = false;
  }
});

$("#settings-btn").addEventListener("click", () => {
  settingsOverlay.hidden = false;
  loadSettings();
});
$("#settings-close").addEventListener("click", () => { settingsOverlay.hidden = true; });
settingsOverlay.addEventListener("click", (e) => {
  if (e.target === settingsOverlay) settingsOverlay.hidden = true;
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !settingsOverlay.hidden) settingsOverlay.hidden = true;
});

async function checkHealth() {
  const dot = document.querySelector(".status-dot");
  const label = $("#health-label");
  try {
    const resp = await fetch("/api/health");
    if (resp.ok) {
      dot.classList.add("up");
      label.textContent = "backend online";
      log("backend online", "ok");
    } else throw new Error("bad response");
  } catch {
    dot.classList.add("down");
    label.textContent = "backend unreachable";
    log("backend unreachable", "err");
  }
}

selectModule("username");
checkHealth();
log("ZeroOSINTx dashboard ready");

function tickClock() {
  const el = $("#hud-clock");
  if (!el) return;
  el.textContent = new Date().toUTCString().slice(17, 25);
}
tickClock();
setInterval(tickClock, 1000);

window.addEventListener("load", () => {
  const boot = $("#boot-overlay");
  if (!boot) return;
  setTimeout(() => {
    boot.classList.add("hide");
    setTimeout(() => boot.remove(), 400);
  }, 1500);
});
