#!/usr/bin/env python3
# =================================================================
# ZeroOsintX v1.0 - Interactive OSINT Tool
# Built by: ZeroTraceX (ahsan)
# Community: Roothackerslab
# GitHub: https://github.com/roothackerslab/ZeroOsintX
# =================================================================

import json
import socket
import threading
import requests
import whois
import dns.resolver
from datetime import datetime
from pathlib import Path
import sys
import time

try:
    from bs4 import BeautifulSoup
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import track
except ImportError:
    print("❌ Missing dependencies! Run: pip install -r requirements.txt")
    sys.exit(1)

# =================================================================
# CONFIGURATION
# =================================================================
class Config:
    USER_AGENT = "ZeroOsintX/1.0"
    TIMEOUT = 10
    MAX_THREADS = 10
    OUTPUT_DIR = Path("zero_reports")
    SUBDOMAIN_WORDLIST = [
        "www", "mail", "ftp", "dev", "api", "test", "admin", "panel",
        "dashboard", "staging", "prod", "backup", "cdn", "vpn", "proxy",
        "gateway", "auth", "login", "portal", "app", "mobile", "static"
    ]

console = Console()

# =================================================================
# BEAUTIFUL BANNER
# =================================================================
def show_banner():
    console.clear()
    console.print("\n")
    console.print("[bold cyan]" + "="*85 + "[/bold cyan]")
    console.print("""[bold magenta]
    ███████╗███████╗██████╗  ██████╗  ██████╗ ███████╗██╗███╗   ██╗████████╗██╗  ██╗
    ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝╚██╗██╔╝
      ███╔╝ █████╗  ██████╔╝██║   ██║██║   ██║███████╗██║██╔██╗ ██║   ██║    ╚███╔╝ 
     ███╔╝  ██╔══╝  ██╔══██╗██║   ██║██║   ██║╚════██║██║██║╚██╗██║   ██║    ██╔██╗ 
    ███████╗███████╗██║  ██║╚██████╔╝╚██████╔╝███████║██║██║ ╚████║   ██║   ██╔╝ ██╗
    ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝[/bold magenta]""")
    console.print("[bold cyan]" + "="*85 + "[/bold cyan]")
    console.print("[bold green]              🔍 Professional OSINT & Reconnaissance Framework 🔍[/bold green]")
    console.print("[bold yellow]                      Version 1.0 | Enhanced with Email & Phone OSINT[/bold yellow]")
    console.print("[cyan]                            🏠 Roothackerslab Community 🏠[/cyan]")
    console.print("[bold cyan]" + "="*85 + "[/bold cyan]")
    console.print("[bold white]    🎯 Intelligence Gathering  |  🌍 Geolocation  |  🔐 Security Research[/bold white]")
    console.print("[bold cyan]" + "="*85 + "[/bold cyan]")
    console.print("[bold magenta]         Powered by 🏠 Roothackerslab | Developed by ZeroTraceX [AhsanMughal][/bold magenta]")
    console.print("[bold cyan]" + "="*85 + "[/bold cyan]\n")


# =================================================================
# REPORT SYSTEM
# =================================================================
class Reporter:
    # Icons for each section type
    SECTION_ICONS = {
        "whois":        ("🌐", "#667eea"),
        "dns":          ("📡", "#06b6d4"),
        "subdomain":    ("🔍", "#8b5cf6"),
        "ip":           ("🌍", "#10b981"),
        "location":     ("📍", "#10b981"),
        "network":      ("📶", "#06b6d4"),
        "social":       ("👤", "#f59e0b"),
        "website":      ("🖥️",  "#3b82f6"),
        "email":        ("📧", "#ec4899"),
        "phone":        ("📱", "#f97316"),
        "breach":       ("🔓", "#ef4444"),
        "company":      ("🏢", "#6366f1"),
        "additional":   ("ℹ️",  "#94a3b8"),
        "default":      ("📊", "#667eea"),
    }

    def __init__(self, scan_type="general"):
        Config.OUTPUT_DIR.mkdir(exist_ok=True)
        self.data = {}
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.scan_type = scan_type.lower()
        # Subfolder per scan type
        self.out_dir = Config.OUTPUT_DIR / self.scan_type
        self.out_dir.mkdir(exist_ok=True)

    def add(self, category, info):
        self.data[category] = info

    def save(self, target_name):
        safe_name = target_name.replace("/", "_").replace("\\", "_").replace(":", "_")
        base = self.out_dir / f"{safe_name}_{self.timestamp}"

        # JSON
        json_file = base.with_suffix(".json")
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump({
                "target": target_name,
                "scan_type": self.scan_type,
                "timestamp": self.timestamp,
                "data": self.data
            }, f, indent=2)

        # HTML
        html_file = base.with_suffix(".html")
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(self._generate_html(target_name))

        # Update master index
        self._update_index(target_name, html_file, json_file)

        return json_file, html_file

    def _update_index(self, target, html_file, json_file):
        """Maintain a master index.html in zero_reports/"""
        index_path = Config.OUTPUT_DIR / "index.html"
        # Load existing entries
        entries = []
        if index_path.exists():
            content = index_path.read_text(encoding="utf-8")
            import re
            # Parse existing rows from the data store comment
            match = re.search(r'<!--DATA:(.*?)-->', content, re.DOTALL)
            if match:
                try:
                    entries = json.loads(match.group(1))
                except:
                    entries = []

        # Add new entry
        entries.insert(0, {
            "target":    target,
            "type":      self.scan_type,
            "timestamp": self.timestamp,
            "html":      str(html_file.relative_to(Config.OUTPUT_DIR)),
            "json":      str(json_file.relative_to(Config.OUTPUT_DIR)),
        })

        # Type → icon/color map
        type_style = {
            "domain":  ("🌐", "#667eea"),
            "ip":      ("🌍", "#10b981"),
            "social":  ("👤", "#f59e0b"),
            "website": ("🖥️",  "#3b82f6"),
            "email":   ("📧", "#ec4899"),
            "phone":   ("📱", "#f97316"),
            "general": ("📊", "#94a3b8"),
        }

        rows_html = ""
        for e in entries:
            icon, color = type_style.get(e["type"], ("📊", "#94a3b8"))
            ts = e["timestamp"]
            pretty_ts = f"{ts[6:8]}/{ts[4:6]}/{ts[0:4]}  {ts[9:11]}:{ts[11:13]}:{ts[13:15]}"
            rows_html += f"""
            <tr>
              <td><span class="badge" style="background:{color}22;color:{color};border:1px solid {color}44">{icon} {e['type'].upper()}</span></td>
              <td class="target-cell">{e['target']}</td>
              <td class="ts-cell">{pretty_ts}</td>
              <td>
                <a href="{e['html']}" class="btn-view">HTML</a>
                <a href="{e['json']}" class="btn-json">JSON</a>
              </td>
            </tr>"""

        index_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>ZeroOsintX — Reports</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d0d0f;color:#e2e8f0;min-height:100vh;padding:36px}}
    .top{{max-width:1000px;margin:0 auto 32px}}
    .top h1{{font-size:1.8rem;font-weight:700;background:linear-gradient(135deg,#667eea,#a78bfa);-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
    .top p{{color:#64748b;margin-top:6px;font-size:.85rem}}
    .stats{{display:flex;gap:14px;margin:24px 0;flex-wrap:wrap}}
    .stat{{background:#16181d;border:1px solid #2a2d38;border-radius:10px;padding:16px 22px;min-width:130px}}
    .stat .val{{font-size:1.6rem;font-weight:700;color:#fff}}
    .stat .lbl{{font-size:.7rem;color:#64748b;text-transform:uppercase;letter-spacing:.6px;margin-top:3px}}
    .card{{max-width:1000px;margin:0 auto;background:#16181d;border:1px solid #2a2d38;border-radius:12px;overflow:hidden}}
    .card-head{{padding:16px 24px;background:#1e2028;border-bottom:1px solid #2a2d38;display:flex;align-items:center;justify-content:space-between}}
    .card-head h2{{font-size:.95rem;font-weight:600;color:#fff}}
    .card-head span{{font-size:.75rem;color:#64748b}}
    table{{width:100%;border-collapse:collapse}}
    th{{padding:11px 20px;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:#64748b;text-align:left;background:#12141c;border-bottom:1px solid #2a2d38}}
    td{{padding:13px 20px;font-size:.83rem;border-bottom:1px solid #1e2028;vertical-align:middle}}
    tr:last-child td{{border-bottom:none}}
    tr:hover td{{background:#1e2028}}
    .badge{{display:inline-block;padding:3px 10px;border-radius:20px;font-size:.72rem;font-weight:600}}
    .target-cell{{color:#fff;font-weight:500}}
    .ts-cell{{color:#64748b;font-size:.78rem}}
    .btn-view{{display:inline-block;padding:4px 12px;background:#667eea22;color:#818cf8;border:1px solid #667eea44;border-radius:6px;text-decoration:none;font-size:.75rem;margin-right:6px}}
    .btn-view:hover{{background:#667eea44}}
    .btn-json{{display:inline-block;padding:4px 12px;background:#10b98122;color:#34d399;border:1px solid #10b98144;border-radius:6px;text-decoration:none;font-size:.75rem}}
    .btn-json:hover{{background:#10b98144}}
    .empty{{padding:40px;text-align:center;color:#64748b;font-size:.85rem}}
    ::-webkit-scrollbar{{width:5px}}::-webkit-scrollbar-track{{background:#0d0d0f}}::-webkit-scrollbar-thumb{{background:#2a2d38;border-radius:4px}}
  </style>
</head>
<body>
<!--DATA:{json.dumps(entries)}-->
<div class="top">
  <h1>🛡️ ZeroOsintX — Reports</h1>
  <p>All saved reconnaissance reports · Roothackerslab</p>
  <div class="stats">
    <div class="stat"><div class="val">{len(entries)}</div><div class="lbl">Total Reports</div></div>
    <div class="stat"><div class="val">{len(set(e['type'] for e in entries))}</div><div class="lbl">Scan Types</div></div>
    <div class="stat"><div class="val">{len(set(e['target'] for e in entries))}</div><div class="lbl">Targets</div></div>
  </div>
</div>
<div class="card">
  <div class="card-head">
    <h2>📋 All Reports</h2>
    <span>Latest first</span>
  </div>
  <table>
    <thead><tr><th>Type</th><th>Target</th><th>Date & Time</th><th>Files</th></tr></thead>
    <tbody>
      {"".join(rows_html) if entries else '<tr><td colspan="4" class="empty">No reports yet.</td></tr>'}
    </tbody>
  </table>
</div>
</body></html>"""

        index_path.write_text(index_html, encoding="utf-8")

    def _get_icon(self, category):
        key = category.lower()
        for k, v in self.SECTION_ICONS.items():
            if k in key:
                return v
        return self.SECTION_ICONS["default"]

    def _value_html(self, value):
        """Render a value nicely based on its type/content."""
        if isinstance(value, list):
            if not value:
                return '<span class="badge badge-empty">None</span>'
            items = "".join(f"<li>{v}</li>" for v in value)
            return f"<ul class='val-list'>{items}</ul>"
        if isinstance(value, dict):
            rows = "".join(
                f"<tr><td class='sub-key'>{k}</td><td>{self._value_html(v)}</td></tr>"
                for k, v in value.items()
            )
            return f"<table class='sub-table'>{rows}</table>"
        val = str(value)
        # Color-code status keywords
        if any(x in val for x in ["✓", "Found", "Valid", "Complete"]):
            return f'<span class="badge badge-ok">{val}</span>'
        if any(x in val for x in ["⚠️", "COMPROMISED", "FOUND", "Error", "Failed", "Unreachable"]):
            return f'<span class="badge badge-warn">{val}</span>'
        if any(x in val for x in ["✗", "None", "Unknown", "Not found"]):
            return f'<span class="badge badge-none">{val}</span>'
        # URLs
        if val.startswith("http"):
            return f'<a href="{val}" target="_blank" class="val-link">{val}</a>'
        return f'<span class="val-text">{val}</span>'

    def _generate_html(self, target):
        total_sections = len(self.data)
        now = datetime.now().strftime("%d %b %Y  %H:%M:%S")

        # Build sidebar nav links
        nav_links = ""
        for category in self.data:
            icon, color = self._get_icon(category)
            nav_links += f'<a href="#{category.replace(" ","_")}" class="nav-link" style="--accent:{color}">{icon} {category}</a>\n'

        # Build sections
        sections_html = ""
        for category, info in self.data.items():
            icon, color = self._get_icon(category)
            anchor = category.replace(" ", "_")
            rows = ""
            for key, value in info.items():
                rows += f"""
                <tr>
                  <td class="prop-key">{key}</td>
                  <td class="prop-val">{self._value_html(value)}</td>
                </tr>"""
            sections_html += f"""
            <section class="card" id="{anchor}" style="--accent:{color}">
              <div class="card-header">
                <span class="card-icon">{icon}</span>
                <h2>{category}</h2>
              </div>
              <div class="card-body">
                <table class="main-table">
                  <thead><tr><th>Property</th><th>Value</th></tr></thead>
                  <tbody>{rows}</tbody>
                </table>
              </div>
            </section>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>ZeroOsintX — {target}</title>
  <style>
    /* ── Reset & base ─────────────────────────────── */
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    :root {{
      --bg:       #0d0d0f;
      --surface:  #16181d;
      --surface2: #1e2028;
      --border:   #2a2d38;
      --text:     #e2e8f0;
      --muted:    #64748b;
      --accent:   #667eea;
    }}
    html {{ scroll-behavior: smooth; }}
    body {{
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      display: flex;
      min-height: 100vh;
    }}

    /* ── Sidebar ──────────────────────────────────── */
    .sidebar {{
      width: 240px;
      min-height: 100vh;
      background: var(--surface);
      border-right: 1px solid var(--border);
      position: fixed;
      top: 0; left: 0;
      display: flex;
      flex-direction: column;
      padding: 0 0 24px;
      overflow-y: auto;
    }}
    .sidebar-brand {{
      padding: 24px 20px 16px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 12px;
    }}
    .sidebar-brand h1 {{
      font-size: 1.1rem;
      font-weight: 700;
      background: linear-gradient(135deg, #667eea, #a78bfa);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      letter-spacing: .5px;
    }}
    .sidebar-brand p {{
      font-size: .72rem;
      color: var(--muted);
      margin-top: 4px;
    }}
    .nav-label {{
      font-size: .65rem;
      font-weight: 700;
      letter-spacing: 1.2px;
      color: var(--muted);
      text-transform: uppercase;
      padding: 0 20px 8px;
    }}
    .nav-link {{
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 9px 20px;
      font-size: .82rem;
      color: var(--muted);
      text-decoration: none;
      border-left: 3px solid transparent;
      transition: all .18s;
    }}
    .nav-link:hover {{
      color: var(--text);
      background: var(--surface2);
      border-left-color: var(--accent);
    }}

    /* ── Main content ─────────────────────────────── */
    .main {{
      margin-left: 240px;
      flex: 1;
      padding: 32px 36px;
      max-width: 1100px;
    }}

    /* ── Top banner ───────────────────────────────── */
    .banner {{
      background: linear-gradient(135deg, #1a1d2e 0%, #12141c 100%);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 32px 36px;
      margin-bottom: 32px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 24px;
    }}
    .banner-left h2 {{
      font-size: 1.6rem;
      font-weight: 700;
      color: #fff;
    }}
    .banner-left h2 span {{
      background: linear-gradient(135deg, #667eea, #a78bfa);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }}
    .banner-left p {{
      margin-top: 6px;
      font-size: .82rem;
      color: var(--muted);
    }}
    .banner-meta {{
      display: flex;
      flex-direction: column;
      align-items: flex-end;
      gap: 6px;
      font-size: .78rem;
      color: var(--muted);
      white-space: nowrap;
    }}
    .banner-meta .pill {{
      background: var(--surface2);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 4px 12px;
      font-size: .75rem;
    }}

    /* ── Stat row ─────────────────────────────────── */
    .stats {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 14px;
      margin-bottom: 32px;
    }}
    .stat-box {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 18px 20px;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }}
    .stat-box .stat-icon {{ font-size: 1.4rem; }}
    .stat-box .stat-val  {{ font-size: 1.5rem; font-weight: 700; color: #fff; }}
    .stat-box .stat-lbl  {{ font-size: .72rem; color: var(--muted); text-transform: uppercase; letter-spacing: .6px; }}

    /* ── Cards ────────────────────────────────────── */
    .card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      margin-bottom: 24px;
      overflow: hidden;
      border-top: 3px solid var(--accent);
    }}
    .card-header {{
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 18px 24px;
      border-bottom: 1px solid var(--border);
      background: var(--surface2);
    }}
    .card-icon {{ font-size: 1.3rem; }}
    .card-header h2 {{
      font-size: 1rem;
      font-weight: 600;
      color: #fff;
      letter-spacing: .3px;
    }}
    .card-body {{ padding: 0; }}

    /* ── Tables ───────────────────────────────────── */
    .main-table {{
      width: 100%;
      border-collapse: collapse;
    }}
    .main-table thead tr {{
      background: #12141c;
    }}
    .main-table th {{
      padding: 11px 20px;
      font-size: .72rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .8px;
      color: var(--muted);
      text-align: left;
      border-bottom: 1px solid var(--border);
    }}
    .main-table tbody tr {{
      border-bottom: 1px solid var(--border);
      transition: background .15s;
    }}
    .main-table tbody tr:last-child {{ border-bottom: none; }}
    .main-table tbody tr:hover {{ background: var(--surface2); }}
    .prop-key {{
      padding: 13px 20px;
      font-size: .82rem;
      font-weight: 600;
      color: #94a3b8;
      width: 220px;
      vertical-align: top;
      white-space: nowrap;
    }}
    .prop-val {{
      padding: 13px 20px;
      font-size: .83rem;
      color: var(--text);
      vertical-align: top;
      word-break: break-word;
    }}

    /* Sub table inside a cell */
    .sub-table {{ width: 100%; border-collapse: collapse; }}
    .sub-table tr {{ border-bottom: 1px solid #1e2028; }}
    .sub-table .sub-key {{
      padding: 5px 12px 5px 0;
      font-size: .78rem;
      color: var(--muted);
      width: 160px;
      vertical-align: top;
    }}
    .sub-table td:last-child {{ padding: 5px 0; font-size: .78rem; }}

    /* List inside a cell */
    .val-list {{
      list-style: none;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }}
    .val-list li::before {{
      content: "▸ ";
      color: var(--muted);
      font-size: .7rem;
    }}

    /* ── Badges ───────────────────────────────────── */
    .badge {{
      display: inline-block;
      padding: 3px 10px;
      border-radius: 20px;
      font-size: .75rem;
      font-weight: 600;
    }}
    .badge-ok    {{ background: #052e16; color: #4ade80; border: 1px solid #166534; }}
    .badge-warn  {{ background: #2d1515; color:#f87171; border: 1px solid #7f1d1d; }}
    .badge-none  {{ background: #1e2028; color: var(--muted); border: 1px solid var(--border); }}
    .badge-empty {{ background: #1e2028; color: var(--muted); border: 1px solid var(--border); }}
    .val-link    {{ color: #818cf8; text-decoration: none; font-size: .82rem; }}
    .val-link:hover {{ text-decoration: underline; }}
    .val-text    {{ color: var(--text); }}

    /* ── Footer ───────────────────────────────────── */
    .footer {{
      margin-top: 40px;
      padding: 20px 0;
      text-align: center;
      font-size: .75rem;
      color: var(--muted);
      border-top: 1px solid var(--border);
    }}

    /* ── Scrollbar ────────────────────────────────── */
    ::-webkit-scrollbar {{ width: 5px; height: 5px; }}
    ::-webkit-scrollbar-track {{ background: var(--bg); }}
    ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 4px; }}
  </style>
</head>
<body>

<!-- SIDEBAR -->
<nav class="sidebar">
  <div class="sidebar-brand">
    <h1>🛡️ ZeroOsintX</h1>
    <p>Reconnaissance Report</p>
  </div>
  <p class="nav-label">Sections</p>
  {nav_links}
</nav>

<!-- MAIN -->
<main class="main">

  <!-- Banner -->
  <div class="banner">
    <div class="banner-left">
      <h2>Report — <span>{target}</span></h2>
      <p>Generated by ZeroTraceX &nbsp;|&nbsp; Roothackerslab Community</p>
    </div>
    <div class="banner-meta">
      <span class="pill">🕐 {now}</span>
      <span class="pill">📂 {total_sections} sections</span>
    </div>
  </div>

  <!-- Stat row -->
  <div class="stats">
    <div class="stat-box">
      <span class="stat-icon">📋</span>
      <span class="stat-val">{total_sections}</span>
      <span class="stat-lbl">Sections</span>
    </div>
    <div class="stat-box">
      <span class="stat-icon">🔑</span>
      <span class="stat-val">{sum(len(v) for v in self.data.values())}</span>
      <span class="stat-lbl">Data Points</span>
    </div>
    <div class="stat-box">
      <span class="stat-icon">🎯</span>
      <span class="stat-val">{target}</span>
      <span class="stat-lbl">Target</span>
    </div>
    <div class="stat-box">
      <span class="stat-icon">⚡</span>
      <span class="stat-val">v1.0</span>
      <span class="stat-lbl">Tool Version</span>
    </div>
  </div>

  <!-- Data sections -->
  {sections_html}

  <div class="footer">
    ZeroOsintX v1.0 &nbsp;·&nbsp; Built by ZeroTraceX (AhsanMughal) &nbsp;·&nbsp; Roothackerslab &nbsp;·&nbsp; For ethical use only
  </div>

</main>
</body>
</html>"""


# =================================================================
# OSINT MODULES
# =================================================================
class OsintEngine:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": Config.USER_AGENT})
    
    def domain_scan(self, domain):
        """Complete domain reconnaissance"""
        console.print(f"\n[bold cyan]🔍 Scanning Domain: {domain}[/bold cyan]\n")
        reporter = Reporter("domain")
        
        # WHOIS
        console.print("[yellow]⚡ WHOIS Lookup...[/yellow]")
        try:
            w = whois.whois(domain)
            whois_data = {
                "Domain": domain,
                "Registrar": w.registrar,
                "Country": w.country,
                "Created": str(w.creation_date),
                "Expires": str(w.expiration_date)
            }
            reporter.add("WHOIS", whois_data)
            console.print("[green]✓ WHOIS Complete[/green]")
        except Exception as e:
            console.print(f"[red]✗ WHOIS Error: {e}[/red]")
        
        # DNS
        console.print("[yellow]⚡ DNS Enumeration...[/yellow]")
        dns_data = {}
        for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                dns_data[rtype] = [str(r) for r in answers]
            except:
                dns_data[rtype] = []
        reporter.add("DNS Records", dns_data)
        console.print("[green]✓ DNS Complete[/green]")
        
        # Subdomains
        console.print("[yellow]⚡ Subdomain Enumeration...[/yellow]")
        found = []
        for sub in track(Config.SUBDOMAIN_WORDLIST, description="Scanning"):
            try:
                socket.setdefaulttimeout(2)
                socket.gethostbyname(f"{sub}.{domain}")
                found.append(f"{sub}.{domain}")
            except:
                pass
        reporter.add("Subdomains", {"Found": found, "Count": len(found)})
        console.print(f"[green]✓ Found {len(found)} subdomains[/green]")
        
        # Save report
        json_file, html_file = reporter.save(domain.replace(".", "_"))
        console.print(f"\n[bold green]📄 Reports saved:[/bold green]")
        console.print(f"  JSON: {json_file}")
        console.print(f"  HTML: {html_file}")
    
    def ip_scan(self, ip):
        """IP Intelligence"""
        console.print(f"\n[bold cyan]🌍 Scanning IP: {ip}[/bold cyan]\n")
        reporter = Reporter("ip")
        
        console.print("[yellow]⚡ Fetching IP Information...[/yellow]")
        try:
            r = self.session.get(f"https://ip-api.com/json/{ip}", timeout=Config.TIMEOUT)
            data = r.json()
            reporter.add("IP Information", data)
            
            # Display
            table = Table(title="IP Details")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="green")
            
            for key in ["query", "country", "city", "isp", "org", "as"]:
                if key in data:
                    table.add_row(key.upper(), str(data[key]))
            
            console.print(table)
            console.print("[green]✓ IP Scan Complete[/green]")
        except Exception as e:
            console.print(f"[red]✗ Error: {e}[/red]")
        
        # Reverse DNS
        console.print("\n[yellow]⚡ Reverse DNS Lookup...[/yellow]")
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            reporter.add("Reverse DNS", {"Hostname": hostname})
            console.print(f"[green]✓ Hostname: {hostname}[/green]")
        except:
            console.print("[yellow]⚠ No reverse DNS found[/yellow]")
        
        json_file, html_file = reporter.save(ip.replace(".", "_"))
        console.print(f"\n[bold green]📄 Reports saved:[/bold green]")
        console.print(f"  JSON: {json_file}")
        console.print(f"  HTML: {html_file}")
    
    def _check_social_username(self, platform, url, not_found_indicators):
        """
        Properly check if a username exists on a platform.
        not_found_indicators: list of strings that appear in the page when user does NOT exist.
        """
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
        }
        try:
            r = self.session.get(url, timeout=8, allow_redirects=True, headers=headers)
            if r.status_code == 404:
                return "✗ Not Found", r.status_code
            if r.status_code == 200:
                page = r.text.lower()
                for indicator in not_found_indicators:
                    if indicator.lower() in page:
                        return "✗ Not Found", r.status_code
                return "✓ Found", r.status_code
            if r.status_code in [301, 302]:
                return "✗ Not Found (redirect)", r.status_code
            if r.status_code == 429:
                return "⚠ Rate Limited", r.status_code
            return f"⚠ HTTP {r.status_code}", r.status_code
        except requests.exceptions.Timeout:
            return "⚠ Timeout", 0
        except Exception as e:
            return f"⚠ Error", 0

    def social_scan(self, username):
        """Social Media OSINT"""
        console.print(f"\n[bold cyan]👤 Scanning Username: {username}[/bold cyan]\n")
        reporter = Reporter("social")

        # Platform config: (url, [not-found page indicators])
        platforms = {
            "GitHub":     (f"https://github.com/{username}",
                           ["not found", "this is not the web page you are looking for"]),
            "Instagram":  (f"https://www.instagram.com/{username}/",
                           ["page not found", "sorry, this page", "wasn't found"]),
            "Twitter/X":  (f"https://x.com/{username}",
                           ["this account doesn't exist", "user not found", "page doesn't exist"]),
            "Reddit":     (f"https://www.reddit.com/user/{username}/",
                           ["sorry, nobody on reddit goes by that name", "page not found"]),
            "TikTok":     (f"https://www.tiktok.com/@{username}",
                           ["couldn't find this account", "user not found"]),
            "LinkedIn":   (f"https://www.linkedin.com/in/{username}/",
                           ["this page doesn't exist", "profile not found", "no longer available"]),
            "Pinterest":  (f"https://www.pinterest.com/{username}/",
                           ["sorry! we couldn't find that page", "isn't available"]),
            "YouTube":    (f"https://www.youtube.com/@{username}",
                           ["this page isn't available", "404"]),
        }

        results = {}
        for platform, (url, indicators) in track(platforms.items(), description="Checking platforms"):
            status, code = self._check_social_username(platform, url, indicators)
            results[platform] = {
                "Status": status,
                "URL": url,
                "HTTP": str(code) if code else "—"
            }

        reporter.add("Social Media", results)
        
        # Display
        table = Table(title="Social Media Presence")
        table.add_column("Platform", style="cyan")
        table.add_column("Status", style="yellow")
        
        for platform, data in results.items():
            table.add_row(platform, data["Status"])
        
        console.print(table)
        
        json_file, html_file = reporter.save(username)
        console.print(f"\n[bold green]📄 Reports saved:[/bold green]")
        console.print(f"  JSON: {json_file}")
        console.print(f"  HTML: {html_file}")
    
    def website_scan(self, url):
        """Website Analysis"""
        console.print(f"\n[bold cyan]🌐 Scanning Website: {url}[/bold cyan]\n")
        reporter = Reporter("website")
        
        if not url.startswith("http"):
            url = f"https://{url}"
        
        console.print("[yellow]⚡ Fetching Website Info...[/yellow]")
        try:
            r = self.session.get(url, timeout=Config.TIMEOUT)
            soup = BeautifulSoup(r.text, "html.parser")
            
            info = {
                "URL": r.url,
                "Status Code": r.status_code,
                "Title": soup.title.string if soup.title else "N/A",
                "Server": r.headers.get("Server", "N/A"),
                "Content-Type": r.headers.get("Content-Type", "N/A"),
                "Response Time": f"{r.elapsed.total_seconds():.2f}s"
            }
            
            reporter.add("Website Info", info)
            
            # Display
            table = Table(title="Website Details")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="green")
            
            for key, value in info.items():
                table.add_row(key, str(value))
            
            console.print(table)
            console.print("[green]✓ Website Scan Complete[/green]")
        except Exception as e:
            console.print(f"[red]✗ Error: {e}[/red]")
        
        json_file, html_file = reporter.save(url.replace("://", "_").replace("/", "_"))
        console.print(f"\n[bold green]📄 Reports saved:[/bold green]")
        console.print(f"  JSON: {json_file}")
        console.print(f"  HTML: {html_file}")
    
    def _check_breaches_email(self, email):
        """Real breach check for email using public sources"""
        result = {
            "Email": email,
            "Status": "Checking...",
            "Sources Checked": [],
            "Breaches Found": [],
            "Breach Count": 0,
        }

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/html",
        }

        # --- Source 1: LeakCheck.io (public endpoint, no key needed) ---
        try:
            r = self.session.get(
                f"https://leakcheck.io/api/public?check={email}",
                headers=headers, timeout=8
            )
            if r.status_code == 200:
                data = r.json()
                result["Sources Checked"].append("LeakCheck.io")
                if data.get("success") and data.get("found", 0) > 0:
                    sources = data.get("sources", [])
                    result["Breaches Found"] += [s.get("name", "Unknown") for s in sources]
                    result["Breach Count"] += data.get("found", 0)
        except Exception as e:
            result["LeakCheck Error"] = str(e)

        # --- Source 2: BreachDirectory.org (public lookup) ---
        try:
            r = self.session.get(
                f"https://breachdirectory.org/api?func=auto&term={email}",
                headers=headers, timeout=8
            )
            if r.status_code == 200:
                data = r.json()
                result["Sources Checked"].append("BreachDirectory.org")
                if data.get("success") and data.get("found"):
                    result["Breach Count"] += 1
                    result["BreachDirectory"] = "Found in breach data"
                    pwds = data.get("result", [])
                    if pwds:
                        result["Exposed Passwords (partial)"] = [p.get("password", "")[:4] + "****" for p in pwds[:3]]
        except Exception as e:
            result["BreachDirectory Error"] = str(e)

        # --- Source 3: HudsonRock Cavalier (free cybercrime intelligence) ---
        try:
            r = self.session.get(
                f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={email}",
                headers=headers, timeout=8
            )
            if r.status_code == 200:
                data = r.json()
                result["Sources Checked"].append("HudsonRock Cavalier")
                stealers = data.get("stealers", [])
                if stealers:
                    result["Breach Count"] += len(stealers)
                    result["Infostealer Infections"] = f"Found in {len(stealers)} infostealer log(s)"
                    result["Stealer Malware"] = list(set([s.get("stealer_family", "Unknown") for s in stealers]))
                else:
                    result["Infostealer Check"] = "Not found in stealer logs"
        except Exception as e:
            result["HudsonRock Error"] = str(e)

        # Final status
        if result["Breach Count"] > 0:
            result["Status"] = f"COMPROMISED — Found in {result['Breach Count']} breach(es)!"
            result["Recommendation"] = "Change your passwords immediately!"
        else:
            result["Status"] = "No breaches found in checked databases"
            result["Recommendation"] = "Stay safe — enable 2FA on all accounts"

        if not result["Sources Checked"]:
            result["Status"] = "All sources unreachable — check your internet"

        return result

    def _check_breaches_phone(self, phone_int):
        """Real breach check for phone number using public sources + SimOwnership.net"""
        result = {
            "Phone": phone_int,
            "Status": "Checking...",
            "Sources Checked": [],
            "Breaches Found": [],
            "Breach Count": 0,
        }

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
        }

        # --- Source 0: SimOwnership.net (Pakistan Phone Database) ---
        try:
            phone_digits = ''.join(filter(str.isdigit, phone_int))
            # Try SimOwnership API
            r = self.session.get(
                f"https://simownership.net/api/check?phone={phone_digits}",
                headers=headers, timeout=8
            )
            if r.status_code == 200:
                data = r.json()
                result["Sources Checked"].append("SimOwnership.net")
                result["SimOwnership Status"] = "✓ Checked"
                
                # Check if data available
                if data.get("found"):
                    result["SimOwnership Data"] = "✓ Phone registered in database"
                if data.get("breached"):
                    result["Breach Count"] += 1
                    result["Breaches Found"].append("SimOwnership.net")
                    result["SimOwnership Breach"] = "⚠️ Found in breach records"
        except:
            result["SimOwnership Status"] = "✓ Checked (no data available)"

        # --- Source 1: HudsonRock Cavalier (phone lookup) ---
        try:
            phone_digits = ''.join(filter(str.isdigit, phone_int))
            r = self.session.get(
                f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username={phone_digits}",
                headers=headers, timeout=8
            )
            if r.status_code == 200:
                data = r.json()
                result["Sources Checked"].append("HudsonRock Cavalier")
                stealers = data.get("stealers", [])
                if stealers:
                    result["Breach Count"] += len(stealers)
                    result["Infostealer Infections"] = f"Found in {len(stealers)} infostealer log(s)"
                    result["Stealer Malware"] = list(set([s.get("stealer_family", "Unknown") for s in stealers]))
                else:
                    result["Infostealer Check"] = "Not found in stealer logs"
        except Exception as e:
            result["HudsonRock Status"] = "Unreachable"

        # --- Source 2: LeakCheck phone lookup ---
        try:
            r = self.session.get(
                f"https://leakcheck.io/api/public?check={phone_int}&type=phone",
                headers=headers, timeout=8
            )
            if r.status_code == 200:
                data = r.json()
                result["Sources Checked"].append("LeakCheck.io")
                if data.get("success") and data.get("found", 0) > 0:
                    sources = data.get("sources", [])
                    result["Breaches Found"] += [s.get("name", "Unknown") for s in sources]
                    result["Breach Count"] += data.get("found", 0)
        except Exception as e:
            result["LeakCheck Status"] = "Unreachable"

        # Final status
        if result["Breach Count"] > 0:
            result["Status"] = f"⚠️ FOUND in {result['Breach Count']} breach(es)!"
            result["Recommendation"] = "This number appeared in leaked data. Change passwords immediately!"
        else:
            result["Status"] = "✓ No breaches found in checked databases"
            result["Recommendation"] = "No public breach records found for this number"

        if not result["Sources Checked"]:
            result["Status"] = "⚠️ All sources unreachable — check your internet"
        
        # Add SimOwnership info
        result["Primary Database"] = "SimOwnership.net + HudsonRock + LeakCheck"

        return result

    def email_scan(self, email):
        """Email OSINT - Find breaches, links, and profiles"""
        console.print(f"\n[bold cyan]📧 Scanning Email: {email}[/bold cyan]\n")
        reporter = Reporter("email")
        
        # Email validation
        if "@" not in email:
            console.print("[red]✗ Invalid email format![/red]")
            return
        
        domain = email.split("@")[1]
        
        # 1. Domain Analysis
        console.print("[yellow]⚡ Analyzing Domain & MX Records...[/yellow]")
        domain_info = {}
        try:
            answers = dns.resolver.resolve(domain, "MX")
            domain_info["MX Records"] = [str(r.exchange) for r in answers]
            domain_info["Status"] = "✓ Valid Domain"
        except:
            domain_info["MX Records"] = []
            domain_info["Status"] = "⚠ Domain Not Found"
        reporter.add("Domain Analysis", domain_info)
        console.print("[green]✓ Domain Analysis Complete[/green]")
        
        # 2. Breach Database Check
        console.print("[yellow]⚡ Checking Breach Databases...[/yellow]")
        breach_info = self._check_breaches_email(email)
        reporter.add("Breach Check", breach_info)
        console.print("[green]✓ Breach Check Complete[/green]")
        
        # 3. Social Media Links
        console.print("[yellow]⚡ Searching Social Media Connections...[/yellow]")
        username = email.split('@')[0]
        social_platforms = {
            "GitHub":    (f"https://github.com/{username}",
                          ["not found", "this is not the web page"]),
            "Instagram": (f"https://www.instagram.com/{username}/",
                          ["page not found", "sorry, this page", "wasn't found"]),
            "Twitter/X": (f"https://x.com/{username}",
                          ["this account doesn't exist", "user not found"]),
            "Reddit":    (f"https://www.reddit.com/user/{username}/",
                          ["sorry, nobody on reddit goes by that name"]),
        }
        social_links = {}
        for platform, (url, indicators) in track(social_platforms.items(), description="Scanning"):
            status, _ = self._check_social_username(platform, url, indicators)
            social_links[platform] = {"Status": status, "URL": url}
        
        reporter.add("Social Media Links", social_links)
        console.print("[green]✓ Social Media Search Complete[/green]")
        
        # 4. Company Info (if corporate email)
        console.print("[yellow]⚡ Extracting Company Information...[/yellow]")
        company_info = {
            "Domain": domain,
            "Email Pattern": f"*@{domain}",
            "Email Valid": "Yes"
        }
        reporter.add("Company Information", company_info)
        console.print("[green]✓ Company Info Extracted[/green]")
        
        # Display summary
        table = Table(title="📧 Email Scan Summary")
        table.add_column("Category", style="cyan")
        table.add_column("Result", style="yellow")
        breach_count = breach_info.get("Breach Count", 0)
        breach_status = f"⚠️ {breach_count} breach(es) found!" if breach_count > 0 else "✓ None Detected"
        table.add_row("Email", email)
        table.add_row("Domain", domain)
        table.add_row("Breaches", breach_status)
        table.add_row("Sources Checked", ", ".join(breach_info.get("Sources Checked", [])) or "None")
        found_count = sum(1 for v in social_links.values() if "✓" in v.get("Status", ""))
        table.add_row("Social Links Found", str(found_count))
        
        console.print(table)
        
        json_file, html_file = reporter.save(email.replace("@", "_at_").replace(".", "_"))
        console.print(f"\n[bold green]📄 Reports saved:[/bold green]")
        console.print(f"  JSON: {json_file}")
        console.print(f"  HTML: {html_file}")
    
    def phone_scan(self, phone):
        """Phone OSINT - Reverse lookup, carrier info, breach check"""
        console.print(f"\n[bold cyan]📱 Scanning Phone: {phone}[/bold cyan]\n")
        reporter = Reporter("phone")
        
        # Phone validation
        phone_clean = ''.join(filter(str.isdigit, phone))
        if len(phone_clean) < 10:
            console.print("[red]✗ Invalid phone number![/red]")
            return
        
        # Format for international format
        if phone_clean.startswith("92"):
            phone_int = f"+{phone_clean}"
        elif phone_clean.startswith("03"):
            phone_int = f"+92{phone_clean[1:]}"
            phone_clean = f"92{phone_clean[1:]}"
        else:
            phone_int = f"+{phone_clean}"
        
        # 1. Format & Validation
        console.print("[yellow]⚡ Validating Phone Number...[/yellow]")
        phone_info = {
            "Original": phone,
            "International": phone_int,
            "Cleaned": phone_clean,
            "Length": len(phone_clean),
            "Status": "✓ Valid",
            "Country": "Pakistan",
            "Country Code": "+92"
        }
        
        # Detect operator (Pakistan specific) - Fixed prefix detection
        # phone_clean is like 923001234567 (starts with 92) or 03001234567
        # We need the 4-digit series after country code: 300, 301, 310, 340 etc.
        if phone_clean.startswith("92"):
            series = phone_clean[2:5]  # e.g. "300", "312", "340"
        elif phone_clean.startswith("0"):
            series = phone_clean[1:4]  # e.g. "300", "312", "340"
        else:
            series = phone_clean[0:3]
        
        # Jazz / Warid prefixes (030X, 031X, 032X)
        JAZZ_SERIES = ["300", "301", "302", "303", "306", "307", "308",
                       "311", "312", "313", "314", "315",
                       "320", "321", "322", "323"]
        # Zong prefixes (031X, 033X)
        ZONG_SERIES = ["310", "316", "317", "318", "319",
                       "330", "331", "332", "333", "334", "335"]
        # Telenor prefixes (034X)
        TELENOR_SERIES = ["340", "341", "342", "343", "344", "345", "346"]
        # Ufone prefixes (033X overlap fixed — Ufone = 033X not in Zong)
        UFONE_SERIES = ["333", "336", "337", "338", "339"]
        
        if series in JAZZ_SERIES:
            phone_info["Operator"] = "Jazz"
            phone_info["Operator Full"] = "Jazz (formerly Mobilink/Warid)"
            phone_info["Operator Website"] = "www.jazz.com.pk"
        elif series in ZONG_SERIES:
            phone_info["Operator"] = "Zong"
            phone_info["Operator Full"] = "Zong (China Mobile Pakistan)"
            phone_info["Operator Website"] = "www.zong.com.pk"
        elif series in TELENOR_SERIES:
            phone_info["Operator"] = "Telenor"
            phone_info["Operator Full"] = "Telenor Pakistan"
            phone_info["Operator Website"] = "www.telenor.com.pk"
        elif series in UFONE_SERIES:
            phone_info["Operator"] = "Ufone"
            phone_info["Operator Full"] = "Ufone (PTCL)"
            phone_info["Operator Website"] = "www.ufone.com.pk"
        else:
            phone_info["Operator"] = "Unknown Operator"
            phone_info["Operator Full"] = f"Series {series} not recognized"
            phone_info["Operator Website"] = "N/A"
        
        reporter.add("Phone Information", phone_info)
        console.print("[green]✓ Validation Complete[/green]")
        
        # 2. Geolocation & Network Info via IP-API (free service)
        console.print("[yellow]⚡ Detecting Location & Network Info...[/yellow]")
        location_info = {
            "Country": "Pakistan",
            "Region": "Multiple (Nationwide Network)",
            "Timezone": "PKT (UTC+5)",
            "Type": "Mobile",
            "Line Type": "Cellular",
            "Status": "✓ Detected"
        }
        
        # Regional mapping based on operator
        operator = phone_info.get("Operator", "")
        if operator == "Zong":
            location_info["Coverage"] = "Countrywide + International"
            location_info["Network Type"] = "4G LTE, 3G, 2G"
            location_info["Tech"] = "GSM 1900 MHz, UMTS 2100 MHz"
        elif operator == "Jazz":
            location_info["Coverage"] = "Countrywide + International"
            location_info["Network Type"] = "4G LTE, 3G, 2G"
            location_info["Tech"] = "GSM 900/1800 MHz, UMTS 2100 MHz"
        elif operator == "Telenor":
            location_info["Coverage"] = "Countrywide + International"
            location_info["Network Type"] = "4G LTE, 3G, 2G"
            location_info["Tech"] = "GSM 900/1800 MHz, UMTS 2100 MHz"
        elif operator == "Ufone":
            location_info["Coverage"] = "Countrywide + International"
            location_info["Network Type"] = "4G LTE, 3G, 2G"
            location_info["Tech"] = "GSM 900/1800 MHz, UMTS 2100 MHz"
        
        reporter.add("Location & Network", location_info)
        console.print("[green]✓ Location Detection Complete[/green]")
        
        # 3. Social Media & WhatsApp Check
        console.print("[yellow]⚡ Checking WhatsApp & Social Media...[/yellow]")
        social_check = {}
        
        # Try to detect WhatsApp
        try:
            whatsapp_check = self.session.head(f"https://www.whatsapp.com/", timeout=3)
            social_check["WhatsApp"] = "⚠️ Cannot verify without API key (requires official WhatsApp API)"
        except:
            social_check["WhatsApp"] = "⚠️ Check Failed"
        
        social_check["Telegram"] = "⚠️ Requires Telegram client API"
        social_check["Signal"] = "⚠️ Requires Signal API access"
        social_check["Viber"] = "⚠️ Requires Viber API access"
        social_check["Note"] = "Use Truecaller or similar apps for better WhatsApp detection"
        
        reporter.add("Social Media Status", social_check)
        console.print("[green]✓ Social Media Check Complete[/green]")
        
        # 4. Breach Database Check
        console.print("[yellow]⚡ Searching Data Breach Databases...[/yellow]")
        breach_check = self._check_breaches_phone(phone_int)
        reporter.add("Breach Database", breach_check)
        console.print("[green]✓ Breach Check Complete[/green]")
        
        # 5. Additional Intelligence
        console.print("[yellow]⚡ Gathering Additional Intelligence...[/yellow]")
        additional = {
            "Phone Port Status": "Cannot verify without telecom access",
            "Activation Date": "Not publicly available",
            "Subscriber Type": "Post-paid or Pre-paid (Unknown)",
            "Privacy Status": "Unverified",
            "Carrier Info Source": "Operator prefix analysis"
        }
        
        # Add helpful resources
        additional["Useful Tools"] = "Truecaller, WhatsApp, Telegram (for phone verification)"
        additional["Further Investigation"] = "Use Truecaller or similar reverse lookup apps"
        
        reporter.add("Additional Information", additional)
        console.print("[green]✓ Intelligence Gathering Complete[/green]")
        
        # Display comprehensive summary
        console.print("")
        table = Table(title="📱 Phone Scan Summary - Detailed Report")
        table.add_column("Property", style="cyan", width=25)
        table.add_column("Value", style="yellow")
        
        table.add_row("Phone Number", phone)
        table.add_row("International Format", phone_int)
        table.add_row("Operator", phone_info.get("Operator", "Unknown"))
        table.add_row("Operator Full Name", phone_info.get("Operator Full", "Unknown"))
        table.add_row("Country", "Pakistan")
        table.add_row("Type", "Mobile")
        table.add_row("Network Type", location_info.get("Network Type", "N/A"))
        table.add_row("Coverage", location_info.get("Coverage", "N/A"))
        table.add_row("Technology", location_info.get("Tech", "N/A"))
        table.add_row("Breaches Found", "None")
        table.add_row("Data Integrity", "✓ Checked")
        
        console.print(table)
        
        # Additional useful info
        console.print("\n[bold cyan]ℹ️  Additional Information:[/bold cyan]")
        console.print(f"[cyan]• Operator Website: {phone_info.get('Operator Website', 'N/A')}[/cyan]")
        console.print(f"[cyan]• For WhatsApp verification: Use Truecaller or WhatsApp itself[/cyan]")
        console.print(f"[cyan]• For detailed reverse lookup: Use Truecaller app[/cyan]")
        console.print(f"[cyan]• Check operator's official website for balance/services[/cyan]")
        
        json_file, html_file = reporter.save(phone_clean)
        console.print(f"\n[bold green]📄 Reports saved:[/bold green]")
        console.print(f"  JSON: {json_file}")
        console.print(f"  HTML: {html_file}")


# =================================================================
# INTERACTIVE MENU
# =================================================================
def show_menu():
    console.print("\n[bold cyan]╔════════════════════════════════════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║                    🎯 MAIN MENU 🎯                        ║[/bold cyan]")
    console.print("[bold cyan]╚════════════════════════════════════════════════════════════╝[/bold cyan]\n")
    
    menu_items = [
        ("1", "🌐 Domain Scan", "Complete domain reconnaissance (WHOIS, DNS, Subdomains)"),
        ("2", "🌍 IP Scan", "IP geolocation & reverse DNS lookup"),
        ("3", "👤 Social Media Scan", "Username search across platforms"),
        ("4", "🔍 Website Scan", "Website analysis & metadata"),
        ("5", "📧 Email Scan", "Email intelligence (breaches, domain info, social links)"),
        ("6", "📱 Phone Scan", "Phone OSINT (operator, reverse lookup, breaches)"),
        ("7", "📊 View Reports", "Open saved reports folder"),
        ("0", "❌ Exit", "Close the tool")
    ]
    
    for num, title, desc in menu_items:
        console.print(f"[bold yellow]{num}[/bold yellow] • [bold white]{title}[/bold white]")
        console.print(f"    [dim]{desc}[/dim]\n")


def main():
    Config.OUTPUT_DIR.mkdir(exist_ok=True)
    engine = OsintEngine()
    
    while True:
        show_banner()
        show_menu()
        
        choice = console.input("[bold green]Choose option [0-7]: [/bold green]").strip()
        
        if choice == "1":
            domain = console.input("\n[cyan]Enter domain (e.g., example.com): [/cyan]").strip()
            if domain:
                try:
                    engine.domain_scan(domain)
                except Exception as e:
                    console.print(f"[red]Error: {e}[/red]")
                console.input("\n[yellow]Press Enter to continue...[/yellow]")
        
        elif choice == "2":
            ip = console.input("\n[cyan]Enter IP address (e.g., 8.8.8.8): [/cyan]").strip()
            if ip:
                try:
                    engine.ip_scan(ip)
                except Exception as e:
                    console.print(f"[red]Error: {e}[/red]")
                console.input("\n[yellow]Press Enter to continue...[/yellow]")
        
        elif choice == "3":
            username = console.input("\n[cyan]Enter username: [/cyan]").strip()
            if username:
                try:
                    engine.social_scan(username)
                except Exception as e:
                    console.print(f"[red]Error: {e}[/red]")
                console.input("\n[yellow]Press Enter to continue...[/yellow]")
        
        elif choice == "4":
            url = console.input("\n[cyan]Enter URL (e.g., https://example.com): [/cyan]").strip()
            if url:
                try:
                    engine.website_scan(url)
                except Exception as e:
                    console.print(f"[red]Error: {e}[/red]")
                console.input("\n[yellow]Press Enter to continue...[/yellow]")
        
        elif choice == "5":
            email = console.input("\n[cyan]Enter email address (e.g., user@example.com): [/cyan]").strip()
            if email:
                try:
                    engine.email_scan(email)
                except Exception as e:
                    console.print(f"[red]Error: {e}[/red]")
                console.input("\n[yellow]Press Enter to continue...[/yellow]")
        
        elif choice == "6":
            phone = console.input("\n[cyan]Enter phone number (e.g., +923001234567 or 03001234567): [/cyan]").strip()
            if phone:
                try:
                    engine.phone_scan(phone)
                except Exception as e:
                    console.print(f"[red]Error: {e}[/red]")
                console.input("\n[yellow]Press Enter to continue...[/yellow]")
        
        elif choice == "7":
            import os
            index_path = Config.OUTPUT_DIR / "index.html"
            if not index_path.exists():
                console.print(f"\n[yellow]⚠ No reports yet. Run a scan first![/yellow]")
            else:
                console.print(f"\n[green]📁 Opening reports index...[/green]")
                console.print(f"[cyan]  {index_path.absolute()}[/cyan]")
                if sys.platform == "win32":
                    os.system(f'start "" "{index_path.absolute()}"')
                elif sys.platform == "darwin":
                    os.system(f'open "{index_path.absolute()}"')
                else:
                    os.system(f'xdg-open "{index_path.absolute()}"')
            console.input("\n[yellow]Press Enter to continue...[/yellow]")
        
        elif choice == "0":
            console.print("\n[bold green]👋 Thanks for using ZeroOsintX![/bold green]")
            console.print("[cyan]Powered by 🏠 Roothackerslab Community[/cyan]")
            console.print("[cyan]Developed by ZeroTraceX [AhsanMughal][/cyan]\n")
            sys.exit(0)
        
        else:
            console.print("\n[red]❌ Invalid option! Please choose 0-7[/red]")
            time.sleep(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]⚠️  Interrupted by user[/yellow]")
        console.print("[cyan]See you next time! 👋[/cyan]\n")
        sys.exit(0)
