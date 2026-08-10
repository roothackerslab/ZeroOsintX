"""Report generation: save scan results as HTML, JSON, CSV, or Markdown."""
from __future__ import annotations

import csv
import html
import io
import json
import os
from datetime import datetime

from config import settings

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>ZeroOSINTx Report — {target}</title>
<style>
  :root {{ --bg:#0a0e0c; --panel:#111713; --line:#1d2621; --text:#c8d6cc; --accent:#3ee08c; --muted:#6b7c72; }}
  * {{ box-sizing:border-box; }}
  body {{ background:var(--bg); color:var(--text); font-family:'JetBrains Mono',ui-monospace,monospace; margin:0; padding:2.5rem; }}
  h1 {{ color:var(--accent); font-size:1.4rem; letter-spacing:.02em; margin-bottom:.2rem; }}
  .meta {{ color:var(--muted); font-size:.8rem; margin-bottom:2rem; }}
  .card {{ background:var(--panel); border:1px solid var(--line); border-radius:6px; padding:1.2rem 1.4rem; margin-bottom:1rem; }}
  .card h2 {{ color:var(--accent); font-size:.95rem; margin:0 0 .8rem; border-bottom:1px solid var(--line); padding-bottom:.5rem; }}
  pre {{ white-space:pre-wrap; word-break:break-word; font-size:.8rem; color:var(--text); margin:0; }}
  .status-ok {{ color:var(--accent); }}
  .status-skipped {{ color:#e0b93e; }}
  .status-error {{ color:#e05a5a; }}
</style></head>
<body>
  <h1>&gt; ZeroOSINTx Report</h1>
  <div class="meta">target: {target} · generated: {timestamp}</div>
  {sections}
</body></html>"""


def _section(title: str, payload: dict) -> str:
    status = payload.get("status", "ok") if isinstance(payload, dict) else "ok"
    body = html.escape(json.dumps(payload, indent=2, default=str))
    return f'<div class="card"><h2 class="status-{status}">{html.escape(str(title))}</h2><pre>{body}</pre></div>'


def _flatten_for_csv(data: dict, prefix: str = "") -> list[tuple[str, str]]:
    rows = []
    for k, v in data.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            rows.extend(_flatten_for_csv(v, key))
        elif isinstance(v, list):
            rows.append((key, json.dumps(v, default=str)))
        else:
            rows.append((key, str(v)))
    return rows


_ALLOWED_FORMATS = {"html", "json", "csv", "markdown", "md"}


def save(target: str, module: str, data: dict, fmt: str = "html") -> str:
    os.makedirs(settings.reports_dir, exist_ok=True)
    safe_target = "".join(c if c.isalnum() or c in "._-" else "_" for c in target) or "unknown"
    safe_module = "".join(c if c.isalnum() or c in "._-" else "_" for c in module) or "scan"
    fmt = fmt if fmt in _ALLOWED_FORMATS else "html"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{safe_module}_{safe_target}_{ts}.{fmt}"
    path = os.path.join(settings.reports_dir, filename)
    if os.path.commonpath([os.path.abspath(path), os.path.abspath(settings.reports_dir)]) != os.path.abspath(settings.reports_dir):
        raise ValueError("resolved report path escaped the reports directory")

    if fmt == "json":
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    elif fmt == "markdown" or fmt == "md":
        lines = [f"# ZeroOSINTx Report — {target}", f"_module: {module} · generated: {datetime.now().isoformat()}_", ""]
        lines.append("```json")
        lines.append(json.dumps(data, indent=2, default=str))
        lines.append("```")
        with open(path, "w") as f:
            f.write("\n".join(lines))

    elif fmt == "csv":
        rows = _flatten_for_csv(data if isinstance(data, dict) else {"value": data})
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["field", "value"])
        writer.writerows(rows)
        with open(path, "w") as f:
            f.write(buf.getvalue())

    else:  # html
        sections = _section(module, data)
        rendered_html = HTML_TEMPLATE.format(
            target=html.escape(str(target)), timestamp=datetime.now().isoformat(), sections=sections
        )
        with open(path, "w") as f:
            f.write(rendered_html)

    return path
