"""
report.py — Graham's report aggregator
Merges Matt's OSINT output + Mohith's VT results + Courtney's LLM output
into a unified JSON report, with optional HTML rendering.

Usage:
    from report import build_report, save_report

    report = build_report(osint, vt_data, llm_data)
    save_report(report, "output/report.json")
    save_report(report, "output/report.html")   # auto-detects format by extension
"""

import json
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Core aggregator
# ---------------------------------------------------------------------------

def build_report(osint: dict, vt_data: dict, llm_data: dict) -> dict:
    """
    Merge outputs from all three upstream modules into a unified report dict.

    Args:
        osint:    Output of Matt's ingest.injest() — full OSINT dict
        vt_data:  Output of Mohith's extract_report_data() — VT scan dict
        llm_data: Output of Courtney's LLM call — structured JSON with
                  risk_score, threat_class, iocs, reasoning

    Returns:
        Unified report dict.

    Raises:
        ValueError: If SHA-256 hashes from OSINT and VT don't match.
    """
    osint_sha256 = osint.get("hashes", {}).get("sha256", "")
    vt_sha256    = vt_data.get("sha256", "")

    # Reconcile SHA-256 between Matt and Mohith — mismatch = upstream error
    if osint_sha256 and vt_sha256 and osint_sha256.lower() != vt_sha256.lower():
        raise ValueError(
            f"SHA-256 mismatch between OSINT ({osint_sha256}) "
            f"and VirusTotal ({vt_sha256}). Aborting report."
        )

    sha256 = osint_sha256 or vt_sha256

    # Parse detection ratio string "X/Y" → integers
    detection_ratio_str = vt_data.get("detection_ratio", "0/0")
    try:
        det_num, det_denom = detection_ratio_str.split("/")
        det_num, det_denom = int(det_num), int(det_denom)
    except ValueError:
        det_num, det_denom = 0, 0

    return {
        "meta": {
            "generated_at":   datetime.now(timezone.utc).isoformat(),
            "schema_version": "1.0",
            "filename":       vt_data.get("filename", osint.get("hashes", {}).get("md5", "unknown")),
            "sha256":         sha256,
            "md5":            osint.get("hashes", {}).get("md5", ""),
            "sha1":           osint.get("hashes", {}).get("sha1", ""),
        },

        # ── Matt's OSINT block ──────────────────────────────────────────────
        "binary": {
            "file_size":  osint.get("file_size"),
            "arch":       osint.get("arch"),
            "security":   osint.get("security"),
            "entropy":    osint.get("entropy"),
            "sections":   osint.get("sections"),
            "imports":    osint.get("imports"),
            "symbols":    osint.get("symbols"),
            "strings":    osint.get("strings"),
            "static":     osint.get("static"),
            "elf_iocs": {
                "verdict":  osint.get("iocs", {}).get("verdict"),
                "severity": osint.get("iocs", {}).get("severity"),
                "counts":   osint.get("iocs", {}).get("counts"),
                "hits":     osint.get("iocs", {}).get("hits"),
            },
        },

        # ── Mohith's VirusTotal block ───────────────────────────────────────
        "virustotal": {
            "status":           vt_data.get("status"),
            "detection_ratio":  detection_ratio_str,
            "malicious_count":  vt_data.get("malicious_count", 0),
            "suspicious_count": vt_data.get("suspicious_count", 0),
            "times_submitted":  vt_data.get("times_submitted", 1),
        },

        # ── Courtney's LLM block ────────────────────────────────────────────
        "llm": {
            "risk_score":   llm_data.get("risk_score"),
            "threat_class": llm_data.get("threat_class"),
            "iocs":         llm_data.get("iocs", []),
            "reasoning":    llm_data.get("reasoning", ""),
        },

        # ── Rolled-up summary (top-level triage view) ───────────────────────
        "summary": {
            "sha256":          sha256,
            "detection_ratio": detection_ratio_str,
            "malicious_count": vt_data.get("malicious_count", 0),
            "vt_verdict":      _derive_vt_verdict(det_num, det_denom),
            "elf_verdict":     osint.get("iocs", {}).get("verdict", "UNKNOWN"),
            "risk_score":      llm_data.get("risk_score"),
            "threat_class":    llm_data.get("threat_class"),
            "iocs":            llm_data.get("iocs", []),
            "overall_verdict": _overall_verdict(
                det_num, det_denom,
                osint.get("iocs", {}).get("verdict", ""),
                llm_data.get("risk_score"),
            ),
        },
    }


# ---------------------------------------------------------------------------
# Verdict helpers
# ---------------------------------------------------------------------------

def _derive_vt_verdict(malicious: int, total: int) -> str:
    """Map raw VT detection counts to a human-readable verdict."""
    if total == 0:
        return "UNKNOWN"
    ratio = malicious / total
    if malicious == 0:
        return "CLEAN"
    elif ratio < 0.10:
        return "LOW"
    elif ratio < 0.30:
        return "MEDIUM"
    elif ratio < 0.60:
        return "HIGH"
    else:
        return "CRITICAL"


def _overall_verdict(
    malicious: int,
    total: int,
    elf_verdict: str,
    risk_score: float | None,
) -> str:
    """
    Roll up VT, ELF IOC, and LLM risk score into a single verdict.
    Takes the most severe signal.
    """
    severity_rank = {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "UNKNOWN": -1}

    vt_v   = _derive_vt_verdict(malicious, total)
    elf_v  = elf_verdict.upper() if elf_verdict else "UNKNOWN"

    # Map LLM risk score (0.0–1.0) to verdict tier
    if risk_score is None:
        llm_v = "UNKNOWN"
    elif risk_score >= 0.80:
        llm_v = "CRITICAL"
    elif risk_score >= 0.60:
        llm_v = "HIGH"
    elif risk_score >= 0.35:
        llm_v = "MEDIUM"
    elif risk_score >= 0.10:
        llm_v = "LOW"
    else:
        llm_v = "CLEAN"

    verdicts = [vt_v, elf_v, llm_v]
    return max(verdicts, key=lambda v: severity_rank.get(v, -1))


# ---------------------------------------------------------------------------
# Output: JSON + HTML
# ---------------------------------------------------------------------------

def save_report(report: dict, output_path: str) -> None:
    """
    Save report to disk. Detects format from file extension:
      .json → structured JSON
      .html → human-readable HTML report
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.suffix.lower() == ".html":
        path.write_text(_render_html(report), encoding="utf-8")
    else:
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"[+] Report saved → {output_path}")


def _verdict_color(verdict: str) -> str:
    return {
        "CRITICAL": "#c0392b",
        "HIGH":     "#e67e22",
        "MEDIUM":   "#f1c40f",
        "LOW":      "#27ae60",
        "CLEAN":    "#2ecc71",
    }.get(verdict.upper(), "#7f8c8d")


def _render_html(report: dict) -> str:
    """Render the unified report dict as a self-contained HTML page."""
    s   = report["summary"]
    m   = report["meta"]
    vt  = report["virustotal"]
    elf = report["binary"]["elf_iocs"]
    llm = report["llm"]

    verdict        = s.get("overall_verdict", "UNKNOWN")
    verdict_color  = _verdict_color(verdict)

    ioc_rows = "".join(
        f"<tr><td>{ioc}</td></tr>" for ioc in (s.get("iocs") or [])
    ) or "<tr><td><em>None identified</em></td></tr>"

    elf_hits = elf.get("hits") or {}
    elf_hit_rows = ""
    for category, items in elf_hits.items():
        if items:
            for item in items:
                elf_hit_rows += f"<tr><td>{category}</td><td>{item}</td></tr>"
    if not elf_hit_rows:
        elf_hit_rows = "<tr><td colspan='2'><em>None</em></td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>ELF Analysis Report — {m.get('filename', '')}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background: #f4f6f8; color: #2c3e50; font-size: 14px; line-height: 1.6; }}
  .page {{ max-width: 960px; margin: 32px auto; padding: 0 24px 64px; }}
  h1 {{ font-size: 22px; font-weight: 600; margin-bottom: 4px; }}
  h2 {{ font-size: 15px; font-weight: 600; margin-bottom: 12px; color: #2c3e50; }}
  .subtitle {{ color: #7f8c8d; font-size: 12px; margin-bottom: 32px; }}
  .verdict-banner {{ background: {verdict_color}; color: #fff;
                     border-radius: 10px; padding: 20px 28px; margin-bottom: 28px;
                     display: flex; align-items: center; gap: 20px; }}
  .verdict-badge {{ font-size: 26px; font-weight: 700; letter-spacing: 1px; }}
  .verdict-meta  {{ font-size: 13px; opacity: .88; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }}
  .card {{ background: #fff; border-radius: 8px; padding: 20px 24px;
           box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  .card.full {{ grid-column: 1 / -1; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ text-align: left; font-weight: 600; font-size: 12px; color: #7f8c8d;
        text-transform: uppercase; letter-spacing: .5px;
        border-bottom: 1px solid #ecf0f1; padding: 6px 8px; }}
  td {{ padding: 6px 8px; border-bottom: 1px solid #f4f6f8; font-size: 13px; }}
  tr:last-child td {{ border-bottom: none; }}
  .mono {{ font-family: "SF Mono", "Fira Code", monospace; font-size: 11px;
           word-break: break-all; color: #555; }}
  .tag {{ display: inline-block; padding: 2px 8px; border-radius: 4px;
          font-size: 11px; font-weight: 600; }}
  .risk-bar-wrap {{ background: #ecf0f1; border-radius: 4px; height: 8px; margin-top: 6px; }}
  .risk-bar {{ height: 8px; border-radius: 4px;
               background: {verdict_color}; width: {int((s.get('risk_score') or 0) * 100)}%; }}
  footer {{ text-align: center; color: #bdc3c7; font-size: 11px; margin-top: 40px; }}
</style>
</head>
<body>
<div class="page">

  <h1>ELF Binary Analysis Report</h1>
  <p class="subtitle">
    Generated {m.get('generated_at', '')} &nbsp;·&nbsp;
    {m.get('filename', '')}
  </p>

  <!-- Verdict banner -->
  <div class="verdict-banner">
    <div>
      <div style="font-size:12px;opacity:.8;margin-bottom:2px;">Overall verdict</div>
      <div class="verdict-badge">{verdict}</div>
    </div>
    <div style="flex:1">
      <div class="verdict-meta">VT: {s.get('detection_ratio','—')} engines &nbsp;|&nbsp;
        ELF IOC: {s.get('elf_verdict','—')} &nbsp;|&nbsp;
        Threat class: {s.get('threat_class') or '—'}
      </div>
      <div class="verdict-meta" style="margin-top:4px">
        Risk score: {f"{s.get('risk_score'):.2f}" if s.get('risk_score') is not None else '—'}
      </div>
    </div>
  </div>

  <div class="grid">

    <!-- Identity -->
    <div class="card">
      <h2>File identity</h2>
      <table>
        <tr><th>Field</th><th>Value</th></tr>
        <tr><td>Filename</td><td>{m.get('filename','')}</td></tr>
        <tr><td>SHA-256</td><td class="mono">{m.get('sha256','')}</td></tr>
        <tr><td>MD5</td><td class="mono">{m.get('md5','')}</td></tr>
        <tr><td>SHA-1</td><td class="mono">{m.get('sha1','')}</td></tr>
      </table>
    </div>

    <!-- VirusTotal -->
    <div class="card">
      <h2>VirusTotal</h2>
      <table>
        <tr><th>Field</th><th>Value</th></tr>
        <tr><td>Detection ratio</td><td><strong>{vt.get('detection_ratio','')}</strong></td></tr>
        <tr><td>Malicious</td><td>{vt.get('malicious_count',0)}</td></tr>
        <tr><td>Suspicious</td><td>{vt.get('suspicious_count',0)}</td></tr>
        <tr><td>Times submitted</td><td>{vt.get('times_submitted',1)}</td></tr>
        <tr><td>Scan status</td><td>{vt.get('status','')}</td></tr>
      </table>
    </div>

    <!-- LLM analysis -->
    <div class="card">
      <h2>LLM analysis</h2>
      <table>
        <tr><th>Field</th><th>Value</th></tr>
        <tr><td>Threat class</td><td>{llm.get('threat_class') or '—'}</td></tr>
        <tr><td>Risk score</td>
            <td>{f"{llm.get('risk_score'):.2f}" if llm.get('risk_score') is not None else '—'}
              <div class="risk-bar-wrap"><div class="risk-bar"></div></div>
            </td></tr>
      </table>
      <p style="margin-top:12px;font-size:12px;color:#555">{llm.get('reasoning','')}</p>
    </div>

    <!-- ELF IOC summary -->
    <div class="card">
      <h2>ELF IOC verdict</h2>
      <table>
        <tr><th>Field</th><th>Value</th></tr>
        <tr><td>Verdict</td>
            <td><span class="tag" style="background:{_verdict_color(elf.get('verdict','UNKNOWN'))};color:#fff">
              {elf.get('verdict','UNKNOWN')}
            </span></td></tr>
        <tr><td>Severity score</td><td>{elf.get('severity','—')}</td></tr>
        {"".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in (elf.get('counts') or {}).items())}
      </table>
    </div>

    <!-- LLM IOCs -->
    <div class="card">
      <h2>IOCs (from LLM)</h2>
      <table>
        <tr><th>Indicator</th></tr>
        {ioc_rows}
      </table>
    </div>

    <!-- ELF IOC hits -->
    <div class="card">
      <h2>ELF IOC hits</h2>
      <table>
        <tr><th>Category</th><th>Value</th></tr>
        {elf_hit_rows}
      </table>
    </div>

  </div><!-- /grid -->

  <footer>StaticElf · ElfAnalyzer pipeline · schema v1.0</footer>
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _cli():
    parser = argparse.ArgumentParser(
        description="Build a unified report from OSINT + VT + LLM outputs."
    )
    parser.add_argument("osint",   help="Path to Matt's osint_output.json")
    parser.add_argument("vt",      help="Path to Mohith's vt_output.json")
    parser.add_argument("llm",     help="Path to Courtney's llm_output.json")
    parser.add_argument("-o", "--output", default="report.json",
                        help="Output path — .json or .html (default: report.json)")
    args = parser.parse_args()

    def load(path):
        with open(path) as f:
            return json.load(f)

    try:
        osint_data = load(args.osint)
        vt_data    = load(args.vt)
        llm_data   = load(args.llm)
    except FileNotFoundError as e:
        print(f"[!] Input file not found: {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] JSON parse error: {e}")
        sys.exit(1)

    try:
        report = build_report(osint_data, vt_data, llm_data)
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)

    save_report(report, args.output)

    summary = report["summary"]
    print(f"    Overall verdict : {summary['overall_verdict']}")
    print(f"    VT detections   : {summary['detection_ratio']}")
    print(f"    ELF verdict     : {summary['elf_verdict']}")
    print(f"    Risk score      : {summary.get('risk_score')}")
    print(f"    Threat class    : {summary.get('threat_class')}")


if __name__ == "__main__":
    _cli()


