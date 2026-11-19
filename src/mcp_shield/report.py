"""Risk scoring and JSON / Markdown report rendering."""

import json
from datetime import datetime, timezone

from . import __version__
from .models import SEVERITY_ORDER, sort_findings

SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 7,
    "low": 3,
    "info": 1,
}


def risk_score(findings):
    """0 (clean) to 100 (maximally risky), weighted by severity."""
    return min(100, sum(SEVERITY_WEIGHTS[f.severity] for f in findings))


def grade(score):
    if score <= 0:
        return "clean"
    if score < 25:
        return "low"
    if score < 50:
        return "moderate"
    if score < 75:
        return "high"
    return "critical"


def build_report(target, findings, mode="audit"):
    findings = sort_findings(findings)
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] += 1
    score = risk_score(findings)
    return {
        "tool": "mcp-shield",
        "version": __version__,
        "mode": mode,
        "target": target,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "risk_score": score,
        "grade": grade(score),
        "summary": counts,
        "findings": [f.to_dict() for f in findings],
    }


def render_json(report):
    return json.dumps(report, indent=2) + "\n"


def _md_cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(report):
    lines = []
    lines.append("# mcp-shield audit report")
    lines.append("")
    lines.append("- **Target:** %s" % report["target"])
    lines.append("- **Mode:** %s" % report["mode"])
    lines.append("- **Generated (UTC):** %s" % report["generated_utc"])
    lines.append("- **Risk score:** %d/100 (%s)" % (report["risk_score"], report["grade"]))
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for sev in ("critical", "high", "medium", "low", "info"):
        lines.append("| %s | %d |" % (sev, report["summary"][sev]))
    lines.append("")
    if not report["findings"]:
        lines.append("No findings. The audited configuration looks clean.")
        lines.append("")
        return "\n".join(lines)
    lines.append("## Findings")
    lines.append("")
    lines.append("| # | Severity | Check | Location | Title |")
    lines.append("| --- | --- | --- | --- | --- |")
    for i, f in enumerate(report["findings"], 1):
        lines.append("| %d | %s | %s | %s | %s |" % (
            i, f["severity"], _md_cell(f["check_id"]),
            _md_cell(f["location"]), _md_cell(f["title"])))
    lines.append("")
    lines.append("## Details")
    for i, f in enumerate(report["findings"], 1):
        lines.append("")
        lines.append("### %d. [%s] %s" % (i, f["severity"].upper(), f["title"]))
        lines.append("")
        lines.append("- **Check:** `%s`" % f["check_id"])
        lines.append("- **Location:** %s" % f["location"])
        lines.append("- **Detail:** %s" % f["detail"])
        lines.append("- **Remediation:** %s" % f["remediation"])
    lines.append("")
    return "\n".join(lines)
