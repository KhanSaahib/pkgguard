"""Human-readable rendering of a ScanReport."""
from __future__ import annotations

from .scanner import ScanReport

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def render_text(report: ScanReport) -> str:
    lines = [f"pkgguard scan: {report.target}", f"verdict: {report.verdict}", ""]
    counts = report.severity_counts
    lines.append(
        "summary: "
        + ", ".join(f"{k.lower()}={counts[k]}" for k in _SEVERITY_ORDER if counts[k])
        or "summary: no findings"
    )
    lines.append("")
    for f in report.findings:
        lines.append(f"[{f.severity.name}] {f.rule_id} - {f.file}:{f.line}")
        lines.append(f"    {f.description}")
        if f.snippet:
            lines.append(f"    snippet: {f.snippet.strip()!r}")
    if not report.findings:
        lines.append("no suspicious patterns detected.")
    return "\n".join(lines)
