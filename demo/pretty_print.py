"""pretty_print.py — render a ModernizationResponse JSON for the demo stage.

Usage:  curl ... /api/v1/modernize | python3 demo/pretty_print.py
"""

import json
import sys


def main() -> None:
    d = json.load(sys.stdin)

    print("\n" + "=" * 66)
    print(f"  PIPELINE RESULT   success={d['pipeline_success']}   auditor={d['auditor_source']}   sandbox={d['sandbox_source']}   {d['duration_ms']} ms")
    print("=" * 66)

    print(f"\n  Vulnerabilities found: {len(d['vulnerabilities'])}")
    for v in d["vulnerabilities"]:
        print(f"    [{v['severity']:>8}] {v['file_path']}:{v['line_number']}  {v['description'][:60]}")

    print(f"\n  CVE advisories matched: {len(d['cve_hits'])}")
    for c in d["cve_hits"][:5]:
        print(f"    {c['cve_id']:<16} {c['package']:<14} sev={c['severity']:<8} fix={c.get('fixed_version')}")

    print("\n  Refactor outcomes:")
    for r in d["refactors"]:
        score = f"{r['consensus_score']:.2f}" if r.get("consensus_score") is not None else "  —  "
        print(f"    {r['status']:<20} consensus={score} healing_attempts={r.get('healing_attempts')}")

    roi = d["roi_summary"]
    print(f"\n  ROI: {roi['total_hours_saved']} h saved | ${roi['total_cost_saved_usd']} | {roi['total_carbon_kg_co2e_per_year']} kg CO2e/yr")

    print("\n  Event timeline:")
    for t in d["event_timeline"]:
        print(f"    {t}")
    print()


if __name__ == "__main__":
    main()
