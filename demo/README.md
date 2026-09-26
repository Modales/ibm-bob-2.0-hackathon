# Demo Runbook — IBM Bob 2.0 Hackathon

Everything a judge (or teammate) needs to see the **Automated Enterprise
Legacy & Security Modernizer** run live in under two minutes.

## TL;DR

```bash
pip install -r services/orchestrator/requirements.txt -r services/auditor/requirements.txt
./demo/demo.sh            # full end-to-end run
./demo/demo.sh --watch    # run again with the live SSE event stream attached
```

## What the demo shows

`demo/legacy-app/` is a seeded "legacy enterprise" repo with real,
representative flaws across three languages:

| File | Seeded flaws |
| --- | --- |
| `app/auth.py` | md5 password hashing; SQL injection via f-string from `request.args` |
| `app/report.py` | `os.system` / `subprocess.call(shell=True)` command injection |
| `web/Login.tsx` | `eval()`, `dangerouslySetInnerHTML`, hardcoded API key |
| `legacy/BatchJob.java` | `Runtime.exec("rm -rf " + target)`, MD5 digest, hardcoded password |

The script seeds a small git history (so churn analysis has signal), then:

1. **Auditor** (`:8001`) — AST taint-flow + git churn → ranked risk report
2. **Orchestrator** (`:8000`, JWT-secured) — authenticates, then drives the
   bus: CVE vector lookup → IBM Bob refactor → AST safety gate → 3-agent
   consensus debate → self-healing sandbox loop
3. Prints the consolidated result: findings, CVE matches, per-file refactor
   verdicts, and the **ROI summary** (hours, dollars, CO₂e)

## Talking points for judges

- **Zero-trust**: the pipeline is unreachable without a JWT role claim
  (try it: call `/api/v1/modernize` without a token → 401).
- **Agentic safety**: every AI patch passes an AST gate (no injected `eval`,
  no Big-O regression) and a weighted 3-persona debate with a security veto.
- **Self-healing**: failing code is re-prompted through IBM Bob and re-tested
  with exponential backoff, up to 5 attempts.
- **Observable**: `/metrics` exposes Prometheus counters/histograms/gauge.
- **Polyglot**: Python gets deep AST analysis; JS/TS and Java get curated
  security scanning — findings feed the same pipeline.
- **Resilient**: every external dependency (auditor, sandbox, LLM, Bob CLI)
  has a deterministic offline fallback, so the demo cannot be bricked by the
  venue's Wi-Fi.

## Troubleshooting

- *"missing deps"* — run the pip install line above.
- *port already in use* — `lsof -ti :8000 -ti :8001 | xargs kill`.
- *auditor not found* — run `./demo/demo.sh` from a full repo checkout.
