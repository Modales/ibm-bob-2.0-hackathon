# IBM Bob 2.0 Hackathon

Shared team repository for the IBM Bob 2.0 hackathon.

## Architecture

```
ibm-bob-2.0-hackathon/
├── frontend/                  # Web frontend (Node)
│   ├── package.json
│   └── index.html
├── services/
│   ├── sandbox/               # Sandbox execution service (Python)
│   │   ├── main.py
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   ├── auditor/               # Auditor service (Python)
│   │   ├── main.py
│   │   └── requirements.txt
│   └── orchestrator/          # Orchestrator service (Python)
│       ├── main.py
│       └── requirements.txt
├── .gitignore                 # Python + Node ignores
└── README.md
```

| Directory               | Owner    | Stack          |
| ----------------------- | -------- | -------------- |
| `frontend/`             | Tiffany  | Node / HTML    |
| `services/sandbox/`     | Ilyas    | Python, Docker |
| `services/auditor/`     | Rumman   | Python         |
| `services/orchestrator/`| Admin    | Python         |

## Team workflow — read this before pushing

To prevent git merge conflicts, **everyone works strictly inside their own
assigned directory**:

1. **Branch off `main`** before starting any work:
   ```bash
   git checkout main && git pull
   git checkout -b <your-name>/<short-description>
   # e.g. git checkout -b tiffany/frontend-login-page
   ```
2. **Only touch files in your assigned directory.** Do not edit, reformat,
   rename, or delete files outside it — including the root `README.md` and
   `.gitignore` (request changes to shared files via an issue or PR comment
   instead).
3. Commit early and often, push your branch, and open a pull request when
   ready. Keep PRs scoped to your own directory.
4. Rebase on `main` regularly to stay current:
   ```bash
   git fetch origin && git rebase origin/main
   ```

If you need a shared change (e.g. a new top-level folder or a contract
between services), coordinate in the team channel first — never edit another
owner's directory directly.
