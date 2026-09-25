#!/usr/bin/env bash
#
# scaffold-ibm-bob-2.0-hackathon.sh
# Scaffolds the shared team repository for the IBM Bob 2.0 hackathon.
#
# Usage:
#   chmod +x scaffold-ibm-bob-2.0-hackathon.sh
#   ./scaffold-ibm-bob-2.0-hackathon.sh
#
set -euo pipefail

REPO_NAME="ibm-bob-2.0-hackathon"

echo ">>> Scaffolding ${REPO_NAME} ..."

# ---------------------------------------------------------------------------
# Repository root + git init
# ---------------------------------------------------------------------------
mkdir -p "${REPO_NAME}"
cd "${REPO_NAME}"

if [ ! -d .git ]; then
  git init -b main
fi

# ---------------------------------------------------------------------------
# Directory structure
# ---------------------------------------------------------------------------
mkdir -p frontend
mkdir -p services/sandbox
mkdir -p services/auditor
mkdir -p services/orchestrator

# ---------------------------------------------------------------------------
# /frontend — placeholder package.json + index.html
# ---------------------------------------------------------------------------
cat > frontend/package.json <<'EOF'
{
  "name": "ibm-bob-2-0-hackathon-frontend",
  "version": "0.1.0",
  "private": true,
  "description": "Frontend for the IBM Bob 2.0 hackathon project. Owner: Tiffany.",
  "scripts": {
    "dev": "echo \"TODO: wire up dev server\"",
    "build": "echo \"TODO: wire up build\"",
    "test": "echo \"TODO: add tests\""
  }
}
EOF

cat > frontend/index.html <<'EOF'
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>IBM Bob 2.0 Hackathon — Frontend</title>
  </head>
  <body>
    <h1>IBM Bob 2.0 Hackathon</h1>
    <p>Frontend placeholder. Owner: Tiffany.</p>
  </body>
</html>
EOF

# ---------------------------------------------------------------------------
# /services/sandbox — placeholder main.py, Dockerfile, requirements.txt
# ---------------------------------------------------------------------------
cat > services/sandbox/main.py <<'EOF'
"""Sandbox service — IBM Bob 2.0 hackathon. Owner: Ilyas."""


def main() -> None:
    print("sandbox service placeholder")


if __name__ == "__main__":
    main()
EOF

cat > services/sandbox/Dockerfile <<'EOF'
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "main.py"]
EOF

cat > services/sandbox/requirements.txt <<'EOF'
# Sandbox service dependencies — add below as needed.
EOF

# ---------------------------------------------------------------------------
# /services/auditor — placeholder main.py + requirements.txt
# ---------------------------------------------------------------------------
cat > services/auditor/main.py <<'EOF'
"""Auditor service — IBM Bob 2.0 hackathon. Owner: Rumman."""


def main() -> None:
    print("auditor service placeholder")


if __name__ == "__main__":
    main()
EOF

cat > services/auditor/requirements.txt <<'EOF'
# Auditor service dependencies — add below as needed.
EOF

# ---------------------------------------------------------------------------
# /services/orchestrator — placeholder main.py + requirements.txt
# ---------------------------------------------------------------------------
cat > services/orchestrator/main.py <<'EOF'
"""Orchestrator service — IBM Bob 2.0 hackathon. Owner: repo admin."""


def main() -> None:
    print("orchestrator service placeholder")


if __name__ == "__main__":
    main()
EOF

cat > services/orchestrator/requirements.txt <<'EOF'
# Orchestrator service dependencies — add below as needed.
EOF

# ---------------------------------------------------------------------------
# .gitignore — Python + Node
# ---------------------------------------------------------------------------
cat > .gitignore <<'EOF'
# ---- Python ----
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
dist/
*.egg-info/
.eggs/
.venv/
venv/
env/
ENV/
.pytest_cache/
.mypy_cache/
.ruff_cache/
.coverage
htmlcov/
pip-log.txt

# ---- Node ----
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*
pnpm-debug.log*
.npm
.yarn/
.pnp.*

# ---- Env / secrets ----
.env
.env.*
!.env.example

# ---- OS / editors ----
.DS_Store
Thumbs.db
.idea/
.vscode/
*.swp
EOF

# ---------------------------------------------------------------------------
# README.md — architecture map + team workflow rules
# ---------------------------------------------------------------------------
cat > README.md <<'EOF'
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
EOF

# ---------------------------------------------------------------------------
# Initial commit
# ---------------------------------------------------------------------------
git add -A
git commit -m "chore: scaffold repo structure for IBM Bob 2.0 hackathon" || true

echo ">>> Done. Repository '${REPO_NAME}' is ready."
echo ">>> Next: git remote add origin git@github.com:<org>/${REPO_NAME}.git && git push -u origin main"
