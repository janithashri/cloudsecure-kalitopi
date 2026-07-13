# Pre-push security checklist

Review before `git push` to a **public** repository.

## Must NEVER be committed

| File | Contains |
|------|----------|
| `.env` | `SECRET_KEY`, `POSTGRES_PASSWORD`, `NEO4J_PASSWORD`, AuraDB credentials |
| `frontend/.env` | Local API URL overrides |
| `IaC_backend/.env` | `SARVAM_API_KEY` (if set) |
| `~/.aws/` | AWS access keys (mounted in Docker, not in repo) |

All of the above are listed in `.gitignore`.

## Scrubbed before public release

- `trust-policy.json` uses `YOUR_ACCOUNT_ID` placeholder — replace with your AWS account ID locally
- Demo scripts read `AWS_ACCOUNT_ID` from the environment (default `123456789012`)
- No real account numbers, passwords, or host paths in committed files

## Safe to commit

- `.env.example` / `frontend/.env.example` — empty placeholders only
- Docs mentioning example passwords like `localpostgres123` — not real secrets

## After cloning (new machine)

```powershell
copy .env.example .env
# Fill in SECRET_KEY, POSTGRES_PASSWORD, NEO4J_URI, NEO4J_PASSWORD (AuraDB)
copy frontend\.env.example frontend\.env
```

Generate a new `SECRET_KEY`:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(50))"
```

## Neo4j AuraDB setup

1. Create a free instance at [Neo4j Aura](https://neo4j.com/cloud/aura/).
2. Copy the connection URI (`neo4j+s://...`) and password into `.env`.
3. Graph Data Science (GDS) for deep scan requires an Aura **Professional** instance or local Neo4j with the GDS plugin.

## Verify before push

```powershell
git status
git check-ignore -v .env frontend/.env
# .env should show as ignored

# Scan for accidental secrets (should return no real credentials)
Select-String -Path (git ls-files) -Pattern 'YOUR_REAL_PASSWORD|AKIA[0-9A-Z]{16}' 
```
