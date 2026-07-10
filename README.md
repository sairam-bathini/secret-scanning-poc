# Secret Scanning POC

This proof-of-concept repository demonstrates local secret scanning and a GitHub Actions workflow for identifying exposed secrets.

## What was added

- `scanner/secret_scanner.py` - a Python secret scanner with GitHub-style detection patterns.
- `app/config.py` - sample app config with intentionally fake secret values.
- `.env.example` - fake secret environment variables for test scanning.
- `.github/workflows/secret-scanning-poc.yml` - workflow that runs the scanner on push and pull requests.

## How to run locally

```powershell
cd "c:\Users\admin\Downloads\secret-scanning-poc\secret-scanning-poc"
python scanner/secret_scanner.py --path . --summary
```

## What it detects

- GitHub personal access tokens
- AWS access key IDs
- AWS secret access keys
- Slack webhook URLs
- Stripe secret keys
- generic API keys and tokens
- database connection URIs with embedded credentials

## Notes

This repository is for demonstration only. Do not commit real secrets to version control.
