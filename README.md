# Secret Scan CLI
A production-ready Python CLI wrapper around Gitleaks for scanning multiple local repositories, generating a branded HTML report, and publishing a **sanitized** findings payload to Cloudvisor.

## Why this exists
`secret-scan-cli` makes local secret scanning simple for customers while standardizing what is shared upstream for centralized reporting.

- Scans repository history and working tree using Gitleaks.
- Generates a local HTML report for human review.
- Publishes a redacted JSON report to Cloudvisor.
- Supports optional engagement tagging for customer routing (`--eng-id`).

## About Gitleaks
This tool uses [Gitleaks](https://gitleaks.io/), an open-source (MIT) secret scanner for git repositories, files, directories, and stdin.

Useful official references:
- Gitleaks website: https://gitleaks.io/
- Gitleaks repository and docs: https://github.com/gitleaks/gitleaks

## Security and Privacy Guarantees
This is the most important behavior of this CLI.

### What is never published to Cloudvisor
- Raw source code content.
- Full secret values.

### What is published
- Finding metadata (rule, file path, line, commit metadata, etc.).
- `SecretRedacted` value only (masked representation).
- Optional top-level `engagement_id` when `--eng-id` is provided.

### How sanitization is enforced
Before publish, each finding is sanitized:
- `Secret` is removed.
- `Match` is removed.
- `SecretRedacted` is added (masked form).

## How it works
1. Discover repositories inside the input folder.
2. Ensure Gitleaks binary exists (local / PATH / download).
3. Run scans:
   - Git history scan.
   - Working tree scan (`--no-git`).
4. Build findings and enrich metadata.
5. Publish sanitized JSON payload to Cloudvisor queue.
6. Generate local HTML report.
7. Optionally write local JSON (`--json-output`).

## Requirements
- Python 3.10+ recommended.
- Network access to:
  - Gitleaks release download URL (first run if binary not present).
  - Cloudvisor publish endpoint (SQS URL configured in code).
- Git available in environment when scanning repository history.

## Quick Start
From `secret-scan-cli/`:

```bash
python3 gitleaks_scanner.py /path/to/folder/that/contains/repos
```

Example:

```bash
python3 gitleaks_scanner.py /Users/john/UserData/Projects/Repositories
```

## CLI Usage
```bash
python3 gitleaks_scanner.py <repos_path> [options]
```

### Positional
- `repos_path`: directory containing one or more repositories to scan.

### Options
- `--output <path>`: HTML report output path. Default: `gitleaks_report.html`
- `--gitleaks-path <path>`: use an existing Gitleaks binary (skip auto-download).
- `--no-git-history`: scan working tree only.
- `--color {auto|always|never}`: terminal color behavior.
- `--json-output <path>`: optionally save sanitized JSON payload locally.
- `--eng-id <value>`: optional Cloudvisor customer engagement ID.

## Output Artifacts
### HTML report
Generated locally at `--output` path.

Includes:
- summary cards,
- findings table,
- commit/author metadata,
- redacted secret display only.

### Cloud publish payload
Published automatically every run.

JSON shape (simplified):

```json
{
  "schema": "cloudvisor.secret-scan-report.v1",
  "generated_at": "YYYY-MM-DD HH:MM:SS",
  "repos_path": "...",
  "engagement_id": "optional",
  "summary": {
    "total_findings": 0,
    "repositories_affected": 0,
    "secret_types": 0
  },
  "findings": {
    "items": [
      {
        "RuleID": "...",
        "File": "...",
        "StartLine": 0,
        "SecretRedacted": "..."
      }
    ]
  }
}
```

## Exit Codes
- `0`: scan completed, no findings.
- `1`: scan completed, findings detected.
- `2`: runtime/setup error.

## Troubleshooting
### TLS certificate verification errors
If you see certificate verification failures during download or publish:
- Install Python certs (macOS framework Python):
  - `/Applications/Python 3.12/Install Certificates.command`
- Or install `certifi` in the active Python environment.
- Or provide a trusted local gitleaks binary with `--gitleaks-path`.

### AccessDenied on publish
If publish fails with `403 AccessDenied`, validate queue policy and encryption settings for your Cloudvisor endpoint.

### No repositories found
Ensure the input path contains directories (each expected to be a repo candidate).

## Operational Notes
- This tool currently targets Gitleaks `v8.18.2` by default.
- Findings coverage is rule-driven. If expected test secrets are missed, they may not match built-in rule patterns. Consider custom Gitleaks configuration for org-specific patterns.

## Best Practices
- Run scans in CI and on developer machines.
- Keep generated HTML reports local/internal.
- Treat sanitized cloud payloads as sensitive operational metadata.
- Add and maintain custom Gitleaks rules for your organization when needed.

## License
See [`LICENSE`](LICENSE) in this repository.
