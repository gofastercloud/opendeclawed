# safe-install

A security-first skill for vetting and installing OpenClaw skills. Designed to be used as a one-shot command via Telegram (or any messaging channel).

## What it does

When you say **"install skill \<name\>"**, the agent runs a 6-step pipeline:

1. **Fetch** — Downloads the skill archive from ClawHub (or uses a local file)
2. **Hash** — Computes SHA256 and checks file size (rejects >50MB)
3. **Static analysis** — Extracts the archive and scans for:
   - Blocked permissions (`net:lan`, `fs:root`, `exec:shell`, `cap:*`)
   - Dangerous code patterns (`eval()`, `os.system()`, `subprocess.call(shell=True)`, private key access, hardcoded API keys, LAN access attempts)
   - Missing or malformed manifest
4. **VirusTotal scan** — Checks the hash against VT's database; uploads for scanning if unknown; waits up to 120s for results
5. **Allowlist update** — Adds the skill to `skills.allowlist.json` with hash, timestamp, and VT status
6. **Install** — Runs `openclaw skill install <name>` via CLI

If any step fails critically, the skill archive is **quarantined** (copied to `~/.openclaw/quarantine/` with metadata).

## Triggers

```
install skill <name>     # full pipeline: vet + allowlist + install
vet skill <name>         # scan only, no install
check skill <name>       # allowlist lookup only
```

## Required environment

| Variable | Description |
|---|---|
| `VIRUSTOTAL_API_KEY` | Free API key from [virustotal.com](https://www.virustotal.com/) |

## Optional environment

| Variable | Default | Description |
|---|---|---|
| `SKILLS_ALLOWLIST_PATH` | `~/.openclaw/skills.allowlist.json` | Path to allowlist file |
| `SKILL_QUARANTINE_DIR` | `~/.openclaw/quarantine/` | Where rejected skills go |

## Standalone usage

```bash
# Full pipeline
python3 safe_install.py --skill my-cool-skill

# Vet only (no install)
python3 safe_install.py --skill my-cool-skill --vet-only

# Re-vet an already allowlisted skill
python3 safe_install.py --skill my-cool-skill --force

# Vet a local archive
python3 safe_install.py --skill ./downloaded-skill.tar.gz
```

## Allowlist format

The allowlist at `~/.openclaw/skills.allowlist.json` contains:

```json
{
  "allowlist": {
    "skill-name": {
      "version": "1.0.0",
      "sha256": "abc123...",
      "source": "clawhub",
      "approved_by": "safe-install",
      "approved_at": "2026-02-16T00:00:00Z",
      "virustotal_clean": true
    }
  },
  "policy": {
    "enforce": true,
    "require_virustotal": true,
    "blocked_permissions": ["net:lan", "fs:root", "exec:shell"]
  }
}
```

## Security notes

- The allowlist file is created with mode `0600` (owner-only read/write)
- Quarantined files include full metadata for forensic review
- Static analysis catches the most common malicious patterns found in the wild (see: 341 malicious skills discovered on ClawHub in 2025)
- VirusTotal integration provides multi-engine AV coverage
- The skill itself only requests `read`, `write`, and `net:api` permissions — no shell access, no LAN access
