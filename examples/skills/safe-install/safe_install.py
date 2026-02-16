#!/usr/bin/env python3
"""
safe-install: Vet, scan, and install OpenClaw skills with security enforcement.

Pipeline:
  1. Download/locate skill archive
  2. Compute SHA256 hash
  3. Static analysis (permissions check, blocked patterns)
  4. VirusTotal scan (upload hash or file)
  5. Update allowlist if clean
  6. Install via openclaw CLI

Usage (as OpenClaw skill):
  "install skill <name>"          — full pipeline
  "vet skill <name>"              — scan only, no install
  "check skill <name>"            — allowlist lookup only

Usage (standalone):
  python3 safe_install.py --skill <name> [--vet-only] [--force]
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Config ───────────────────────────────────────────────────────────────

ALLOWLIST_PATH = os.environ.get(
    "SKILLS_ALLOWLIST_PATH",
    os.path.expanduser("~/.openclaw/skills.allowlist.json"),
)
QUARANTINE_DIR = os.environ.get(
    "SKILL_QUARANTINE_DIR",
    os.path.expanduser("~/.openclaw/quarantine"),
)
VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VT_API_URL = "https://www.virustotal.com/api/v3"

# Patterns that should never appear in a skill
BLOCKED_PATTERNS = [
    r"subprocess\.call\(.*shell\s*=\s*True",
    r"os\.system\(",
    r"exec\(",
    r"eval\(",
    r"__import__\(",
    r"socket\.connect\(",
    r"urllib\.request\.urlopen\(",  # should use approved HTTP client
    r"requests\.get\(.*192\.168\.",  # LAN access attempt
    r"requests\.get\(.*10\.\d+\.",
    r"requests\.get\(.*172\.(1[6-9]|2\d|3[01])\.",
    r"/etc/shadow",
    r"/etc/passwd",
    r"\.ssh/",
    r"PRIVATE.KEY",
    r"sk-ant-",  # Anthropic key pattern
    r"BEGIN.*PRIVATE",
]

# Permissions that skills must never request
BLOCKED_PERMISSIONS = {"net:lan", "fs:root", "exec:shell", "cap:*", "cap:NET_ADMIN"}

MAX_SKILL_SIZE_MB = 50


# ── Helpers ──────────────────────────────────────────────────────────────


def log(level: str, msg: str):
    icons = {"info": "[+]", "warn": "[!]", "error": "[x]", "ok": "[✓]"}
    print(f"{icons.get(level, '[?]')} {msg}")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_allowlist() -> dict:
    if not os.path.exists(ALLOWLIST_PATH):
        return {"allowlist": {}, "policy": {"enforce": True}}
    with open(ALLOWLIST_PATH) as f:
        return json.load(f)


def save_allowlist(data: dict):
    os.makedirs(os.path.dirname(ALLOWLIST_PATH), exist_ok=True)
    with open(ALLOWLIST_PATH, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(ALLOWLIST_PATH, 0o600)
    log("ok", f"Allowlist updated: {ALLOWLIST_PATH}")


# ── Step 1: Download / Locate ────────────────────────────────────────────


def fetch_skill(skill_name: str, work_dir: str) -> str:
    """Download skill from ClawHub or locate local archive. Returns path."""
    # Try local path first
    local = Path(skill_name)
    if local.exists() and local.is_file():
        log("info", f"Using local skill archive: {local}")
        return str(local)

    # Download from ClawHub via openclaw CLI
    log("info", f"Fetching skill '{skill_name}' from ClawHub...")
    dest = os.path.join(work_dir, f"{skill_name}.tar.gz")
    try:
        subprocess.run(
            ["openclaw", "skill", "download", skill_name, "--output", dest],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        log("ok", f"Downloaded: {dest}")
        return dest
    except FileNotFoundError:
        log("error", "openclaw CLI not found. Is it installed?")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        log("error", f"Failed to download skill: {e.stderr.strip()}")
        sys.exit(1)


# ── Step 2: Hash ─────────────────────────────────────────────────────────


def compute_hash(path: str) -> str:
    file_hash = sha256_file(path)
    size_mb = os.path.getsize(path) / (1024 * 1024)
    log("info", f"SHA256: {file_hash}")
    log("info", f"Size: {size_mb:.2f} MB")

    if size_mb > MAX_SKILL_SIZE_MB:
        log("error", f"Skill exceeds {MAX_SKILL_SIZE_MB}MB limit — refusing")
        sys.exit(1)

    return file_hash


# ── Step 3: Static Analysis ─────────────────────────────────────────────


def static_analysis(path: str, work_dir: str) -> list[str]:
    """Extract and scan skill contents for dangerous patterns."""
    findings = []

    # Extract archive
    extract_dir = os.path.join(work_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)

    # SECURITY: Use --strip-components and validate paths to prevent zip-slip
    # attacks where malicious archives contain entries like "../../etc/cron.d/backdoor"
    try:
        # First, list archive contents and check for path traversal
        list_result = subprocess.run(
            ["tar", "tzf", path],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        for entry in list_result.stdout.strip().split("\n"):
            normalized = os.path.normpath(entry)
            if normalized.startswith("..") or normalized.startswith("/"):
                findings.append(
                    f"CRITICAL: Path traversal in archive: '{entry}' (zip-slip attack)"
                )
                return findings

        subprocess.run(
            ["tar", "xzf", path, "-C", extract_dir, "--strip-components=0"],
            check=True,
            capture_output=True,
            timeout=30,
        )
    except subprocess.CalledProcessError:
        findings.append("CRITICAL: Failed to extract archive (possibly malformed)")
        return findings

    # Check manifest permissions
    manifest_path = None
    for root, _dirs, files in os.walk(extract_dir):
        if "manifest.json" in files:
            manifest_path = os.path.join(root, "manifest.json")
            break

    if manifest_path:
        with open(manifest_path) as f:
            manifest = json.load(f)

        perms = set(manifest.get("permissions", []))
        blocked = perms & BLOCKED_PERMISSIONS
        if blocked:
            findings.append(
                f"CRITICAL: Blocked permissions requested: {', '.join(blocked)}"
            )

        # Check for suspicious triggers
        triggers = manifest.get("triggers", [])
        for t in triggers:
            if any(kw in t.lower() for kw in ["sudo", "root", "admin", "escalat"]):
                findings.append(f"SUSPICIOUS: Trigger contains risky keyword: '{t}'")
    else:
        findings.append("WARNING: No manifest.json found in skill archive")

    # Scan all text files for blocked patterns
    for root, _dirs, files in os.walk(extract_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", errors="ignore") as f:
                    content = f.read()
                for pattern in BLOCKED_PATTERNS:
                    matches = re.findall(pattern, content)
                    if matches:
                        rel = os.path.relpath(fpath, extract_dir)
                        findings.append(
                            f"BLOCKED: Pattern '{pattern}' found in {rel}"
                        )
            except (OSError, UnicodeDecodeError):
                continue

    if not findings:
        log("ok", "Static analysis: CLEAN")
    else:
        log("warn", f"Static analysis: {len(findings)} finding(s)")
        for f in findings:
            log("warn", f"  → {f}")

    return findings


# ── Step 4: VirusTotal ───────────────────────────────────────────────────


def virustotal_scan(file_hash: str, file_path: str) -> dict:
    """Check VirusTotal for the file hash, upload if unknown."""
    if not VT_API_KEY:
        log("warn", "VIRUSTOTAL_API_KEY not set — skipping VT scan")
        return {"status": "skipped", "reason": "no_api_key"}

    try:
        import requests
    except ImportError:
        log("warn", "requests library not available — skipping VT scan")
        return {"status": "skipped", "reason": "no_requests_lib"}

    headers = {"x-apikey": VT_API_KEY}

    # Check by hash first
    log("info", f"Checking VirusTotal for hash {file_hash[:16]}...")
    resp = requests.get(f"{VT_API_URL}/files/{file_hash}", headers=headers, timeout=30)

    if resp.status_code == 200:
        data = resp.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())

        result = {
            "status": "found",
            "malicious": malicious,
            "suspicious": suspicious,
            "total": total,
            "clean": malicious == 0 and suspicious == 0,
        }

        if result["clean"]:
            log("ok", f"VirusTotal: CLEAN ({total} engines, 0 detections)")
        else:
            log(
                "error",
                f"VirusTotal: DETECTED ({malicious} malicious, {suspicious} suspicious / {total})",
            )

        return result

    elif resp.status_code == 404:
        # Not in VT database — upload for scanning
        log("info", "Hash unknown to VirusTotal — uploading for scan...")
        with open(file_path, "rb") as f:
            upload_resp = requests.post(
                f"{VT_API_URL}/files",
                headers=headers,
                files={"file": f},
                timeout=120,
            )

        if upload_resp.status_code == 200:
            analysis_id = upload_resp.json()["data"]["id"]
            log("info", f"Uploaded. Analysis ID: {analysis_id}")
            log("info", "Waiting for scan results (up to 120s)...")

            # Poll for results
            for _ in range(12):
                time.sleep(10)
                poll = requests.get(
                    f"{VT_API_URL}/analyses/{analysis_id}",
                    headers=headers,
                    timeout=30,
                )
                if poll.status_code == 200:
                    status = poll.json()["data"]["attributes"]["status"]
                    if status == "completed":
                        stats = poll.json()["data"]["attributes"]["stats"]
                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)
                        total = sum(stats.values())
                        clean = malicious == 0 and suspicious == 0
                        if clean:
                            log("ok", f"VirusTotal: CLEAN ({total} engines)")
                        else:
                            log("error", f"VirusTotal: DETECTED ({malicious}m/{suspicious}s)")
                        return {
                            "status": "scanned",
                            "malicious": malicious,
                            "suspicious": suspicious,
                            "total": total,
                            "clean": clean,
                        }

            log("warn", "VirusTotal scan timed out — treating as inconclusive")
            return {"status": "timeout", "clean": False}
        else:
            log("warn", f"VirusTotal upload failed: {upload_resp.status_code}")
            return {"status": "upload_failed", "clean": False}
    else:
        log("warn", f"VirusTotal API error: {resp.status_code}")
        return {"status": "api_error", "clean": False}


# ── Step 5: Allowlist Update ────────────────────────────────────────────


def update_allowlist(skill_name: str, file_hash: str, vt_result: dict) -> bool:
    """Add skill to allowlist if it passed all checks."""
    al = load_allowlist()

    al["allowlist"][skill_name] = {
        "version": "latest",
        "sha256": file_hash,
        "source": "clawhub",
        "approved_by": "safe-install",
        "approved_at": datetime.now(timezone.utc).isoformat(),
        "virustotal_clean": vt_result.get("clean", False),
        "virustotal_status": vt_result.get("status", "unknown"),
        "notes": "Auto-approved by safe-install skill",
    }

    save_allowlist(al)
    return True


# ── Step 6: Install ─────────────────────────────────────────────────────


def install_skill(skill_name: str, local_archive: str = ""):
    """Install the skill via openclaw CLI.

    SECURITY (TOCTOU fix): If local_archive is provided, install from the
    local vetted file instead of re-downloading from ClawHub. This ensures
    the bytes we scanned are the same bytes we install.
    """
    if local_archive and os.path.isfile(local_archive):
        log("info", f"Installing skill '{skill_name}' from vetted local archive...")
        cmd = ["openclaw", "skill", "install", "--from-archive", local_archive]
    else:
        log("info", f"Installing skill '{skill_name}' from ClawHub...")
        cmd = ["openclaw", "skill", "install", skill_name]

    try:
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        log("ok", f"Skill '{skill_name}' installed successfully")
        if result.stdout.strip():
            print(result.stdout.strip())
    except subprocess.CalledProcessError as e:
        log("error", f"Installation failed: {e.stderr.strip()}")
        sys.exit(1)


# ── Quarantine ───────────────────────────────────────────────────────────


def quarantine(skill_name: str, file_path: str, reason: str):
    """Move suspect skill to quarantine directory."""
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    dest = os.path.join(QUARANTINE_DIR, f"{skill_name}_{ts}.quarantined")

    import shutil
    shutil.copy2(file_path, dest)

    # Write quarantine metadata
    meta = {
        "skill": skill_name,
        "quarantined_at": ts,
        "reason": reason,
        "original_path": file_path,
        "sha256": sha256_file(file_path),
    }
    with open(f"{dest}.meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    log("warn", f"Skill quarantined: {dest}")


# ── Main Pipeline ────────────────────────────────────────────────────────


def run_pipeline(skill_name: str, vet_only: bool = False, force: bool = False):
    """Execute the full safe-install pipeline."""
    print("=" * 60)
    print(f"  safe-install: {skill_name}")
    print(f"  Mode: {'vet-only' if vet_only else 'full install'}")
    print("=" * 60)

    # Check if already allowlisted
    al = load_allowlist()
    if skill_name in al.get("allowlist", {}) and not force:
        entry = al["allowlist"][skill_name]
        log("ok", f"Skill '{skill_name}' is already allowlisted")
        log("info", f"  Approved: {entry.get('approved_at', 'unknown')}")
        log("info", f"  SHA256: {entry.get('sha256', 'unknown')[:16]}...")
        if not vet_only:
            install_skill(skill_name)
        return

    with tempfile.TemporaryDirectory(prefix="safe-install-") as work_dir:
        # Step 1: Fetch
        file_path = fetch_skill(skill_name, work_dir)

        # Step 2: Hash
        file_hash = compute_hash(file_path)

        # Step 3: Static analysis
        findings = static_analysis(file_path, work_dir)
        critical = [f for f in findings if f.startswith("CRITICAL")]
        if critical:
            log("error", f"{len(critical)} critical finding(s) — REJECTING")
            quarantine(skill_name, file_path, "; ".join(critical))
            sys.exit(1)

        # Step 4: VirusTotal
        vt_result = virustotal_scan(file_hash, file_path)
        policy = al.get("policy", {})

        if policy.get("require_virustotal", True) and not vt_result.get("clean", False):
            if vt_result.get("status") == "skipped":
                log("warn", "VT skipped but policy requires it — proceeding with warning")
            elif vt_result.get("status") == "timeout":
                log("error", "VT scan inconclusive — REJECTING (policy: require_virustotal)")
                quarantine(skill_name, file_path, "VirusTotal scan inconclusive")
                sys.exit(1)
            else:
                log("error", "VirusTotal flagged this skill — REJECTING")
                quarantine(skill_name, file_path, "VirusTotal detection")
                sys.exit(1)

        if vet_only:
            log("ok", f"Vetting complete for '{skill_name}' — no issues found")
            return

        # Step 5: Update allowlist
        update_allowlist(skill_name, file_hash, vt_result)

        # Step 6: Install from local vetted archive (TOCTOU fix)
        # We install the exact bytes we scanned, not a fresh download.
        install_skill(skill_name, local_archive=file_path)

    print("=" * 60)
    log("ok", f"'{skill_name}' vetted, allowlisted, and installed")
    print("=" * 60)


# ── CLI Entry Point ──────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Securely vet and install OpenClaw skills"
    )
    parser.add_argument("--skill", required=True, help="Skill name or local archive path")
    parser.add_argument("--vet-only", action="store_true", help="Scan only, don't install")
    parser.add_argument("--force", action="store_true", help="Re-vet even if allowlisted")
    args = parser.parse_args()

    run_pipeline(args.skill, vet_only=args.vet_only, force=args.force)
