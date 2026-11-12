#!/usr/bin/env python
"""Interactive installer for JATMP.

    python install.py                 # interactive
    python install.py --mode single   # non-interactive single-user
    python install.py --mode multi --admin admin --password 'S3cure-Passw0rd'

You can also skip this and open the web UI: an un-installed instance shows a setup wizard.
"""
from __future__ import annotations

import argparse
import getpass
import sys


def ask(prompt: str, default: str = "") -> str:
    val = input(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
    return val or default


def main() -> int:
    ap = argparse.ArgumentParser(description="Install Just Another Threat Monitoring Platform")
    ap.add_argument("--mode", choices=["single", "multi"])
    ap.add_argument("--admin")
    ap.add_argument("--password")
    ap.add_argument("--no-seed", action="store_true", help="do not add the default sources")
    ap.add_argument("--force", action="store_true", help="re-run even if already installed")
    args = ap.parse_args()

    from app.config import is_installed

    if is_installed() and not args.force:
        print("Already installed. Use --force to re-run (data is kept).")
        return 0

    from app.auth import password_problems
    from app.setup_service import perform_install

    print("=== JATMP installer ===\n")
    mode = args.mode
    if not mode:
        print("Usage mode:\n  1) single-user  – no login, for a personal workstation\n"
              "  2) multi-user   – login required, roles, admin dashboard")
        mode = "multi" if ask("Choose 1 or 2", "1") == "2" else "single"

    admin, password = args.admin or "", args.password or ""
    if mode == "multi":
        admin = admin or ask("Admin username", "admin")
        while not password:
            pw = getpass.getpass("Admin password (min 10 chars, mixed case + digit): ")
            problem = password_problems(pw)
            if problem:
                print(f"  ! {problem}")
                continue
            if getpass.getpass("Repeat password: ") != pw:
                print("  ! passwords do not match")
                continue
            password = pw

    keys, llm = {}, {}
    if sys.stdin.isatty() and not args.mode:
        print("\nOptional API keys (press Enter to skip – you can add them later in Settings):")
        for k, label in (("virustotal_api_key", "VirusTotal"), ("otx_api_key", "AlienVault OTX"),
                         ("urlscan_api_key", "urlscan.io"), ("anyrun_api_key", "ANY.RUN"),
                         ("x_bearer_token", "X API bearer token")):
            v = getpass.getpass(f"  {label}: ").strip()
            if v:
                keys[k] = v
        print("\nLLM provider: none | ollama | openai_compatible | anthropic")
        prov = ask("  provider", "none")
        if prov != "none":
            llm["llm_provider"] = prov
            if prov in ("ollama", "openai_compatible"):
                llm["llm_base_url"] = ask("  base URL", "http://localhost:11434" if prov == "ollama" else "http://localhost:1234/v1")
            llm["llm_model"] = ask("  model", "llama3.1" if prov == "ollama" else "claude-opus-5-5" if prov == "anthropic" else "")
            if prov != "ollama":
                v = getpass.getpass("  API key (Enter to skip / use env): ").strip()
                if v:
                    llm["llm_api_key"] = v

    perform_install(mode=mode, admin_username=admin, admin_password=password,
                    seed_sources=not args.no_seed, api_keys=keys, llm=llm)
    print(f"\nInstalled in {mode}-user mode. Start with:  python run.py   then open http://127.0.0.1:8000")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
