#!/usr/bin/env python3
"""
recon.py — ShadowGrid v3 CLI
Terminal alternative to the web interface.
Uses the same tool classes and storage layer as the backend.

Usage:
  python3 recon.py -d example.com
  python3 recon.py -d example.com --tools crtsh,subfinder,httpx,nuclei
  python3 recon.py -d example.com --passive-only
  python3 recon.py -d example.com --oos "*.internal.example.com"
"""
from __future__ import annotations
import argparse
import asyncio
import sys
import os
from datetime import datetime, timezone
from pathlib import Path

# Make sure backend/ is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from models import Scan, ScanStatus, new_id
from storage import SqlStorage
from scan_engine import run_scan
from tools.registry import REGISTRY

PASSIVE_TOOLS = [
    "crtsh","assetfinder","subfinder","amass",
    "dnsx","dns_records","zone_transfer",
    "waybackurls","gau","whois","asnmap",
]

BANNER = r"""
  ____              ___                _       _       _
 |  _ \            / _ \              | |     | |     | |
 | |_) |_   _  __ | | | |_   ______ _| |_ ___| |__   | |
 |  _ <| | | |/ _` | | \ \ / / _` | __/ __| '_ \    | |
 | |_) | |_| | (_| | |_| \ V / (_| | || (__| | | |   |_|
 |____/ \__,_|\__, |\___/ \_/ \__,_|\__\___|_| |_|   (_)
               __/ |
              |___/  v3.0  — Recon Framework
"""

def print_banner():
    print("\033[92m" + BANNER + "\033[0m")

async def main():
    print_banner()

    parser = argparse.ArgumentParser(description="ShadowGrid recon framework CLI")
    parser.add_argument("-d", "--domain", required=True, nargs="+", help="Target domain(s)")
    parser.add_argument("--oos", nargs="*", default=[], help="Out-of-scope patterns")
    parser.add_argument("--tools", help="Comma-separated tool list (default: all)")
    parser.add_argument("--passive-only", action="store_true", help="Only run passive tools")
    parser.add_argument("--wordlist", help="Custom DNS wordlist path")
    parser.add_argument("--output-dir", default="./output", help="Output directory")
    parser.add_argument("--data-dir", default="./data", help="Data directory")
    parser.add_argument("--list-tools", action="store_true", help="List available tools and exit")
    args = parser.parse_args()

    if args.list_tools:
        print(f"\n{'Tool':<20} {'Category':<14} {'Available':<10} Description")
        print("-" * 80)
        import shutil
        for name, cls in REGISTRY.items():
            avail = "✓" if (shutil.which(name) or name == "crtsh") else "✗"
            print(f"  {name:<18} {cls.category.value:<14} {avail:<10} {cls.description}")
        return

    # ── Resolve tool list ────────────────────────────────────────
    if args.tools:
        tools = [t.strip() for t in args.tools.split(",")]
    elif args.passive_only:
        tools = PASSIVE_TOOLS
    else:
        tools = list(REGISTRY.keys())

    output_dir = Path(args.output_dir)
    data_dir   = Path(args.data_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    # ── Storage ──────────────────────────────────────────────────
    storage = SqlStorage(str(output_dir))

    # ── Create project + scan ────────────────────────────────────
    from models import Project, Target
    project = Project(name=f"CLI-{args.domain[0]}", description="CLI scan")
    await storage.save_project(project)
    for dom in args.domain:
        await storage.save_target(Target(project_id=project.id, domain=dom))
    for o in args.oos:
        await storage.save_target(Target(project_id=project.id, domain=o, is_oos=True))

    scan = Scan(project_id=project.id, tools=tools, wordlist=args.wordlist)
    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.now(timezone.utc)
    await storage.save_scan(scan)

    print(f"\n\033[92m[+]\033[0m Scan ID:  {scan.id}")
    print(f"\033[92m[+]\033[0m Targets:  {', '.join(args.domain)}")
    print(f"\033[92m[+]\033[0m OOS:      {', '.join(args.oos) or '(none)'}")
    print(f"\033[92m[+]\033[0m Tools:    {len(tools)} selected")
    print(f"\033[92m[+]\033[0m Output:   {output_dir}\n")

    # ── Progress display ─────────────────────────────────────────
    import threading

    from scan_engine import get_progress_queue
    queue = get_progress_queue(scan.id)

    async def show_progress():
        while True:
            try:
                ev = await asyncio.wait_for(queue.get(), timeout=5)
                tool, status, msg, count = ev["tool"], ev["status"], ev.get("message",""), ev.get("count",0)
                if tool.startswith("__"):
                    if tool == "__phase__":
                        print(f"\n\033[96m[Phase]\033[0m {msg}")
                    elif tool == "__scan__":
                        break
                    continue
                color = {"running":"\033[93m","done":"\033[92m","error":"\033[91m","skipped":"\033[90m"}.get(status,"\033[0m")
                icon  = {"running":"⟳","done":"✓","error":"✗","skipped":"—"}.get(status,"?")
                suffix = f" ({count} results)" if count else ""
                print(f"  {color}{icon}\033[0m  \033[1m{tool:<18}\033[0m {status:<8} {msg}{suffix}")
            except asyncio.TimeoutError:
                pass

    progress_task = asyncio.create_task(show_progress())

    await run_scan(
        scan=scan,
        domains=args.domain,
        oos=args.oos,
        output_dir=output_dir,
        data_dir=data_dir,
        storage=storage,
    )

    await progress_task

    print(f"\n\033[92m[+]\033[0m Scan {scan.status.value.upper()} — results in {output_dir}")
    print(f"\033[92m[+]\033[0m Open the web UI or check {output_dir} for output files\n")


if __name__ == "__main__":
    asyncio.run(main())
