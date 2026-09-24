#!/usr/bin/env python3
"""Check the actual CLI production dependency closure after storage cutover."""
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
metadata = json.loads(subprocess.check_output([
    "cargo", "metadata", "--format-version", "1", "--locked", "--offline",
], cwd=root))
packages = {p["id"]: p for p in metadata["packages"]}
nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
cli = next(p["id"] for p in packages.values() if p["name"] == "radio-cli")
closure = set()
pending = [cli]
while pending:
    package = pending.pop()
    if package in closure:
        continue
    closure.add(package)
    pending.extend(d["pkg"] for d in nodes[package]["deps"]
                   if any(k["kind"] != "dev" for k in d["dep_kinds"]))
names = {packages[p]["name"] for p in closure}
legacy = {"iroh-blobs", "iroh-docs", "iroh-willow", "willow-store"}
found = names & legacy
if found:
    raise SystemExit("FAIL: CLI still closes over legacy stores: " + ", ".join(sorted(found)))
required = {"cybergraph", "cybergraph-radio", "bbg", "cyber-radio", "fjall", "redb"}
if missing := required - names:
    raise SystemExit("FAIL: missing shared storage/transport: " + ", ".join(sorted(missing)))
print("PASS: radio-cli uses Cybergraph/BBG; legacy blob/docs stores absent from its production closure")
workspace_names = {packages[p]["name"] for p in metadata["workspace_members"]}
print("Remaining legacy workspace packages: " + ", ".join(sorted(workspace_names & legacy)))
print("This checks CLI cutover only; full Radio storage extraction remains open.")
