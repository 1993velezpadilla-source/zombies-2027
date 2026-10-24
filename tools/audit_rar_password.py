#!/usr/bin/env python3
"""Safely enumerate an encrypted archive with the user-supplied password. Never extract or execute."""
import collections
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
import requests

REPO = os.environ.get("GITHUB_REPOSITORY", "1993velezpadilla-source/zombies-2027")
TAG = "requested-downloads-2026-10-23"
PASS = os.environ.get("RAR_AUDIT_PASSWORD")
ORIGINAL_SHA = "e094a78a769ad8566aa304b13c232427bb770035ece4f678250d9621670e55a3"
OUT = Path("audits")
OUT.mkdir(exist_ok=True)
TEMP = Path("/tmp/zombies-password-audit")
TEMP.mkdir(exist_ok=True)

def download_archive():
    h = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GH_TOKEN"): h["Authorization"] = "Bearer " + os.environ["GH_TOKEN"]
    session = requests.Session()
    session.headers.update(h)
    r = session.get("https://api.github.com/repos/" + REPO + "/releases/tags/" + TAG, timeout=45)
    r.raise_for_status()
    all_assets = r.json()["assets"]
    parts = sorted((a for a in all_assets if re.search(r"\.rar\.part\d{3}$", a["name"])),
                   key=lambda a: int(a["name"].rsplit("part",1)[-1]))
    if len(parts)!=11: raise RuntimeError("Expected 11 RAR parts, got " + str(len(parts)))
    expected_size = sum(a["size"] for a in parts)
    free_bytes = shutil.disk_usage(TEMP).free
    if free_bytes < expected_size + 300_000_000:
        raise RuntimeError("Insufficient disk space for reconstructed archive")
    dest = TEMP / parts[0]["name"].rsplit(".part",1)[0]
    full_sha = hashlib.sha256()
    count = 0
    with dest.open("wb") as fout:
        for idx, asset in enumerate(parts, 1):
            part_sha = hashlib.sha256()
            part_size = 0
            with session.get(asset["browser_download_url"], stream=True, timeout=(45,180)) as response:
                response.raise_for_status()
                for data in response.iter_content(4*1024*1024):
                    if data:
                        fout.write(data)
                        full_sha.update(data)
                        part_sha.update(data)
                        part_size += len(data)
                        count += len(data)
            if part_size != asset["size"] or "sha256:"+part_sha.hexdigest() != asset.get("digest"):
                raise RuntimeError("Bad part checksum at part " + str(idx))
            print("VALID_PART",idx,"/",len(parts),part_size,flush=True)
    if full_sha.hexdigest() != ORIGINAL_SHA:
        raise RuntimeError("RAR SHA-256 does not match original manifest")
    return dest, count

def inspect(path, archive_bytes):
    if not PASS: raise RuntimeError("No RAR_AUDIT_PASSWORD environment variable provided")
    # Listing with -slt makes no extraction, installation or execution of the contents.
    result = subprocess.run(["7z", "l", "-slt", "-y", "-p"+PASS, str(path)],
                            input="", text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=600)
    log = result.stdout.replace(PASS,"[REDACTED]")
    (OUT/"rar-password-7zip-listing.txt").write_text(log)
    sections = log.split("----------",1)
    entries=[]
    if len(sections)>1:
        for block in re.split(r"\n\s*\n",sections[1]):
            fields={}
            for line in block.splitlines():
                if " = " in line:
                    k,v=line.split(" = ",1)
                    fields[k.strip()]=v.strip()
            if "Path" in fields:
                sz=fields.get("Size","")
                entries.append({
                  "path":fields["Path"], "size":int(sz) if sz.isdigit() else None,
                  "directory":fields.get("Folder")=="+" or fields.get("Attributes","").startswith("D"),
                  "encrypted":fields.get("Encrypted"), "method":fields.get("Method"),
                  "crc":fields.get("CRC")
                })
    accepted = result.returncode == 0 and bool(entries)
    files = [x for x in entries if not x["directory"]]
    folders = [x for x in entries if x["directory"]]
    extensions = collections.Counter(Path(x["path"]).suffix.lower() or "(none)" for x in files)
    toplvl = collections.Counter(re.split(r"[/\\]",x["path"])[0] for x in files)
    active = [x for x in files if Path(x["path"]).suffix.lower() in {
        ".exe",".dll",".sys",".bat",".cmd",".ps1",".msi",".vbs",".jar",".sh",".js",
        ".scr",".apk",".so",".py",".lua",".gd"}]
    traversal = [x["path"] for x in entries if x["path"].startswith(("/","\\")) or
                 re.match(r"^[A-Za-z]:",x["path"]) or ".." in re.split(r"[/\\]",x["path"])]
    report = {
        "timestamp_utc":datetime.now(timezone.utc).isoformat(),
        "archive":path.name, "archive_bytes":archive_bytes,
        "sha256":ORIGINAL_SHA, "sha256_verified":True,
        "7zip_returncode":result.returncode, "password_accepted_for_headers":accepted,
        "file_count":len(files) if accepted else None,
        "directory_count":len(folders) if accepted else None,
        "uncompressed_bytes":sum(x["size"] or 0 for x in files) if accepted else None,
        "extensions":extensions.most_common(),
        "top_level":toplvl.most_common(80),
        "largest_files":sorted(files,key=lambda x:x["size"] or 0,reverse=True)[:80],
        "executable_and_code_files":active[:500],
        "traversal":traversal[:100],
        "files":entries if accepted else [],
        "note":"Static list only; no contents were extracted/executed. Password not saved."
    }
    (OUT/"rar-password-inventory.json").write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n")
    lines=["# RAR password follow-up audit", "",
          "Date UTC: "+report["timestamp_utc"],
          "RAR: "+path.name,
          "Original RAR SHA-256 matched: YES",
          "Password accepted for listing encrypted headers: "+str(accepted),
          "7z return code: "+str(result.returncode), ""]
    if accepted:
        lines += ["Files: "+str(len(files)),
                  "Directories: "+str(len(folders)),
                  "Total declared unpacked bytes: "+str(report["uncompressed_bytes"]),
                  "Executable/script candidate count: "+str(len(active)),
                  "Suspicious path candidate count: "+str(len(traversal)),
                  "", "## Top directories"]
        lines += ["- "+name+": "+str(n)+" files" for name,n in toplvl.most_common(40)]
        lines += ["", "## File extensions"]
        lines += ["- "+name+": "+str(n) for name,n in extensions.most_common(40)]
        lines += ["", "## Largest files"]
        lines += ["- "+x["path"]+": "+str(x["size"])+" bytes" for x in report["largest_files"][:50]]
        lines += ["", "## Executables/scripts (first 100)"]
        lines += ["- "+x["path"] for x in active[:100]]
        if traversal:
            lines += ["", "## Potential path traversal"]
            lines += ["- "+p for p in traversal[:50]]
    else:
        lines += ["7-Zip did not yield a valid contents listing.",
                  "## Error excerpt", "~~~",log[-2000:],"~~~"]
    lines += ["", "## Limitations",
              "This is only an archive metadata listing; it does not establish malware safety.",
              "No extracted contents were tested or executed. Full internal CRC and sandbox are not included.",
              "The supplied password is not written to this report."]
    (OUT/"rar-password-audit.md").write_text("\n".join(lines)+"\n")
    print("PASSWORD_ACCEPTED_FOR_HEADER",accepted,flush=True)
    print("FILE_COUNT",len(files),"FOLDER_COUNT",len(folders),flush=True)
    print("TOP_DIRS",toplvl.most_common(20),flush=True)
    print("EXTENSIONS",extensions.most_common(30),flush=True)
    print("FIRST_FILES",[(x["path"],x["size"]) for x in files[:25]],flush=True)
    if not accepted: raise RuntimeError("Password rejected or 7z listing failed")

if __name__ == "__main__":
    p, size = download_archive()
    inspect(p,size)
