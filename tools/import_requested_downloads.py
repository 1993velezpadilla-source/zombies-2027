#!/usr/bin/env python3
"""One-shot importer of two user-requested public downloads into GitHub Releases."""
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import requests

ROOT = Path("incoming")
ROOT.mkdir(exist_ok=True)
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"
SOURCES = {
    "gofile": "https://gofile.io/d/BB8eY1",
    "gamehub": "https://gamehub.xiaoji.com/en/",
}
RESULTS = []
ERRORS = []


def transfer(url, path, headers=None):
    """Download a real binary with streaming and basic integrity checks."""
    session = requests.Session()
    session.headers.update({"User-Agent": UA, "Referer": "https://gofile.io/"})
    if headers:
        session.headers.update(headers)
    path.parent.mkdir(parents=True, exist_ok=True)
    with session.get(url, stream=True, timeout=(30, 120), allow_redirects=True) as r:
        r.raise_for_status()
        ct = r.headers.get("content-type", "").lower()
        if "text/html" in ct or "application/json" in ct:
            raise RuntimeError(f"Refusing web page/API response instead of file: {r.url} {ct}")
        size = 0
        digest = hashlib.sha256()
        with path.open("wb") as fd:
            for block in r.iter_content(chunk_size=2**20):
                if block:
                    fd.write(block)
                    digest.update(block)
                    size += len(block)
    if size < 100:
        path.unlink(missing_ok=True)
        raise RuntimeError("Downloaded file was unexpectedly small")
    return {"filename": path.name, "bytes": size, "sha256": digest.hexdigest(),
            "source": url, "saved_path": str(path)}


def safe_name(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:170] or "download.bin"


def gofile():
    """Read public share through Gofile's guest-account API."""
    s = requests.Session()
    s.headers.update({"user-agent": UA, "origin": "https://gofile.io",
                      "referer": "https://gofile.io/", "accept": "application/json"})
    response = s.post("https://api.gofile.io/accounts", timeout=45)
    response.raise_for_status()
    account = response.json()
    if account.get("status") != "ok":
        raise RuntimeError(f"Gofile guest account error: {str(account)[:300]}")
    token = account.get("data", {}).get("token")
    if not token:
        raise RuntimeError("Gofile guest API returned no account token")
    s.headers["Authorization"] = f"Bearer {token}"
    # Gofile introduced a rotating X-Website-Token; without it, even public
    # shares return HTTP 401. Use the same website-provided generator.
    s.headers["X-BL"] = "en-US"
    s.headers["Accept-Language"] = "en-US,en;q=0.9"
    website_tokens = []
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
            page = browser.new_page(user_agent=UA, locale="en-US")
            page.goto(SOURCES["gofile"], wait_until="domcontentloaded", timeout=45000)
            page.wait_for_function("typeof generateWT === 'function'", timeout=12000)
            dynamic = page.evaluate("(accountToken) => generateWT(accountToken)", token)
            if dynamic:
                website_tokens.append(str(dynamic))
            browser.close()
    except Exception as exc:
        print(f"Website WT generator was not available: {exc}", file=sys.stderr)
    # Compatibility with the public 2026 Gofile WT-generation algorithm.
    for salt in ("12af056dacea0b", "9844d94d963d30"):
        for slot in (int(time.time()) // 14400, (int(time.time()) // 14400) - 1):
            raw = f"{UA}::en-US::{token}::{slot}::{salt}"
            website_tokens.append(hashlib.sha256(raw.encode()).hexdigest())

    visited = set()

    def walk(code, prefix=""):
        if code in visited:
            return
        visited.add(code)
        response = None
        for wt in website_tokens:
            s.headers["X-Website-Token"] = wt
            current = s.get(f"https://api.gofile.io/contents/{code}",
                            params={"pageSize": 1000, "page": 1},
                            timeout=60)
            if current.status_code == 200:
                response = current
                break
            if current.status_code == 429:
                raise RuntimeError("Gofile rate limited the guest-account download")
        if response is None:
            raise RuntimeError(f"Gofile rejected all website tokens, final HTTP {current.status_code}")
        body = response.json()
        if body.get("status") != "ok":
            raise RuntimeError(f"Gofile public share access error: {str(body)[:350]}")
        content = body.get("data") or {}
        if content.get("type") == "file":
            children = [content]
        else:
            children = list((content.get("children") or {}).values())
            if not children:
                raise RuntimeError("Gofile share contained no accessible files")
        for child in children:
            if child.get("type") == "folder":
                walk(child.get("id"), prefix + safe_name(child.get("name", "folder")) + "_")
                continue
            if child.get("type") != "file":
                continue
            link = child.get("link")
            if not link:
                ERRORS.append(f"Gofile: no direct link for {child.get('name')}")
                continue
            filename = prefix + safe_name(child.get("name") or child.get("id", "file.bin"))
            dest = ROOT / "gofile" / filename
            if dest.exists():
                dest = ROOT / "gofile" / (str(child.get("id", "copy")) + "_" + filename)
            try:
                RESULTS.append(transfer(link, dest, {"Cookie": f"accountToken={token}"}))
            except Exception as exc:
                ERRORS.append(f"Gofile file {filename}: {exc}")

    walk("BB8eY1")


def gamehub():
    """Click official Android download rather than sourcing a third-party APK mirror."""
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
        context = browser.new_context(accept_downloads=True, user_agent=UA)
        page = context.new_page()
        download_urls = []
        page.on("request", lambda request: download_urls.append(request.url)
                if ".apk" in request.url.lower() else None)
        page.goto(SOURCES["gamehub"], wait_until="domcontentloaded", timeout=60000)
        page.wait_for_timeout(2500)
        candidates = page.locator("a, button").filter(
            has_text=re.compile(r"Android", flags=re.IGNORECASE))
        if candidates.count() == 0:
            raise RuntimeError("Official site has no Android download button")
        button = candidates.first
        try:
            with page.expect_download(timeout=60000) as download_info:
                button.click(timeout=15000)
            download = download_info.value
            dest = ROOT / "gamehub" / safe_name(download.suggested_filename or "GameHub.apk")
            dest.parent.mkdir(parents=True, exist_ok=True)
            download.save_as(dest)
            if dest.stat().st_size < 100:
                raise RuntimeError("GameHub download was empty")
            # GameHub may distribute an APK or packaged XAPK; preserve original extension.
            with dest.open("rb") as fh:
                if fh.read(2) != b"PK":
                    raise RuntimeError("Downloaded Android package isn't a ZIP/APK container")
            RESULTS.append({
                "filename": dest.name, "bytes": dest.stat().st_size,
                "sha256": hashlib.sha256(dest.read_bytes()).hexdigest(),
                "source": SOURCES["gamehub"], "saved_path": str(dest),
            })
        except Exception as error:
            # If the website uses a direct CDN URL or opens a new tab, try the intercepted link.
            if not download_urls:
                raise RuntimeError(f"Official Android button did not download an APK: {error}")
            direct = download_urls[-1]
            target = ROOT / "gamehub" / ("GameHub.apk" if ".apk" in direct.lower() else "GameHub.xapk")
            RESULTS.append(transfer(direct, target))
        finally:
            browser.close()


def upload_to_repository():
    repo = os.environ.get("GITHUB_REPOSITORY")
    tag = "requested-downloads-2026-10-23"
    if not repo:
        raise RuntimeError("GITHUB_REPOSITORY missing")
    manifest_path = Path("manifest-external-downloads.json")
    manifest_path.write_text(json.dumps({"sources": SOURCES, "downloaded": RESULTS,
                                        "errors": ERRORS}, indent=2, ensure_ascii=False) + "\n")
    notes = "Original sources supplied by repo owner on 2026-10-23.\n\n"
    notes += "Includes only files actually retrieved; see manifest for SHA-256 checksums.\n"
    notes += "\n".join("- " + item["filename"] for item in RESULTS)
    exists = subprocess.run(["gh", "release", "view", tag, "-R", repo],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    if not exists:
        subprocess.run(["gh", "release", "create", tag, "-R", repo,
                        "--title", "Requested reference downloads (2026-10-23)",
                        "--notes", notes], check=True)
    # GitHub Releases rejects individual assets >= 2 GiB. Split these into
    # numbered pieces; all pieces are uploaded to this repository's release.
    limit = 1_300_000_000
    for info in RESULTS:
        source = Path(info["saved_path"])
        try:
            if info["bytes"] <= limit:
                subprocess.run(["gh", "release", "upload", tag, str(source),
                                "--clobber", "-R", repo], check=True)
                continue
            info["parts"] = []
            with source.open("rb") as stream:
                number = 1
                while True:
                    part = source.with_name(source.name + f".part{number:03d}")
                    part_hash = hashlib.sha256()
                    part_size = 0
                    with part.open("wb") as out:
                        while part_size < limit:
                            chunk = stream.read(min(8 * 1024 * 1024, limit - part_size))
                            if not chunk:
                                break
                            out.write(chunk)
                            part_hash.update(chunk)
                            part_size += len(chunk)
                    if not part_size:
                        part.unlink()
                        break
                    subprocess.run(["gh", "release", "upload", tag, str(part),
                                    "--clobber", "-R", repo], check=True)
                    info["parts"].append({"name": part.name,
                                          "bytes": part_size,
                                          "sha256": part_hash.hexdigest()})
                    part.unlink()
                    print(f"Uploaded part {number} of {source.name} ({part_size} bytes)", flush=True)
                    number += 1
            info["assembly"] = "Concatenate the parts in ascending numeric order to reproduce the original file. Verify the original sha256."
        except Exception as exc:
            ERRORS.append(f"GitHub release upload of {info['filename']}: {exc}")
    manifest_path.write_text(json.dumps({"sources": SOURCES, "downloaded": RESULTS,
                                        "errors": ERRORS}, indent=2, ensure_ascii=False) + "\n")
    subprocess.run(["gh", "release", "upload", tag, str(manifest_path),
                    "--clobber", "-R", repo], check=True)
    if ERRORS:
        print("Unfinished imports:", *ERRORS, sep="\n - ", file=sys.stderr)
    if not RESULTS or ERRORS:
        raise SystemExit(1)


if __name__ == "__main__":
    for name, callback in (("Gofile", gofile), ("GameHub", gamehub)):
        try:
            callback()
        except Exception as exc:
            ERRORS.append(f"{name}: {exc}")
    upload_to_repository()
