#!/usr/bin/env python3
"""Non-executing, read-only forensic inventory of the two imported references.
Creates a Markdown report and JSON inventory; never installs or runs an APK/EXE.
"""
from __future__ import annotations
import collections
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from urllib.parse import urlparse
import requests

REPO=os.environ.get("GITHUB_REPOSITORY", "1993velezpadilla-source/zombies-2027")
TAG="requested-downloads-2026-10-23"
OUT=Path("audits")
OUT.mkdir(exist_ok=True)
TEMP=Path("/tmp/zombies-archive-audit")
TEMP.mkdir(exist_ok=True)
SESSION=requests.Session()
SESSION.headers["Accept"]="application/vnd.github+json"
if os.environ.get("GH_TOKEN"):
    SESSION.headers["Authorization"]="Bearer "+os.environ["GH_TOKEN"]
ERRORS=[]
WARNINGS=[]

def run(cmd, timeout=240):
    r=subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout,errors="replace")
    return r.returncode,r.stdout

def sha_file(path):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for chunk in iter(lambda:f.read(4*1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

def get_release():
    url=f"https://api.github.com/repos/{REPO}/releases/tags/{TAG}"
    r=SESSION.get(url,timeout=60)
    r.raise_for_status()
    return r.json()

def download_part(asset,out,hasher=None):
    """Streaming binary transfer: verifies each GitHub-stored asset by SHA256."""
    url=asset["browser_download_url"]
    headers={"Accept":"application/octet-stream"}
    h=hashlib.sha256()
    size=0
    with SESSION.get(url,headers=headers,stream=True,timeout=(40,180)) as r:
        r.raise_for_status()
        with open(out,"ab") as f:
            for block in r.iter_content(4*1024*1024):
                if not block: continue
                f.write(block)
                size+=len(block)
                h.update(block)
                if hasher is not None:
                    hasher.update(block)
    expected=asset.get("digest","")
    got="sha256:"+h.hexdigest()
    if size != asset["size"]:
        ERRORS.append(f"{asset['name']}: byte count mismatch {size} != {asset['size']}")
    if expected and expected != got:
        ERRORS.append(f"{asset['name']}: SHA256 mismatch {got} != {expected}")
    print(f"VERIFIED_ASSET name={asset['name']} bytes={size} sha256={h.hexdigest()}",flush=True)
    return {"name":asset["name"],"bytes":size,"sha256":h.hexdigest(),"match":expected==got if expected else None}

def android_tools():
    root=Path(os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or "/usr/local/lib/android/sdk")
    candidates=sorted((root/"build-tools").glob("*"),reverse=True)
    res={}
    for name in ("aapt","apksigner"):
        res[name]=next((str(p/name) for p in candidates if (p/name).is_file()),shutil.which(name))
    return res

def audit_apk(path):
    info={"filename":path.name,"bytes":path.stat().st_size,"sha256":sha_file(path),"kind":"Android APK"}
    with zipfile.ZipFile(path) as z:
        members=z.infolist()
        info["zip_entries"]=len(members)
        info["uncompressed_bytes"]=sum(x.file_size for x in members)
        info["compression_ratio"]=round(info["uncompressed_bytes"]/max(1,path.stat().st_size),2)
        info["dex_files"]=[x.filename for x in members if re.fullmatch(r"classes\d*\.dex",x.filename)][:32]
        info["native_abis"]=sorted(set(x.filename.split("/")[1] for x in members if x.filename.startswith("lib/") and x.filename.count("/")>=2))
        info["native_libraries"]=len([x for x in members if x.filename.endswith(".so")])
        info["permissions_from_manifest"]=[]
        info["manifest_exists"]="AndroidManifest.xml" in z.namelist()
        info["strange_archive_paths"]=[x.filename for x in members if x.filename.startswith(("/","\\")) or ".." in x.filename.split("/")][:30]
        failed=z.testzip()
        info["zip_crc"] = "PASS" if failed is None else "FAIL: "+failed
    tools=android_tools()
    info["android_tool_paths"]=tools
    if tools["aapt"]:
        for mode,cmd in [("badging",[tools["aapt"],"dump","badging",str(path)]),("permissions",[tools["aapt"],"dump","permissions",str(path)])]:
            rc,out=run(cmd,90)
            info["aapt_"+mode+"_status"]=rc
            info["aapt_"+mode+"_output"]=out[:50000]
        badging=info.get("aapt_badging_output","")
        m=re.search(r"package: name='([^']+)' versionCode='([^']*)' versionName='([^']*)'",badging)
        if m:
            info["package_id"],info["version_code"],info["version_name"]=m.groups()
        m=re.search(r"sdkVersion:'([^']+)'",badging)
        if m: info["min_sdk"]=m.group(1)
        m=re.search(r"targetSdkVersion:'([^']+)'",badging)
        if m: info["target_sdk"]=m.group(1)
        perms=info.get("aapt_permissions_output","")
        info["permissions_from_manifest"]=sorted(set(re.findall(r"(?:uses-permission|permission): name='([^']+)'",perms)))
    if tools["apksigner"]:
        rc,out=run([tools["apksigner"],"verify","--verbose","--print-certs",str(path)],120)
        info["apksigner_status"]="PASS" if rc==0 else "FAIL"
        info["apksigner_output"]=out[:25000]
        info["signer_SHA256"]=re.findall(r"Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]+)",out)
    risky={
       "android.permission.SEND_SMS","android.permission.READ_SMS",
       "android.permission.RECEIVE_SMS","android.permission.READ_CONTACTS",
       "android.permission.WRITE_CONTACTS","android.permission.ACCESS_FINE_LOCATION",
       "android.permission.ACCESS_BACKGROUND_LOCATION","android.permission.RECORD_AUDIO",
       "android.permission.CAMERA","android.permission.REQUEST_INSTALL_PACKAGES",
       "android.permission.QUERY_ALL_PACKAGES","android.permission.MANAGE_EXTERNAL_STORAGE",
       "android.permission.READ_PHONE_STATE","android.permission.SYSTEM_ALERT_WINDOW",
       "android.permission.BIND_ACCESSIBILITY_SERVICE"
    }
    info["permissions_requiring_review"]=sorted(set(info["permissions_from_manifest"]) & risky)
    return info

def audit_rar(path):
    info={"filename":path.name,"bytes":path.stat().st_size,"sha256":sha_file(path),
          "kind":"RAR archive","inventory":[]}
    with path.open("rb") as f: info["header_hex"]=f.read(16).hex()
    info["rar_magic_valid"]=info["header_hex"].startswith("526172211a07")
    seven=shutil.which("7z") or shutil.which("7zz") or shutil.which("7za")
    if not seven:
        WARNINGS.append("7-Zip listing unavailable: package missing; RAR contents not inspected")
        info["listing_status"]="NOT_RUN"
        return info
    rc,text=run([seven,"l","-slt",str(path)],720)
    info["listing_exit_code"]=rc
    info["listing_status"]="PASS" if rc==0 else "FAIL"
    info["listing_log_tail"]=text[-2800:]
    Path(OUT/"rar-7zip-raw-listing.txt").write_text(text,encoding="utf-8")
    rows=[]
    if "----------" in text:
        details=text.split("----------",1)[1]
        for block in re.split(r"\n\s*\n", details):
            vals={}
            for line in block.splitlines():
                if " = " in line:
                    k,v=line.split(" = ",1)
                    vals[k.strip()]=v.strip()
            if "Path" in vals:
                rows.append(vals)
    for vals in rows:
        name=vals["Path"]
        s=int(vals.get("Size","0")) if vals.get("Size","0").isdigit() else 0
        is_dir=vals.get("Folder","-")=="+" or vals.get("Attributes","").startswith("D")
        info["inventory"].append({"path":name,"size":s,"is_directory":is_dir,
                                  "encrypted":vals.get("Encrypted","?")})
    files=[x for x in info["inventory"] if not x["is_directory"]]
    info["file_count"]=len(files)
    info["folder_count"]=len(info["inventory"])-len(files)
    info["uncompressed_file_bytes"]=sum(x["size"] for x in files)
    info["extensions"]=dict(collections.Counter((Path(x["path"]).suffix.lower() or "(no extension)") for x in files).most_common())
    info["top_level_paths"]=dict(collections.Counter(re.split(r"[/\\]",x["path"])[0] for x in files).most_common(30))
    info["largest_files"]=sorted(files,key=lambda x:x["size"],reverse=True)[:60]
    info["executables_and_scripts"]= [x for x in files if Path(x["path"]).suffix.lower() in
      {".exe",".dll",".sys",".scr",".com",".bat",".cmd",".ps1",".vbs",".js",".jar",".apk",".sh",".msi"}][:180]
    info["potential_path_traversal"]=[x["path"] for x in files if (x["path"].startswith(("/","\\"))
        or re.match(r"^[A-Za-z]:",x["path"]) or ".." in re.split(r"[/\\]",x["path"]))][:60]
    info["encryption_detected"]=any(x["encrypted"]=="+" for x in info["inventory"])
    if rc != 0:
        WARNINGS.append("7-Zip could not fully list archive, check listing log; encrypted or malformed archive is possible")
    return info

def section(title):
    return "\n## "+title+"\n"

def bullets(items):
    return "".join(f"- {a}\n" for a in items) or "- None\n"

def safe(value):
    return str(value).replace("|","\\|").replace("\n"," ")

def make_report(release,manifest,part_checks,apk,rar):
    timestamp=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    assets=release["assets"]
    text=f"# Auditoría de archivos descargados — zombies-2027\n\n**Fecha del análisis:** {timestamp}  \n**Repositorio:** \`{REPO}\`  \n**Release:** \`{TAG}\`  \n**Alcance:** análisis estático, comprobaciones de integridad y listado de archivos; nada se ejecutó ni instaló.\n"
    text+=section("Inventario externo verificado")
    text+="| Nombre del archivo | Tamaño (bytes) | SHA-256 en GitHub | Estado |\n|---|---:|---|---|\n"
    found={p["name"]:p for p in part_checks}
    for a in assets:
        chk=found.get(a["name"])
        status="✅ Hash y tamaño comprobados" if chk and chk.get("match") and chk["bytes"]==a["size"] else ("⚠️ Sin revisión binaria" if a["name"]=="manifest-external-downloads.json" else "❌ No confirmado")
        text+=f"| \`{safe(a['name'])}\` | {a['size']:,} | \`{a.get('digest','not published')}\` | {status} |\n"
    text+=section("RAR — Gofile")
    text+=bullets([
       f"Archivo original reconstruido: \`{rar.get('filename','N/D')}\`.",
       f"Tamaño: **{rar.get('bytes',0):,} bytes** ({rar.get('bytes',0)/1e9:.3f} GB).",
       f"SHA-256 original obtenido: \`{rar.get('sha256','N/D')}\`.",
       f"SHA-256 coincide con manifiesto original: **{'SÍ ✅' if rar.get('manifest_sha_match') else 'NO / NO CONFIRMADO ❌'}**.",
       f"Cabecera RAR válida: **{'Sí' if rar.get('rar_magic_valid') else 'No'}**.",
       f"Listado 7-Zip: **{rar.get('listing_status','no ejecutado')}**; archivos: **{rar.get('file_count','?')}**, carpetas: **{rar.get('folder_count','?')}**.",
       f"Datos descomprimidos anunciados: **{rar.get('uncompressed_file_bytes',0):,} bytes**.",
       f"Contenido cifrado detectado: **{rar.get('encryption_detected','no comprobado')}**.",
       f"Rutas peligrosas (../, absolutas): **{len(rar.get('potential_path_traversal',[]))}**.",
       "No se extrajo ni ejecutó contenido. El listado no equivale a una prueba completa CRC de cada archivo interno."
    ])
    text+="\n**Carpetas de primer nivel más frecuentes:**\n\n"
    text+=bullets([f"\`{safe(k)}\`: {n} archivos" for k,n in list(rar.get("top_level_paths",{}).items())[:20]])
    text+="\n**Extensiones predominantes:**\n\n"
    text+=bullets([f"\`{safe(k)}\`: {n}" for k,n in list(rar.get("extensions",{}).items())[:30]])
    text+="\n**Archivos de mayor tamaño (top 30):**\n\n"
    text+=bullets([f"\`{safe(x['path'])}\` — {x['size']:,} bytes" for x in rar.get("largest_files",[])[:30]])
    text+="\n**Ejecutables y scripts (muestra hasta 70):**\n\n"
    text+=bullets([f"\`{safe(x['path'])}\`" for x in rar.get("executables_and_scripts",[])[:70]])
    text+=section("APK — GameHub")
    text+=bullets([
       f"Archivo: \`{apk.get('filename','N/D')}\`.",
       f"Tamaño: **{apk.get('bytes',0):,} bytes**.",
       f"SHA-256: \`{apk.get('sha256','N/D')}\`.",
       f"Integridad ZIP CRC de entradas: **{apk.get('zip_crc','N/D')}**.",
       f"Verificación criptográfica de firma APK: **{apk.get('apksigner_status','herramienta no disponible')}**.",
       f"ID de paquete: \`{apk.get('package_id','no recuperado')}\`; versión: **{apk.get('version_name','no recuperada')}** (versionCode {apk.get('version_code','?')}).",
       f"Android mínimo SDK: **{apk.get('min_sdk','?')}**; target SDK: **{apk.get('target_sdk','?')}**.",
       f"Entradas ZIP: **{apk.get('zip_entries','?')}**; DEX: **{', '.join(apk.get('dex_files',[])) or 'ninguno detectado'}**.",
       f"ABIs nativas: **{', '.join(apk.get('native_abis',[])) or 'no detectadas'}**; bibliotecas .so: **{apk.get('native_libraries','?')}**.",
       f"Huella(s) SHA-256 del certificado firmante: **{', '.join(apk.get('signer_SHA256',[])) or 'no disponible'}**."
    ])
    text+="\n**Permisos declarados en AndroidManifest.xml:**\n\n"
    text+=bullets([f"\`{x}\`{' ⚠️ Revisar uso' if x in apk.get('permissions_requiring_review',[]) else ''}"
                 for x in apk.get("permissions_from_manifest",[])])
    text+=section("Conclusión técnica y límites")
    text+=bullets([
       "La coincidencia SHA-256 acredita consistencia respecto al manifiesto y Release, **no** demuestra que los binarios originales sean seguros.",
       "Firma válida de APK significa que el paquete no ha sido alterado respecto a quien lo firmó; **no** confirma que el firmante sea el editor legítimo sin una huella oficial independiente.",
       "No se realizó análisis dinámico, análisis de malware por firmas ni auditoría de código fuente.",
       "Nunca instalar ni ejecutar los ejecutables del RAR o el APK sin confirmar procedencia, permisos y condiciones de distribución.",
       "El repositorio es público: antes de redistribuir archivos de juegos o instaladores de terceros, revisar derechos de autor/licencias.",
       "Metadatos de inventario completo en \`audits/rar-inventory.json\` y \`audits/apk-analysis.json\`."
    ])
    text+="\n**Incidencias y advertencias:**\n\n"
    text+=bullets(["❌ "+x for x in ERRORS]+["⚠️ "+x for x in WARNINGS])
    return text

def main():
    print("DISK_SPACE_START",shutil.disk_usage("/"),flush=True)
    release=get_release()
    assets=release["assets"]
    by_name={a["name"]:a for a in assets}
    rar_parts=sorted([a for a in assets if re.search(r"\.rar\.part\d{3}$",a["name"])],key=lambda a:int(a["name"].rsplit("part",1)[1]))
    apks=[a for a in assets if a["name"].lower().endswith(".apk")]
    if not rar_parts or not apks: raise RuntimeError("Missing expected RAR part(s) or APK asset(s)")
    indexes=[int(x["name"].rsplit("part",1)[1]) for x in rar_parts]
    if indexes!=list(range(1,len(indexes)+1)):
        ERRORS.append(f"Missing archive part indices: actual {indexes}")
    manifest={}
    if "manifest-external-downloads.json" in by_name:
        mp=TEMP/"manifest-external-downloads.json"
        download_part(by_name["manifest-external-downloads.json"],mp)
        manifest=json.loads(mp.read_text())
    original=next((x for x in manifest.get("downloaded",[]) if x.get("filename","").lower().endswith(".rar")),None)
    rar_path=TEMP/rar_parts[0]["name"].rsplit(".part",1)[0]
    needed=sum(x["size"] for x in rar_parts)
    free=shutil.disk_usage(TEMP).free
    print(f"SPACE_CHECK free={free} required={needed+1024**3}",flush=True)
    if free < needed + 1024**3:
        raise RuntimeError(f"Insufficient runner disk for reconstructing {needed}B RAR (free {free}B); release unchanged")
    checks=[]
    for apkasset in apks:
        target=TEMP/apkasset["name"]
        checks.append(download_part(apkasset,target))
        apk=audit_apk(target)
        if apk["sha256"]!=apkasset["digest"].removeprefix("sha256:"):
            ERRORS.append("APK SHA-256 mismatch with Release digest")
        (OUT/"apk-analysis.json").write_text(json.dumps(apk,indent=2,ensure_ascii=False)+"\n")
        target.unlink()
    whole=hashlib.sha256()
    for asset in rar_parts:
        checks.append(download_part(asset,rar_path,whole))
    rar=audit_rar(rar_path)
    rar["parts"]=len(rar_parts)
    rar["part_verification"]=checks
    rar["manifest_original"] = original
    rar["manifest_sha_match"]=bool(original and rar["sha256"]==original.get("sha256"))
    rar["manifest_size_match"]=bool(original and rar["bytes"]==original.get("bytes"))
    if not rar["manifest_sha_match"]: ERRORS.append("Rebuilt RAR SHA256 differs from original transfer manifest")
    if not rar["manifest_size_match"]: ERRORS.append("Rebuilt RAR size differs from transfer manifest")
    if rar["sha256"]!=whole.hexdigest(): ERRORS.append("Streaming SHA256 differs from reconstructed-file SHA256")
    (OUT/"rar-inventory.json").write_text(json.dumps({**rar,"inventory":rar.pop("inventory")},indent=2,ensure_ascii=False)+"\n")
    report=make_report(release,manifest,checks,apk,rar)
    (OUT/"download-audit-2026-10-24.md").write_text(report,encoding="utf-8")
    print("REPORT_PATH audits/download-audit-2026-10-24.md",flush=True)
    print("REPORT_START\n"+report[:12000]+"\nREPORT_END",flush=True)
    if ERRORS: raise SystemExit(2)

if __name__=="__main__":main()
