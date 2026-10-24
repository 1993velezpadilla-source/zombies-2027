# zombies-2027 — external reference files

Two downloads requested by the repository owner on 2026-10-23:

- Gofile public share: https://gofile.io/d/BB8eY1
- GameHub official Android site: https://gamehub.xiaoji.com/en/

The import script `tools/import_requested_downloads.py` uses the public Gofile guest API and the official GameHub Android download button. The workflow is `.github/workflows/import-requested-downloads.yml`. Successfully retrieved packages are published as **GitHub Release assets** because APK/ZIP files can exceed GitHub's ordinary 100 MB Git limit. Each release includes `manifest-external-downloads.json` with the source, file size, SHA-256, and any errors.

**Files are not considered imported until the GitHub Actions workflow succeeds and the release assets appear.** Do not treat a link to a source web page as equivalent to an APK/ZIP upload. Externally sourced Android installers are reference binaries, not part of the Godot game source tree. Respect their distribution licenses.

For archives larger than 2 GiB, the Release contains numbered pieces (`filename.rar.part001`, `filename.rar.part002`, ...). Download **all** parts and concatenate in ascending order to reconstruct the original archive. On Linux, macOS, or Termux on Android: `cat filename.rar.part* > filename.rar`. Compare the rebuilt file's SHA-256 with the Release manifest before extraction.
