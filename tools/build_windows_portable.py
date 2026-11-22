"""Build WiFiScope for Windows x64 from pinned CPython and Tcl/Tk files."""

import argparse
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

PYTHON_VERSION = "3.14.10"
PYTHON_COMMIT = "b703b2c5e704341d61e367b9b940b77ed11dded0"
PYTHON_ZIP = "python-3.14.10-embed-amd64.zip"
PYTHON_SBOM = PYTHON_ZIP + ".spdx.json"
TCLTK_MSI = "tcltk.msi"
CPYTHON = "https://github.com/python/cpython"
TCLTK_SOURCE = "https://github.com/python/cpython-source-deps"
TCLTK_BINARY = "https://github.com/python/cpython-bin-deps"
PYTHON_FTP = "https://www.python.org/ftp/python/3.14.10"
TCL_SOURCE_COMMITS = {
    "tcl-license.terms": "53c758cbf2cc178b359abc03fdd912c5e66ed74f",
    "tk-license.terms": "a6a5bee1ef4b526b0d11200c84bc02e85d8ecc83",
}
ASSET_SHA256 = {
    PYTHON_ZIP: "90905e64a840557d8c1bc4f5b74db3d7ee85e3ffb217611cac1c7813acea4159",
    PYTHON_SBOM: "d448c78f5fae170303d3b022d61507155e4d30e541c32bff3a4edd2b1e8dbf47",
    TCLTK_MSI: "9642593510b188aa35dcdf1995cbe2b3c3c07446a0ac1dd0c1d1958bf25526f5",
    "tcl-license.terms": "c0a69a2bfd757361ec7e6143973b103c90409316b49e9c88db26ad6388e79f16",
    "tk-license.terms": "2cde822b93ca16ae535c954b7dfe658b4ad10df2a193628d1b358f1765e8b198",
    "cpython-license.rst": "8a7329b25131f64b2bea284155f0824876b1af9f4a2f970e6335751d97dfa6dd",
    "tcl-zlib-license.txt": "e32ff4e00d9d94930537635291da39e7e612703334bf6fde8c7f1686fe8a45a2",
    "tcl-libtommath-license.txt": "2fa64b163659f41965c9815882a8296d3d03ff546b76153e11445f9bdecf955a",
}
ASSET_URLS = {
    PYTHON_ZIP: f"{PYTHON_FTP}/{PYTHON_ZIP}",
    PYTHON_SBOM: f"{PYTHON_FTP}/{PYTHON_SBOM}",
    TCLTK_MSI: f"{PYTHON_FTP}/amd64/{TCLTK_MSI}",
    **{
        name: f"https://raw.githubusercontent.com/python/cpython-source-deps/{commit}/license.terms"
        for name, commit in TCL_SOURCE_COMMITS.items()
    },
    "cpython-license.rst": f"https://raw.githubusercontent.com/python/cpython/{PYTHON_COMMIT}/Doc/license.rst",
    "tcl-zlib-license.txt": (
        f"https://raw.githubusercontent.com/python/cpython-source-deps/{TCL_SOURCE_COMMITS['tcl-license.terms']}"
        "/compat/zlib/LICENSE"
    ),
    "tcl-libtommath-license.txt": (
        f"https://raw.githubusercontent.com/python/cpython-source-deps/{TCL_SOURCE_COMMITS['tcl-license.terms']}"
        "/libtommath/LICENSE"
    ),
}
SOURCE_FILES = ("wifiscope", "README.md", "README.en.md", "LICENSE", "CHANGELOG.md", "SECURITY.md", "docs")
LAUNCHER = r"""@echo off
setlocal DisableDelayedExpansion
set "TCL_LIBRARY="
set "TK_LIBRARY="
set "TCLLIBPATH="
if not "%~1"=="" goto cli
start "WiFiScope" "%~dp0runtime\pythonw.exe" -B -m wifiscope
exit /b %errorlevel%
:cli
"%~dp0runtime\python.exe" -B -m wifiscope %*
exit /b %errorlevel%
"""
TK_PROBE = """
import pathlib
import sys
import tkinter
from wifiscope.gui import Workstation

expected_runtime = pathlib.Path(sys.argv[1]).resolve()
if sys.version_info[:3] != (3, 14, 10):
    raise RuntimeError('Unexpected interpreter version')
if pathlib.Path(sys.executable).resolve().parent != expected_runtime:
    raise RuntimeError('Unexpected interpreter')
if not pathlib.Path(tkinter.__file__).resolve().is_relative_to(expected_runtime):
    raise RuntimeError('Tkinter loaded outside the runtime')
root = tkinter.Tk()
root.withdraw()
app = Workstation(root)
app.open_network_workbench()
app.network_workbench.window.withdraw()
root.update_idletasks()
print(root.tk.call('info', 'patchlevel'), root.tk.call('package', 'provide', 'Tk'))
app.close()
"""


def verified_assets(cache):
    assets = {}
    for name, expected in ASSET_SHA256.items():
        path = cache / name
        if not path.is_file():
            raise FileNotFoundError(f"Missing approved build input: {name}")
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != expected:
            raise ValueError(f"SHA-256 mismatch: {name}")
        assets[name] = path
    return assets


def extract_checked(archive, target):
    for item in archive.infolist():
        name = PurePosixPath(item.filename)
        if (
            name.is_absolute()
            or not name.parts
            or any(
                part == ".." or part.endswith((".", " ")) or any(char in ':<>"|?*' for char in part)
                for part in name.parts
            )
            or "\\" in item.orig_filename
            or stat.S_ISLNK(item.external_attr >> 16)
        ):
            raise ValueError(f"Unsafe archive member: {item.filename}")
        path = target.joinpath(*name.parts)
        if item.is_dir():
            path.mkdir(parents=True, exist_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(item) as source, path.open("xb") as output:
                shutil.copyfileobj(source, output)


def write_archive(stage, output):
    stream = output.open("xb")
    try:
        with stream, ZipFile(stream, "w", compression=ZIP_DEFLATED) as archive:
            for path in sorted(stage.rglob("*")):
                if path.is_file():
                    item = ZipInfo(path.relative_to(stage).as_posix())
                    item.external_attr = 0o100644 << 16
                    archive.writestr(item, path.read_bytes(), compress_type=ZIP_DEFLATED, compresslevel=6)
    except BaseException:
        output.unlink()
        raise


def stage_app(repo, revision, destination):
    commit = subprocess.check_output(
        ["git", "rev-parse", "--verify", "--end-of-options", revision + "^{commit}"],
        cwd=repo,
        text=True,
        timeout=30,
    ).strip()
    source = subprocess.check_output(
        ["git", "archive", "--format=zip", commit, "--", *SOURCE_FILES], cwd=repo, timeout=30,
    )
    with ZipFile(io.BytesIO(source)) as archive:
        extract_checked(archive, destination)
    return commit


def stage_runtime(assets, scratch, runtime):
    with ZipFile(assets[PYTHON_ZIP]) as archive:
        extract_checked(archive, runtime)
    tk = scratch / "tcltk"
    msiexec = Path(os.environ["WINDIR"]) / "System32" / "msiexec.exe"
    command = subprocess.list2cmdline([str(msiexec), "/a", str(assets[TCLTK_MSI]), "/quiet", "/norestart"])
    subprocess.run(
        f'{command} TARGETDIR="{tk}"',
        cwd=scratch,
        check=True,
        timeout=60,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    shutil.copytree(tk / "DLLs", runtime / "DLLs")
    shutil.copytree(tk / "Lib" / "tkinter", runtime / "Lib" / "tkinter")
    shutil.copytree(
        tk / "tcl",
        runtime / "tcl",
        ignore=shutil.ignore_patterns("*.lib", "*.sh", "demos", "nmake"),
    )
    (runtime / "python314._pth").write_text(
        "python314.zip\n.\nDLLs\nLib\n../app\n", encoding="ascii", newline="\r\n",
    )


def write_provenance(assets, stage, commit):
    notices = stage / "licenses"
    notices.mkdir()
    for name, asset in assets.items():
        if name not in (PYTHON_ZIP, TCLTK_MSI):
            shutil.copyfile(asset, notices / name)
    shutil.copyfile(stage / "runtime" / "LICENSE.txt", notices / "CPython-LICENSE.txt")
    provenance = {
        "wifiscope_commit": commit,
        "architecture": "Windows x64",
        "runtime_staged_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "cpython": {
            "version": PYTHON_VERSION,
            "repository": CPYTHON,
            "commit": PYTHON_COMMIT,
            "license": "PSF-2.0 and third-party notices in licenses",
        },
        "tcl_tk": {
            "version": "9.0.4",
            "binary_repository": TCLTK_BINARY,
            "binary_commit": "907f3f4de820cb74fc8fb4431a39beae4c690915",
            "source_repository": TCLTK_SOURCE,
            "source_commits_by_notice": TCL_SOURCE_COMMITS,
            "license": "TCL license in licenses/tcl-license.terms and licenses/tk-license.terms",
        },
        "inputs": {
            name: {"url": ASSET_URLS[name], "sha256": digest} for name, digest in ASSET_SHA256.items()
        },
    }
    (stage / "build-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")


def verify_stage(stage, scratch):
    env = {
        key: value for key, value in os.environ.items()
        if not key.upper().startswith("PYTHON") and key.upper() not in {"TCL_LIBRARY", "TK_LIBRARY", "TCLLIBPATH"}
    }
    system = Path(env["WINDIR"]) / "System32"
    env["PATH"] = str(system)
    invocation = [str(system / "cmd.exe"), "/d", "/c", "WiFiScope.cmd"]
    options = {"timeout": 45, "env": env, "cwd": stage, "creationflags": subprocess.CREATE_NO_WINDOW}
    help_result = subprocess.run(
        [*invocation, "network", "map", "--help"], check=True, capture_output=True, **options,
    )
    report = scratch / "synthetic-report"
    subprocess.run([*invocation, "demo", "--out", str(report)], check=True, stdout=subprocess.DEVNULL, **options)
    if not (report / "report.html").is_file():
        raise RuntimeError("The synthetic demo did not export an HTML report")
    if b"--zeek" in help_result.stdout:
        specimen = scratch / "conn.log"
        specimen.write_text(json.dumps({
            "ts": 1700000000.0, "id.orig_h": "192.0.2.1", "id.orig_p": 48123,
            "id.resp_h": "192.0.2.2", "id.resp_p": 8080, "proto": "tcp", "service": "http",
            "orig_bytes": 91, "resp_bytes": 380, "missed_bytes": 0,
        }) + "\n", encoding="ascii")
        mapped = subprocess.run(
            [*invocation, "network", "map", "--zeek", str(specimen)], check=True, capture_output=True, **options,
        )
        graph = json.loads(mapped.stdout)
        if graph["edges"][0]["kind"] != "zeek-flow" or graph["edges"][0]["resp_bytes"] != 380:
            raise RuntimeError("The bundled runtime did not import the synthetic Zeek flow")
        print("Zeek CLI smoke passed")
    runtime = stage / "runtime"
    gui = subprocess.run(
        [str(runtime / "python.exe"), "-B", "-c", TK_PROBE, str(runtime)], check=True, capture_output=True, **options,
    )
    print(f"Tcl and Tk smoke passed: {gui.stdout.decode('ascii').strip()}")


def build(cache, output, revision):
    if os.name != "nt":
        raise ValueError("Building a Windows portable bundle requires Windows.")
    if output.suffix.lower() != ".zip":
        raise ValueError("The output filename must end in .zip.")
    if output.exists():
        raise FileExistsError(output)
    cache = cache.resolve(strict=True)
    repo = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="WiFiScope portable ") as folder:
        scratch = Path(folder)
        stage = scratch / "bundle"
        inputs = scratch / "inputs"
        inputs.mkdir()
        for name in ASSET_SHA256:
            shutil.copyfile(cache / name, inputs / name)
        assets = verified_assets(inputs)
        commit = stage_app(repo, revision, stage / "app")
        stage_runtime(assets, scratch, stage / "runtime")
        write_provenance(assets, stage, commit)
        (stage / "WiFiScope.cmd").write_text(LAUNCHER, encoding="ascii", newline="\r\n")
        verify_stage(stage, scratch)
        write_archive(stage, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, help="Directory of approved runtime files")
    parser.add_argument("--output", type=Path, help="New output ZIP")
    parser.add_argument("--revision", default="HEAD", help="Git commit or ref")
    parser.add_argument("--list-assets", action="store_true", help="Print asset URLs and SHA-256 pins")
    args = parser.parse_args()
    if args.list_assets:
        for name, url in ASSET_URLS.items():
            print(f"{name} {ASSET_SHA256[name]} {url}")
        return
    if args.assets is None or args.output is None:
        parser.error("--assets and --output are required")
    try:
        build(args.assets, args.output, args.revision)
    except (OSError, ValueError, subprocess.SubprocessError, RuntimeError) as error:
        parser.exit(1, f"Portable build failed: {error}\n")
    print(f"Verified portable bundle: {args.output}")


if __name__ == "__main__":
    main()
