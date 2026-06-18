"""
builder/turnt — Serve pre-bundled turnt binaries or cross-compile from source.

Binaries are shipped in fitnah/assets/turnt/ (downloaded from v0.1 release):
  turnt-relay-windows-amd64.exe        (8.4 MB, full)
  turnt-relay-windows-amd64-upx.exe    (2.6 MB, UPX-packed, smaller footprint)
  turnt-relay-windows-386-upx.exe      (2.4 MB, x86)
  turnt-relay-linux-amd64              (8.2 MB)
  turnt-control-linux-amd64            (15 MB, operator-side controller)
  turnt-credentials-linux-amd64        (8.0 MB, credential extractor)
  turnt-admin-linux-amd64              (8.3 MB, port-forward management console)

CLI:
  builder -f turnt-relay --os windows --arch amd64 [--upx]
  builder -f turnt-relay --os linux
  builder -f turnt-relay --go-build --os windows --arch amd64   (compile from source)
  builder -f turnt-relay --list
"""
from __future__ import annotations

import hashlib
import os
import platform
import shutil
import stat
import subprocess
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

# Pre-bundled assets directory (relative to this file)
_ASSETS = Path(__file__).parent.parent / "assets" / "turnt"

# Mapping: (os, arch, upx) → bundled filename
_BUNDLED: dict[tuple[str, str, bool], str] = {
    ("windows", "amd64", False): "turnt-relay-windows-amd64.exe",
    ("windows", "amd64", True):  "turnt-relay-windows-amd64-upx.exe",
    ("windows", "386",  False):  "turnt-relay-windows-386-upx.exe",
    ("windows", "386",  True):   "turnt-relay-windows-386-upx.exe",
    ("linux",   "amd64", False): "turnt-relay-linux-amd64",
    ("linux",   "amd64", True):  "turnt-relay-linux-amd64",
}

# Operator-side tools (only linux bundles shipped — operator usually runs linux)
_OPERATOR_TOOLS: dict[str, str] = {
    "control":     "turnt-control-linux-amd64",
    "credentials": "turnt-credentials-linux-amd64",
    "admin":       "turnt-admin-linux-amd64",
}

TURNT_REPO   = "praetorian-inc/turnt"
TURNT_TAG    = "v0.1"


@dataclass
class TurntBuildRequest:
    arch: str = "amd64"           # amd64 | 386 | arm64
    os_target: str = "windows"    # windows | linux | darwin
    upx: bool = True              # prefer UPX-compressed binary (smaller footprint on agent)
    go_build: bool = False        # compile from source
    go_bin: str = "go"
    garble: bool = False
    output_dir: Path = field(default_factory=lambda: Path("build/turnt"))
    strip: bool = True


@dataclass
class TurntBuildResult:
    ok: bool
    path: Path | None = None
    sha256: str = ""
    size: int = 0
    error: str = ""
    source: str = ""   # "bundled" | "download" | "compile"


class TurntBuilder:
    """
    Serve or build turnt-relay for agent deployment.
    Also provides paths to operator-side tools (turnt-control, turnt-admin, turnt-credentials).
    """

    def __init__(self, output_dir: str | Path = "build/turnt"):
        self._out = Path(output_dir)
        self._out.mkdir(parents=True, exist_ok=True)

    # ── public API ────────────────────────────────────────────────────────────

    def build(self, req: TurntBuildRequest) -> TurntBuildResult:
        """Return relay binary for target platform. Uses bundled → download → compile."""
        req.output_dir = self._out

        if req.go_build:
            return self._compile(req)

        # 1. Bundled
        result = self._serve_bundled(req)
        if result.ok:
            return result

        # 2. GitHub download
        print(f"[turnt] Bundled not found for {req.os_target}/{req.arch}, downloading...")
        result = self._download(req)
        if result.ok:
            return result

        # 3. Compile
        print(f"[turnt] Download failed ({result.error}), compiling from source...")
        return self._compile(req)

    def operator_tool(self, tool: str) -> Path | None:
        """
        Return path to an operator-side tool: control | credentials | admin.
        Returns None if not found in assets.
        """
        fname = _OPERATOR_TOOLS.get(tool)
        if not fname:
            return None
        p = _ASSETS / fname
        if p.exists():
            return p
        return None

    def list_cached(self) -> list[dict]:
        results = []
        for f in self._out.iterdir():
            if f.is_file():
                data = f.read_bytes()
                results.append({
                    "name":   f.name,
                    "size":   len(data),
                    "sha256": hashlib.sha256(data).hexdigest()[:16] + "...",
                    "path":   str(f),
                })
        return results

    def list_bundled(self) -> list[dict]:
        results = []
        if not _ASSETS.exists():
            return results
        for f in _ASSETS.iterdir():
            if f.is_file():
                data = f.read_bytes()
                results.append({
                    "name":   f.name,
                    "size":   len(data),
                    "sha256": hashlib.sha256(data).hexdigest()[:16] + "...",
                    "path":   str(f),
                })
        return results

    # ── bundled ───────────────────────────────────────────────────────────────

    def _serve_bundled(self, req: TurntBuildRequest) -> TurntBuildResult:
        fname = _BUNDLED.get((req.os_target, req.arch, req.upx))
        if not fname:
            # try without upx preference
            fname = _BUNDLED.get((req.os_target, req.arch, False))
        if not fname:
            return TurntBuildResult(ok=False,
                error=f"No bundled binary for {req.os_target}/{req.arch}")

        src = _ASSETS / fname
        if not src.exists():
            return TurntBuildResult(ok=False, error=f"Bundled asset missing: {src}")

        ext = ".exe" if req.os_target == "windows" else ""
        upx_tag = "-upx" if req.upx and "upx" in fname else ""
        out_name = f"turnt-relay-{req.os_target}-{req.arch}{upx_tag}{ext}"
        dst = req.output_dir / out_name
        shutil.copy2(src, dst)
        if req.os_target != "windows":
            dst.chmod(dst.stat().st_mode | stat.S_IEXEC)

        return self._finalise(dst, "bundled")

    # ── download ──────────────────────────────────────────────────────────────

    def _download(self, req: TurntBuildRequest) -> TurntBuildResult:
        try:
            import json
            api = f"https://api.github.com/repos/{TURNT_REPO}/releases/tags/{TURNT_TAG}"
            with urllib.request.urlopen(api, timeout=10) as resp:
                release = json.loads(resp.read())

            zip_name = f"turnt-{req.os_target}.zip"
            asset_url = None
            for asset in release.get("assets", []):
                if asset["name"] == zip_name:
                    asset_url = asset["browser_download_url"]
                    break

            if not asset_url:
                return TurntBuildResult(ok=False,
                    error=f"Asset {zip_name} not in release {TURNT_TAG}")

            with urllib.request.urlopen(asset_url, timeout=60) as resp:
                zip_data = resp.read()

            ext = ".exe" if req.os_target == "windows" else ""
            upx = "-upx" if req.upx else ""
            inner = f"turnt-relay-{req.os_target}-{req.arch}{upx}{ext}"

            with tempfile.TemporaryDirectory() as tmp:
                zp = Path(tmp) / "rel.zip"
                zp.write_bytes(zip_data)
                with zipfile.ZipFile(zp) as zf:
                    names = zf.namelist()
                    # find best match
                    target = inner if inner in names else next(
                        (n for n in names if "relay" in n and req.arch in n), None)
                    if not target:
                        return TurntBuildResult(ok=False,
                            error=f"relay binary not found in zip. Contents: {names}")
                    zf.extract(target, tmp)
                    src = Path(tmp) / target
                    out_name = f"turnt-relay-{req.os_target}-{req.arch}{upx}{ext}"
                    dst = req.output_dir / out_name
                    shutil.copy2(src, dst)

            if req.os_target != "windows":
                dst.chmod(dst.stat().st_mode | stat.S_IEXEC)

            return self._finalise(dst, "download")

        except Exception as ex:
            return TurntBuildResult(ok=False, error=str(ex))

    # ── compile ───────────────────────────────────────────────────────────────

    def _compile(self, req: TurntBuildRequest) -> TurntBuildResult:
        go_cmd = shutil.which(req.go_bin) or shutil.which("go")
        if not go_cmd:
            return TurntBuildResult(ok=False,
                error="Go toolchain not found. Install Go ≥1.21 or use --go-bin.")
        try:
            with tempfile.TemporaryDirectory() as tmp:
                src_dir = Path(tmp) / "turnt"
                subprocess.run(
                    ["git", "clone", "--depth=1",
                     f"https://github.com/{TURNT_REPO}.git", str(src_dir)],
                    check=True, capture_output=True,
                )
                ext = ".exe" if req.os_target == "windows" else ""
                out_name = f"turnt-relay-{req.os_target}-{req.arch}-compiled{ext}"
                dst = req.output_dir / out_name

                env = os.environ.copy()
                env["GOOS"]        = req.os_target
                env["GOARCH"]      = req.arch
                env["CGO_ENABLED"] = "0"
                ldflags = "-s -w" if req.strip else ""

                relay_pkg = next(
                    (str(p) for p in [
                        src_dir / "cmd" / "turnt-relay",
                        src_dir / "turnt-relay",
                        src_dir,
                    ] if p.is_dir()), "./cmd/turnt-relay"
                )

                cmd = ["garble", "-tiny", "build", "-o", str(dst), relay_pkg] \
                    if (req.garble and shutil.which("garble")) \
                    else [go_cmd, "build", f"-ldflags={ldflags}", "-o", str(dst), relay_pkg]

                r = subprocess.run(cmd, cwd=str(src_dir), env=env,
                                   capture_output=True, text=True)
                if r.returncode != 0:
                    return TurntBuildResult(ok=False,
                        error=f"go build failed:\n{r.stderr}")
                if not dst.exists():
                    return TurntBuildResult(ok=False,
                        error=f"Build ok but output missing: {dst}")
                return self._finalise(dst, "compile")
        except Exception as ex:
            return TurntBuildResult(ok=False, error=str(ex))

    @staticmethod
    def _finalise(path: Path, source: str) -> TurntBuildResult:
        data = path.read_bytes()
        return TurntBuildResult(
            ok=True, path=path,
            sha256=hashlib.sha256(data).hexdigest(),
            size=len(data), source=source,
        )
