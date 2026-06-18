"""collection/dir_list — directory listing with ACLs, hidden files, owner, size summary. MITRE T1083"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class DirList(BasePlugin):
    NAME        = "dir_list"
    DESCRIPTION = "List dir with hidden/system files, ACLs, owner, extension filter, size summary."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1083"
    CATEGORY    = "collection"
    schema      = ParamSchema().add(
        Param("path",       str,  required=False, default=".",    help="Directory to list"),
        Param("recurse",    bool, required=False, default=False,  help="Recurse into subdirectories"),
        Param("hidden",     bool, required=False, default=False,  help="Include hidden+system files"),
        Param("filter",     str,  required=False, default="*",    help="Filename filter e.g. *.txt"),
        Param("show_acl",   bool, required=False, default=False,  help="Show ACL for each item"),
        Param("limit",      int,  required=False, default=200,    help="Max items to show"),
    )

    @mitre("T1083")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        path     = params.get("path", ".")
        recurse  = params.get("recurse", False)
        hidden   = params.get("hidden", False)
        flt      = params.get("filter", "*")
        show_acl = params.get("show_acl", False)
        limit    = params.get("limit", 200)

        flags = "-Recurse" if recurse else ""
        hidden_flag = "-Force" if hidden else ""

        acl_block = (
            "$_ | ForEach-Object {"
            "  $acl = Get-Acl $_.FullName -EA SilentlyContinue;"
            "  $owner = $acl.Owner;"
            "  $access = ($acl.Access | Select-Object -First 2 | % { \"$($_.IdentityReference):$($_.FileSystemRights)\" }) -join '; ';"
            "  \"  ACL Owner=$owner  Access=$access\""
            "};"
        ) if show_acl else ""

        ps = (
            f"$items = Get-ChildItem '{path}' -Filter '{flt}' {flags} {hidden_flag} -EA SilentlyContinue"
            f" | Select-Object -First {limit};"
            "$totalSize = ($items | Where-Object { -not $_.PSIsContainer } | Measure-Object Length -Sum).Sum;"
            "$totalSize = if ($totalSize) { [Math]::Round($totalSize/1MB,2) } else { 0 };"
            f"\"Path: {path}  Items: $($items.Count)  TotalSize: $($totalSize) MB\";"
            "\"\";"
            "$items | ForEach-Object {"
            "  $owner = try { (Get-Acl $_.FullName -EA Stop).Owner } catch { '?' };"
            "  \"{0,-5} {1,-22} {2,12} {3,-30} Owner:{4}\" -f"
            "    $_.Mode, ($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm')),"
            "    $(if ($_.Length) { $_.Length } else { '' }),"
            "    $_.Name, $owner"
            + ("; " + acl_block if show_acl else "")
            + "};"
            "\"\";"
            "\"[Summary] $($items.Count) items, $($totalSize) MB total\""
        )
        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        out = r["output"]
        if len(out) > 5000:
            out = out[:5000] + "\n...[truncated]"
        return ModuleResult.ok(data=out)
