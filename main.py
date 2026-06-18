"""
Fitnah v2 — framework entry point.

Usage:
    python main.py --config config/framework.yaml
    python main.py --config config/framework.yaml --project op1 --operator alice
    python main.py --config config/framework.yaml --no-http --profile jquery
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
import threading
from pathlib import Path


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="fitnah",
        description="Fitnah v2 — Telegram/Discord C2 framework",
    )
    p.add_argument(
        "--config", "-c",
        default="config/framework.yaml",
        help="Path to framework.yaml (default: config/framework.yaml)",
    )
    p.add_argument(
        "--project", "-p",
        default="",
        help="Project name to load or create (default: auto-named by date)",
    )
    p.add_argument(
        "--operator", "-o",
        default="operator",
        help="Operator handle for audit trail (default: operator)",
    )
    p.add_argument(
        "--no-http",
        action="store_true",
        help="Disable the HTTP implant listener",
    )
    p.add_argument(
        "--profile",
        default="",
        help="Malleable C2 profile name: jquery, office365, windows_update, google_fonts",
    )
    p.add_argument(
        "--http-host",
        default="",
        help="Override HTTP listener host (default from config)",
    )
    p.add_argument(
        "--http-port",
        type=int,
        default=0,
        help="Override HTTP listener port (default from config)",
    )
    return p.parse_args()


def _setup_signal_handlers(loop: asyncio.AbstractEventLoop, kernel) -> None:
    """Wire SIGINT/SIGTERM to graceful kernel shutdown."""
    def _shutdown(sig_name: str) -> None:
        print(f"\n[!] Caught {sig_name} — shutting down gracefully...", flush=True)
        asyncio.run_coroutine_threadsafe(kernel.stop(), loop)

    if sys.platform != "win32":
        loop.add_signal_handler(signal.SIGINT,  lambda: _shutdown("SIGINT"))
        loop.add_signal_handler(signal.SIGTERM, lambda: _shutdown("SIGTERM"))
    else:
        # Windows doesn't support loop.add_signal_handler for SIGINT
        import signal as _sig
        _sig.signal(_sig.SIGINT,  lambda s, f: _shutdown("SIGINT"))
        _sig.signal(_sig.SIGTERM, lambda s, f: _shutdown("SIGTERM"))


def main() -> None:
    args = _parse_args()

    # ── config ────────────────────────────────────────────────────────────
    try:
        import fitnah.config as _cfg_mod
        cfg = _cfg_mod.load(args.config)
        _cfg_mod.setup_logging(cfg)
    except Exception as exc:
        print(f"[!] Config error: {exc}", file=sys.stderr)
        sys.exit(1)

    log = logging.getLogger("fitnah.main")

    # ── project ───────────────────────────────────────────────────────────
    from fitnah.orchestration.project import Project, ProjectError
    import time

    project_name = args.project or time.strftime("op_%Y%m%d")
    try:
        if Project.exists(project_name):
            project = Project.load(project_name)
            log.info("Loaded project: %s", project_name)
        else:
            project = Project(name=project_name, operator=args.operator)
            log.info("Created project: %s", project_name)
    except ProjectError as exc:
        print(f"[!] Project error: {exc}", file=sys.stderr)
        sys.exit(1)

    # ── C2 profile ────────────────────────────────────────────────────────
    profile = None
    if args.profile:
        try:
            from fitnah.c2.profiles import ProfileManager
            mgr     = ProfileManager()
            profile = mgr.get(args.profile)
            if profile is None:
                print(f"[!] Unknown profile '{args.profile}'. Available: {', '.join(mgr.list())}")
                sys.exit(1)
            log.info("C2 profile: %s  (%s)", profile.name, profile.checkin_uri)
        except Exception as exc:
            log.warning("Could not load C2 profile: %s", exc)

    # ── kernel ────────────────────────────────────────────────────────────
    from fitnah.orchestration.kernel import Kernel

    # Apply CLI overrides to config before kernel init
    if args.no_http:
        cfg._data.setdefault("c2", {})["http_enabled"] = False
    if args.http_host:
        cfg._data.setdefault("c2", {})["http_host"] = args.http_host
    if args.http_port:
        cfg._data.setdefault("c2", {})["http_port"] = args.http_port
    if profile:
        cfg._data.setdefault("c2", {})["profile"] = profile.name

    kernel = Kernel(cfg=cfg, project=project)
    if profile:
        # Inject profile into HTTP listener after kernel creates it
        if kernel._http:
            kernel._http._profile = profile

    # ── event loop in background thread ───────────────────────────────────
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    _setup_signal_handlers(loop, kernel)

    _ready = threading.Event()

    def _run_loop() -> None:
        loop.run_until_complete(kernel.start(_ready))
        loop.close()

    bg_thread = threading.Thread(target=_run_loop, daemon=True, name="c2-loop")
    bg_thread.start()

    # wait up to 8 s for transports to connect before showing the REPL
    _ready.wait(timeout=8)

    # silence routine INFO chatter during interactive session
    logging.getLogger("fitnah").setLevel(logging.WARNING)

    # ── banner + console (main thread) ────────────────────────────────────
    from fitnah.orchestration.console import FitnahConsole

    print(f"  Project  : {project.name}  |  Operator: {args.operator}")
    print(f"  Transport: Telegram", end="")
    if cfg.discord_enabled and cfg.get("discord", "token", default=""):
        print(" + Discord fallback", end="")
    if not args.no_http:
        host = args.http_host or cfg.get("c2", "http_host", default="0.0.0.0")
        port = args.http_port or cfg.get("c2", "http_port", default=8888)
        tls  = "https" if cfg.get("c2", "tls_cert") else "http"
        print(f" + HTTP listener ({tls}://{host}:{port})", end="")
    if profile:
        print(f"  Profile  : {profile.name}", end="")
    print("\n")

    console = FitnahConsole(kernel=kernel, project=project, loop=loop)
    try:
        console.run()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        log.info("Console exited — waiting for C2 loop to stop...")
        asyncio.run_coroutine_threadsafe(kernel.stop(), loop)
        bg_thread.join(timeout=5)
        log.info("Shutdown complete.")


if __name__ == "__main__":
    main()
