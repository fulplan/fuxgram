# Installation Guide

## Requirements

| Component | Minimum |
|---|---|
| Python | 3.10+ |
| OS (operator) | Windows 10+, Ubuntu 20.04+, macOS 12+ |
| OS (targets) | Windows 7 SP1 – Windows 11 (implant) |
| Cross-compiler | mingw-w64 (for C implant builds) |
| Optional | donut (PE → shellcode), signtool (code signing) |

---

## Step 1 — Clone

```bash
git clone https://github.com/<your-org>/fuxgram.git
cd fuxgram
```

---

## Step 2 — Python dependencies

```bash
pip install -r requirements.txt
```

Core packages installed:
- `python-telegram-bot>=21.0`
- `discord.py>=2.3`
- `prompt_toolkit>=3.0`
- `aiohttp>=3.9`
- `cryptography>=41.0`
- `pyyaml>=6.0`

---

## Step 3 — Configuration

```bash
cp config/framework.yaml.example config/framework.yaml
```

Open `config/framework.yaml` and fill in every field marked `YOUR_`:

```yaml
operator:
  tag: "shadow"                    # shown in audit log + CLI prompt
  auth_pin: "1234"                 # PIN required on bot /start
  allowed_telegram_ids:
    - 123456789                    # your Telegram user ID (from @userinfobot)

telegram:
  token: "YOUR_TELEGRAM_BOT_TOKEN" # from @BotFather
  operator_chat_id: 123456789      # your personal Telegram chat ID

discord:
  token: "YOUR_DISCORD_BOT_TOKEN"  # Discord developer portal
  operator_channel_id: 987654321   # channel ID (right-click → Copy ID)
  enabled: true

implant:
  token: "YOUR_IMPLANT_BOT_TOKEN"  # separate bot for implant comms
  group_id: -100123456789          # Telegram group the implant posts to

http:
  enabled: true
  host: "0.0.0.0"
  port: 8888
  agent_key: "change-this-key"     # implants send this in X-Agent-Key header
```

### Getting Telegram credentials

1. Message `@BotFather` → `/newbot` → note the token
2. Message `@userinfobot` → note your numeric user ID
3. Create a private Telegram group, add your bot, note the group ID (starts with `-100`)

### Getting your Telegram user ID

```
1. Open Telegram
2. Message @userinfobot
3. It replies: "Your user ID: 123456789"
```

### Getting the group chat ID

```bash
# After adding the bot to the group, call:
curl "https://api.telegram.org/bot<TOKEN>/getUpdates"
# Look for "chat":{"id":-100123456789} in a message from the group
```

---

## Step 4 — Data directories

Created automatically on first run. To pre-create:

```bash
mkdir -p data/tls/agents build
```

---

## Step 5 — Cross-compiler (for C implant builds)

**Windows (winget):**
```powershell
winget install MSYS2.MSYS2
# In MSYS2 shell:
pacman -S mingw-w64-x86_64-gcc
```

**Ubuntu/Debian:**
```bash
apt install mingw-w64
```

**macOS (Homebrew):**
```bash
brew install mingw-w64
```

---

## Step 6 — Optional: donut (PE → shellcode)

```bash
pip install donut-shellcode
# or
git clone https://github.com/TheWover/donut
cd donut && make
```

Without donut, `builder -f shellcode` falls back to returning the raw PE.

---

## Step 7 — First start

```bash
python -m fitnah
```

Expected output:
```
[+] Config loaded: config/framework.yaml
[+] Kernel starting...
[+] Plugin engine loaded 103 plugins
[+] Telegram transport connected
[+] HTTP listener started on http://0.0.0.0:8888
[+] Fitnah v2 ready
fitnah> _
```

If Telegram fails to connect:
- Check the token in `framework.yaml`
- Verify your bot is not rate-limited (`/start` the bot in Telegram first)
- Check internet connectivity to `api.telegram.org:443`

---

## Verify installation

```bash
# Run the full test suite — all 177 should pass
python -m pytest tests/ -q

# Check plugin discovery
python -c "from fitnah.orchestration.kernel import Kernel; k=Kernel.__new__(Kernel); print('ok')"
```

---

## Upgrading

```bash
git pull
pip install -r requirements.txt --upgrade
python -m pytest tests/ -q   # verify nothing broke
```

---

## Directory layout after setup

```
fuxgram/
  config/
    framework.yaml          your operator config (never commit)
  data/
    loot.db                 SQLite loot database
    audit.jsonl             append-only audit trail
    fitnah.log              runtime log
    tls/
      ca.crt                mTLS certificate authority
      ca.key                CA private key (chmod 600)
      agents/               per-agent leaf certs
  build/                    generated payloads
  fitnah/
    bofs/                   104 pre-compiled COFF files
    plugins/                post-exploitation modules
```
