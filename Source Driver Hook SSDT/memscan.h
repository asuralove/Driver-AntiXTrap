#ifndef __MEMSCAN_H__
#define __MEMSCAN_H__

#include <ntddk.h>

typedef NTSTATUS(NTAPI* T_NtOpenProcess)(__out PHANDLE ProcessHandle,
__in ACCESS_MASK DesiredAccess,
__in POBJECT_ATTRIBUTES ObjectAttributes,
__in_opt PCLIENT_ID ClientId);


typedef NTSTATUS (*KEATTACHPROCESS)(IN PEPROCESS Process);

T_NtOpenProcess T_OldNtOpenProcess;
unsigned char *OldNtOpenProcess;

KEATTACHPROCESS T_OldKeAttachProcess;
unsigned char *OldKeAttachProcess, dbg_t;
int tmp;

NTSTATUS T_KeAttachProcess(PEPROCESS p);

BOOLEAN T_WriteProcessMemory(DWORD PID, PEPROCESS PEProcess, PVOID StartAddress, DWORD Size, PVOID Buffer);
BOOLEAN T_ReadProcessMemory(DWORD PID, PEPROCESS PEProcess, PVOID StartAddress, DWORD Size, PCHAR pOutputBuffer);
NTSTATUS T_FuncNtOpenProcess(DWORD * ProcessHandle, DWORD DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
NTSTATUS MyNtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    HANDLE ProcessId,
    KPROCESSOR_MODE AccessMode
    );
    
NTSTATUS FunctionOpenProcess(DWORD ProcessID, DWORD *ProcessHandle);
NTSTATUS FunctionOpenThread(DWORD ThreadID, DWORD *ProcessHandle);
NTSTATUS CloseProcess(DWORD *ProcessHandle);

#endif
