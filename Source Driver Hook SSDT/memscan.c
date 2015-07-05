#include <ntifs.h>
#include <windef.h>
#include "memscan.h"

#pragma alloc_text(PAGE, T_WriteProcessMemory)
#pragma alloc_text(PAGE, T_ReadProcessMemory)


NTSTATUS T_KeAttachProcess(PEPROCESS p);

BOOLEAN T_WriteProcessMemory(DWORD PID, PEPROCESS PEProcess, PVOID StartAddress, DWORD Size, PVOID Buffer)
{
	PEPROCESS selectProcess = PEProcess;
	NTSTATUS NtStatus		= STATUS_SUCCESS;

	unsigned int error = 0;

	DbgPrint("WriteProcessMemory\n");

	if(PEProcess == NULL)
	{
		if(!NT_SUCCESS(PsLookupProcessByProcessId((PVOID)(UINT_PTR)PID, &selectProcess)))
			return FALSE;
	}

	__try
	{
		T_KeAttachProcess((PEPROCESS)selectProcess);
		__try
		{
			char *target;
			char *source;
			unsigned int i;

			target = StartAddress;
			source = Buffer;
			for(i = 0; i < Size; i++)
			{
				target[i] = source[i];
			}
		}
		__finally
		{
			KeDetachProcess();
		}
	}
	__except(1)
	{
		DbgPrint("Exception Caused\n");
		error = 1;
	}

	if(PEProcess == NULL)
		ObDereferenceObject(selectProcess);

	if(error)
 	 return FALSE;

	return NT_SUCCESS(NtStatus);
}

BOOLEAN T_ReadProcessMemory(DWORD PID,PEPROCESS PEProcess,PVOID StartAddress, DWORD Size, PCHAR pOutputBuffer)
{
	PEPROCESS selectProcess = PEProcess;
	NTSTATUS NtStatus		= STATUS_SUCCESS;
	
	unsigned int error = 0;

	DbgPrint("ReadProcessMemory\n");

	if(PEProcess == NULL)
	{
		if(!NT_SUCCESS(PsLookupProcessByProcessId((PVOID)(UINT_PTR)PID, &selectProcess)))
			return FALSE;
	}

	__try
	{
		T_KeAttachProcess((PEPROCESS)selectProcess);
		__try
		{
			char *source;
			unsigned int i;

			source = StartAddress;

			for(i = 0; i < Size; i++)
			{
				pOutputBuffer[i] = source[i];
			}
		}
		__finally
		{
			KeDetachProcess();
		}
	}
	__except(1)
	{
		DbgPrint("Exception Caused\n");	
		error = 1;
	}

	if(PEProcess == NULL)
		ObDereferenceObject(selectProcess);

	if(error)
 	 return FALSE;

	return NT_SUCCESS(NtStatus);
}

NTSTATUS T_KeAttachProcess(PEPROCESS p)
{
	// unhook com sucesso 
	__asm
	{
		PUSH p
		MOV EDI,EDI
		PUSH EBP
		PUSH EBP
		POP ESP
		jmp OldKeAttachProcess
	}

    /*return T_OldKeAttachProcess(p);*/ // failed
}

//BOOLEAN T_FuncNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
NTSTATUS T_FuncNtOpenProcess(DWORD * ProcessHandle, DWORD DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
  //__asm int 3

  //return T_OldK
    	__asm{
            pop esp
    	    /*push ClientId
    		push ObjectAttributes
    		push DesiredAccess
    		push ProcessHandle*/
    		push 0xC4
    		jmp OldNtOpenProcess
    	}
}

/*NTSTATUS FunctionOpenProcess(DWORD ProcessID, DWORD *ProcessHandle){
    NTSTATUS NtStatus		= STATUS_SUCCESS;
    if(!NT_SUCCESS(PsLookupProcessByProcessId((PVOID)(UINT_PTR)ProcessID, &selectProcess))){
        NtStatus = STATUS_UNSUCCESSFUL;
    }
    
    *ProcessHandle = 
  return NtStatus;
}

NTSTATUS FunctionOpenThread(DWORD ThreadID, DWORD *ProcessHandle){
    NTSTATUS NtStatus = STATUS_SUCCESS;
    if(!NT_SUCCESS(PsLookupThreadByThreadId((PVOID)(UINT_PTR)ThreadID, &ProcessHandle))){
        NtStatus = STATUS_UNSUCCESSFUL;
    }
  return NtStatus;
}

NTSTATUS CloseProcess(DWORD *ProcessHandle){
    ObDereferenceObject(ProcessHandle);
}*/
