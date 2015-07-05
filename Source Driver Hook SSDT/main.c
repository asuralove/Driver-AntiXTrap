#include <ntddk.h>
#include <windef.h>

#include "InitIOPL.h"
#include "memscan.h"
#include "HookShadowSSDT.h"

__declspec(dllimport) _stdcall KeAddSystemServiceTable(PVOID, PVOID, PVOID, PVOID, PVOID);   
__declspec(dllimport)  ServiceDescriptorTableEntry *KeServiceDescriptorTable; 

NTSTATUS DispatchCreate(IN PDEVICE_OBJECT pDeviceObj, IN PIRP pIrp)
{
	NTSTATUS NtStatus = STATUS_SUCCESS;
	UNICODE_STRING sga;
  

	DbgPrint("*** DispatchCreate Called ***\n");

	RtlInitUnicodeString(&sga, L"KeAttachProcess"); 
	T_OldKeAttachProcess = (KEATTACHPROCESS)MmGetSystemRoutineAddress(&sga);

	RtlInitUnicodeString(&sga, L"NtOpenProcess"); 
	T_OldNtOpenProcess = (T_NtOpenProcess)MmGetSystemRoutineAddress(&sga);

	OldNtOpenProcess = (unsigned char*)T_OldNtOpenProcess;
	DbgPrint("OldNtOpenProcess  -> 0x%x", OldNtOpenProcess);

	OldKeAttachProcess = (unsigned char*)T_OldKeAttachProcess;
	DbgPrint("KeAttachProcess -> 0x%x", OldKeAttachProcess);

	// dbg hex temp
	/*__try
	{
		for(tmp = 0; tmp < 50; tmp++)
		{
			dbg_t = (unsigned char)*OldKeAttachProcess;
			DbgPrint("%02x ", dbg_t);
			OldKeAttachProcess = OldKeAttachProcess + 1;
		}

		OldKeAttachProcess = (unsigned char*)OldKeAttachProcess;
	}
	__except(1)
	{
		DbgPrint("Exception Debugger\n");
	}

	T_OldKeAttachProcess = (KEATTACHPROCESS)OldKeAttachProcess;
	DbgPrint("Dbg T_OldKeAttachProcess -> %x", T_OldKeAttachProcess);
	*/

	OldKeAttachProcess += 0x05;
	OldNtOpenProcess += 0x05;

	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = NtStatus;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return NtStatus;
}

NTSTATUS DispatchClose(IN PDEVICE_OBJECT pDeviceObj, IN PIRP pIrp)
{
	NTSTATUS NtStatus = STATUS_SUCCESS;


	DbgPrint("*** DispatchClose Called ***\n");

	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = NtStatus;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return NtStatus;
}

void UnloadDriver(PDRIVER_OBJECT pDriverObj)
{
	UNICODE_STRING usDosDeviceName;

	DbgPrint("*** UnloadDriver Called ***\n");

	RtlInitUnicodeString(&usDosDeviceName, L"\\Device\\DosExemple");
	IoDeleteSymbolicLink(&usDosDeviceName);

	IoDeleteDevice(pDriverObj->DeviceObject);
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING RegistryPath)
{	
    unsigned char *opcode;
    int i;
    
	NTSTATUS NtStatus = STATUS_SUCCESS;
	PDEVICE_OBJECT pDeviceObj = NULL;
	UNICODE_STRING us_DriverName, us_DosDeviceName;

	DbgPrint("*** DriverEntry Called ***\n");
	DbgPrint("%x %x", T_FuncNtOpenProcess, T_KeAttachProcess);
	
	opcode = (unsigned char*)T_FuncNtOpenProcess;
	
	// Remove Mov edi, edi, push ebp, mov ebp, esp da função .... 
	for(i = 0; i < 6; i++){
        opcode[i] = 0x90;
    }
    
    opcode[0x11] = 0x90;

	RtlInitUnicodeString(&us_DriverName, L"\\Device\\Example");
	RtlInitUnicodeString(&us_DosDeviceName, L"\\DosDevices\\Example");

	NtStatus = IoCreateDevice(pDriverObj, 0, &us_DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObj);
	if(NtStatus == STATUS_SUCCESS)
	{
		pDriverObj->MajorFunction[IRP_MJ_CREATE]			= DispatchCreate;
		pDriverObj->MajorFunction[IRP_MJ_CLOSE]				= DispatchClose;	
		pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL]	= DispatchIoctl;

		pDriverObj->DriverUnload							= UnloadDriver;

		IoCreateSymbolicLink(&us_DosDeviceName, &us_DriverName);
	}

	return NtStatus;
}
