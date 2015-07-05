#include "InitIOPL.h"
#include "memscan.h"
#include <string.h>
 
#pragma alloc_text(PAGE, DispatchIoctl)

NTSTATUS DispatchIoctl(IN PDEVICE_OBJECT pDeviceObj, IN PIRP pIrp)
{
	NTSTATUS NtStatus			= STATUS_UNSUCCESSFUL;
	PIO_STACK_LOCATION pStack	= IoGetCurrentIrpStackLocation(pIrp);

	DbgPrint("*** DispatchIoctl Called ***\n");

	switch(pStack->Parameters.DeviceIoControl.IoControlCode)
	{
		case IOCTL_READMEMORY:
				__try
				{
					int myProcess;
					PCHAR ReadBuffer;
					pInp = pIrp->AssociatedIrp.SystemBuffer;
					myProcess = pInp->ProcessID;
					myProcess++;
					DbgPrint("IOCTL_READMEMOR");
					DbgPrint("******************");
					DbgPrint("ProcessID		-> %x", myProcess);
					DbgPrint("StartAddress	-> %x", pInp->StartAddress);
					DbgPrint("ReadSize		-> %x", pStack->Parameters.DeviceIoControl.OutputBufferLength);
					DbgPrint("******************");

					ReadBuffer = (PCHAR)pIrp->AssociatedIrp.SystemBuffer;
					NtStatus = T_ReadProcessMemory(myProcess, NULL, (LPVOID)pInp->StartAddress, pStack->Parameters.DeviceIoControl.OutputBufferLength, ReadBuffer);

					if(NtStatus)
					{
						pIrp->IoStatus.Information = pStack->Parameters.DeviceIoControl.OutputBufferLength;
						NtStatus = STATUS_SUCCESS;
					}
					else
					{
						pIrp->IoStatus.Information = 0;
						NtStatus = STATUS_UNSUCCESSFUL;
					}
				}
				__except(1)
				{
					NtStatus = STATUS_UNSUCCESSFUL;
				};
			break;
		case IOCTL_WRITEMEMORY:
			__try
			{
				int myProcess;
				unsigned char *buffer;
				pInp = pIrp->AssociatedIrp.SystemBuffer;
				myProcess = pInp->ProcessID;
				myProcess++;
				DbgPrint("IOCTL_WRITEMEMORY");
				DbgPrint("******************");
				DbgPrint("ProcessID		-> %x", myProcess);
				DbgPrint("StartAddress	-> %x", pInp->StartAddress);
				DbgPrint("WriteSize		-> %x", pInp->bytes);
				DbgPrint("Buffer		-> %x", &pInp->buffer);
				buffer = (unsigned char*)&pInp->buffer;
				DbgPrint("******************");
				NtStatus = T_WriteProcessMemory(myProcess, NULL, (LPVOID)pInp->StartAddress, pInp->bytes, buffer);
				if(NtStatus)
					NtStatus = STATUS_SUCCESS;
				else
					NtStatus = STATUS_UNSUCCESSFUL;
			}
			__except(1)
			{
				NtStatus = STATUS_UNSUCCESSFUL;
			};
			break;
		case IOCTL_OPENPROCESS:
			__try
			{
				CLIENT_ID client;
				OBJECT_ATTRIBUTES objAttri;
				DWORD retnpID;
				int myProcess;
				BOOL bInheritHandle;
				DWORD DesiredAccess;
				DWORD * _pID;

				_oProcess = pIrp->AssociatedIrp.SystemBuffer;
				myProcess = _oProcess ->ProcessID;
				myProcess++;

				bInheritHandle = _oProcess->bInheritHandle;
				DesiredAccess = _oProcess->DesiredAccess;

				DbgPrint("IOCTL_OPENPROCESS");
				DbgPrint("******************");
				DbgPrint("ProcessID		-> %x", myProcess);
				DbgPrint("DesiredAccess	-> %x", DesiredAccess);
				DbgPrint("bInheritHandle		-> %x", bInheritHandle);
				DbgPrint("******************");

				_pID = (DWORD*)pIrp->AssociatedIrp.SystemBuffer;

				client.UniqueProcess = (HANDLE)myProcess;
				client.UniqueThread = (HANDLE)0;
				//retnpID = myProcess;

                memset(&objAttri, 0, sizeof(objAttri));
                objAttri.Length = sizeof(objAttri);
				//InitializeObjectAttributes (&objAttri, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
                //InitializeObjectAttributes(&objAttri, 0, 0, 0, 0); 
				NtStatus = T_FuncNtOpenProcess(&retnpID, DesiredAccess, &objAttri, &client);
                //NtStatus = FunctionOpenProcess(myProcess, &retnpID);
                DbgPrint("Retn [%x] OpenProcess [%x]", NtStatus, retnpID);
				//NtStatus = ((T_NtOpenProcess)(T_OldNtOpenProcess))(&retnpID, DesiredAccess, &objAttri, &client);

				*_pID = retnpID;
				if(*_pID == 0){
					*_pID = -1;
				}

				if(NtStatus)
					NtStatus = STATUS_SUCCESS;
				else
					NtStatus = STATUS_UNSUCCESSFUL;
			}
			__except(1)
			{
				NtStatus = STATUS_UNSUCCESSFUL;
			};
			break;

	}

	pIrp->IoStatus.Status = NtStatus;
	if(NtStatus == STATUS_SUCCESS)
        pIrp->IoStatus.Information = pStack->Parameters.DeviceIoControl.OutputBufferLength;
	else
		pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return NtStatus;
}
