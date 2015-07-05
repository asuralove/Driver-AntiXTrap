#ifndef __INITIOPL_H__
#define __INITIOPL_H__

#include <ntddk.h>
#include <windef.h>
#include <ntstatus.h>
#include <ntdef.h>

typedef NTSTATUS (*_NtOpenProcess) (
OUT PHANDLE,
IN ACCESS_MASK,
IN POBJECT_ATTRIBUTES,
IN PCLIENT_ID OPTIONAL);

struct input
{
	DWORD ProcessID;
	DWORD StartAddress;
	DWORD bytes;
	unsigned char *buffer;
} *pInp;

struct _openProcess
{
	DWORD ProcessID;
	BOOL bInheritHandle;
 	DWORD DesiredAccess;
} *_oProcess;

#define IOCTL_UNKNOWN_BASE					FILE_DEVICE_UNKNOWN

#define IOCTL_READMEMORY	CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_WRITEMEMORY	CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_OPENPROCESS	CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0802, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

NTSTATUS DispatchIoctl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

#endif