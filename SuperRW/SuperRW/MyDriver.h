#include <ntddk.h>

#define	DEVICE_NAME			L"\\Device\\MyDriver"
#define LINK_NAME			L"\\DosDevices\\MyDriver"
#define LINK_GLOBAL_NAME	L"\\DosDevices\\Global\\MyDriver"

#define IOCTL_ULR3IN 	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS) //In LONG
#define IOCTL_USR3IN 	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS) //In BSTR
#define IOCTL_GetKPEB 	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS) //Out LONG
#define IOCTL_GetBSTR 	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS) //Out BSTR
#define IOCTL_ReInline	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS) //Test Call Only
#define IOCTL_Struct	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS) //I+O Struct
#define IOCTL_ReplaceObject	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS) //Replace Object from HandleTable by Handle
//#define IOCTL_RstoreObject	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS) //Rstore Object from HandleTable by Handle


typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY64 InLoadOrderLinks;
	ULONG64 __Undefined1;
	ULONG64 __Undefined2;
	ULONG64 __Undefined3;
	ULONG64 NonPagedDebugInfo;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG   Flags;
	USHORT  LoadCount;
	USHORT  __Undefined5;
	ULONG64 __Undefined6;
	ULONG   CheckSum;
	ULONG   __padding1;
	ULONG   TimeDateStamp;
	ULONG   __padding2;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

VOID EnumDriver(PDRIVER_OBJECT pDriverObject);
VOID MyGetCurrentTime();
VOID MySleep(LONG msec);
VOID MyThreadFunc(IN PVOID context);

extern KEVENT kEvent;
VOID CreateThreadTest();



typedef struct _REPLACE_ENTRY
{
	HANDLE Handle;
	HANDLE TargetPid;
}REPLACE_ENTRY, *PREPLACE_ENTRY;

PVOID ExpLookupHandleTableEntry(IN ULONG_PTR TableCode, IN ULONG_PTR tHandle);

NTSTATUS PsLookupProcessByProcessId(
	HANDLE    ProcessId,
	PEPROCESS *Process
);