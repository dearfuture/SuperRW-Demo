//驱动开发模板_Win64
//作者：Tesla.Angela(GDUT.HWL)


#include <ntddk.h>
//#include <ntifs.h>
#include "MyDriver.h"    

PVOID mem = NULL;

VOID DriverUnload(PDRIVER_OBJECT pDriverObj)
{
	UNICODE_STRING strLink;
	RtlInitUnicodeString(&strLink, LINK_NAME);
	IoDeleteSymbolicLink(&strLink);
	IoDeleteDevice(pDriverObj->DeviceObject);
	ExFreePoolWithTag(mem, 'abcd');
	//TODO: Restore Entry
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION pIrpStack;
	ULONG uIoControlCode;
	PVOID pIoBuffer;
	ULONG uInSize;
	ULONG uOutSize;
	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
	uInSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	uOutSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	switch (uIoControlCode)
	{
	case IOCTL_ReplaceObject:
	{
		DbgBreakPoint();
		PREPLACE_ENTRY ReplaceEntry = (PREPLACE_ENTRY)pIoBuffer;
		PEPROCESS CurrentProcess = PsGetCurrentProcess();
#define ObjectTable_Offset_Win7 0x200
//#define ObjectTable_Offset_Win10 0x418 
		
		ULONG_PTR HandleTable = *(PULONG_PTR)((PUCHAR)CurrentProcess + ObjectTable_Offset_Win7);
		ULONG_PTR TableCode = *(PULONG_PTR)HandleTable;
		PULONG_PTR Entry = NULL;
		Entry = ExpLookupHandleTableEntry(TableCode, (ULONG_PTR)ReplaceEntry->Handle);

		PEPROCESS TagetProcess;
		status = PsLookupProcessByProcessId(ReplaceEntry->TargetPid, &TagetProcess);

		if (!NT_SUCCESS(status))
		{
			status = STATUS_INVALID_HANDLE;
			break;
		}

		
		mem = ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'abcd');

		if (mem == NULL)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		
#define SIZEOF_EPROCESS_Win7 0x4d0
//#define SIZEOF_EPROCESS_Win10 0x848 
#define OFFSET_BODY_Win7 0x30
//#define OFFSET_BODY_Win10 0x30

		PVOID ObjectHeader = mem;
		PVOID TargetHeader = (PUCHAR)TagetProcess - OFFSET_BODY_Win7;
		RtlCopyMemory(ObjectHeader, TargetHeader, OFFSET_BODY_Win7 + SIZEOF_EPROCESS_Win7);


#define OBJ_PROTECT_CLOSE		1
//#define OBJ_INHERIT			  2
//#define OBJ_AUDIT_OBJECT_CLOSE  4

		*Entry = (ULONG_PTR)ObjectHeader | OBJ_PROTECT_CLOSE ;		

		//Without OBJ_PROTECT_CLOSE specified, ObReferenceObjectByHandle will not be unlocked 
		//_HANDLE_TABLE_ENTRY { PVOID ObjectHeader; ACCESS_MASK GrantedAccess; }  
		//just modify ObjectHeader
		
		uOutSize = 1;
		status = STATUS_SUCCESS;
		break;
	}
	
	case IOCTL_ULR3IN:
	{
		/*memcpy(&ulR3IN,pIoBuffer,sizeof(ulR3IN));
		DbgPrint("LONG From R3: %ld",ulR3IN);*/


		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_USR3IN:
	{
		/*usR3IN=*(PCWSTR *)pIoBuffer;
		RtlInitUnicodeString(&r3us,usR3IN);
		DbgPrint("BSTR From R3: %wZ",&r3us);
		hFileHandle = SkillIoOpenFile(usR3IN,FILE_READ_ATTRIBUTES,FILE_SHARE_DELETE);
		if (hFileHandle!=NULL)
		{
			SKillDeleteFile(hFileHandle);
			ZwClose(hFileHandle);
			DbgPrint("delete file succeed!\n");
		}*/
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_GetKPEB: //output eprocess
	{
		/*PsLookupProcessByProcessId(ulR3IN,&eProcess);
		memcpy(pIoBuffer,&(ULONG)eProcess,sizeof(ULONG));*/
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_ReInline:
	{
		/*RestoreInlineHook(L"ObReferenceObjectByHandle");
		DbgPrint("Clear ObReferenceObjectByHandle Head Inline Hook!");*/
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_GetBSTR:
	{
		/*RtlInitUnicodeString(&US,L"Driver String For Visual Basic: 我爱北京天安门！");
		RtlUnicodeStringToAnsiString(&AS,&US,TRUE);
		strcpy(ctmp,AS.Buffer);
		RtlFreeAnsiString(&AS);
		memcpy(pIoBuffer,ctmp,260);*/
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_Struct:
	{
		/*memcpy(&calctest,pIoBuffer,sizeof(CALC));
		num1=calctest.Number1;num2=calctest.Number2;
		DbgPrint("num1=%d;num2=%d",num1,num2);
		addans=num1+num2;subans=num1-num2;
		DbgPrint("AddAns=%d;SubAns=%d",addans,subans);
		calctest.AddAns=addans;calctest.SubAns=subans;
		memcpy(pIoBuffer,&calctest,sizeof(CALC));*/
		status = STATUS_SUCCESS;
		break;
	}
	}
	if (status == STATUS_SUCCESS)
		pIrp->IoStatus.Information = uOutSize;
	else
		pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryString)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING ustrLinkName;
	UNICODE_STRING ustrDevName;
	PDEVICE_OBJECT pDevObj;
	pDriverObj->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObj->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	pDriverObj->DriverUnload = DriverUnload;
	RtlInitUnicodeString(&ustrDevName, DEVICE_NAME);
	status = IoCreateDevice(pDriverObj, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDevObj);
	if (!NT_SUCCESS(status))	return status;
	if (IoIsWdmVersionAvailable(1, 0x10))
		RtlInitUnicodeString(&ustrLinkName, LINK_GLOBAL_NAME);
	else
		RtlInitUnicodeString(&ustrLinkName, LINK_NAME);
	status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDevObj);
		return status;
	}
	//ByPass MmVerifyCallbackFunction
	PKLDR_DATA_TABLE_ENTRY ldr = (PKLDR_DATA_TABLE_ENTRY)pDriverObj->DriverSection;
	ldr->Flags |= 0x20;
	EnumDriver(pDriverObj);
	MyGetCurrentTime();
	CreateThreadTest();
	return STATUS_SUCCESS;
}