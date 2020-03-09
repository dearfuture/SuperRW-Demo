#include "MyDriver.h"

VOID EnumDriver(PDRIVER_OBJECT pDriverObject)
{
	PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
	PKLDR_DATA_TABLE_ENTRY firstentry;
	ULONG64 pDrvBase = 0;
	KIRQL OldIrql;
	firstentry = entry;
	
	while ((PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != firstentry)
	{
		DbgPrint("BASE=%p\tPATH=%wZ", entry->DllBase, entry->FullDllName);
		entry = (PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}
	
}


/*typedef struct TIME_FIELDS
{
	CSHORT Year;
	CSHORT Month;
	CSHORT Day;
	CSHORT Hour;
	CSHORT Minute;
	CSHORT Second;
	CSHORT Milliseconds;
	CSHORT Weekday;
} TIME_FIELDS;*/
VOID MyGetCurrentTime()
{
	LARGE_INTEGER CurrentTime;
	LARGE_INTEGER LocalTime;
	TIME_FIELDS   TimeFiled;
	// 这里得到的其实是格林威治时间
	KeQuerySystemTime(&CurrentTime);
	// 转换成本地时间
	ExSystemTimeToLocalTime(&CurrentTime, &LocalTime);
	// 把时间转换为容易理解的形式
	RtlTimeToTimeFields(&LocalTime, &TimeFiled);
	DbgPrint("[TimeTest] NowTime : %4d-%2d-%2d %2d:%2d:%2d",
		TimeFiled.Year, TimeFiled.Month, TimeFiled.Day,
		TimeFiled.Hour, TimeFiled.Minute, TimeFiled.Second);
}


#define DELAY_ONE_MICROSECOND 	(-10)
#define DELAY_ONE_MILLISECOND	(DELAY_ONE_MICROSECOND*1000)

VOID MySleep(LONG msec)
{
	LARGE_INTEGER my_interval;
	my_interval.QuadPart = DELAY_ONE_MILLISECOND;
	my_interval.QuadPart *= msec;
	KeDelayExecutionThread(KernelMode, 0, &my_interval);
}

KEVENT kEvent;

VOID MyThreadFunc(IN PVOID context)
{
	PUNICODE_STRING str = (PUNICODE_STRING)context;
	DbgPrint("Kernel thread running: %wZ\n", str);
	DbgPrint("Wait 3s!\n");
	MySleep(3000);
	DbgPrint("Kernel thread exit!\n");
	KeSetEvent(&kEvent, 0, TRUE);
	PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID CreateThreadTest()
{
	HANDLE     hThread;
	UNICODE_STRING ustrTest = RTL_CONSTANT_STRING(L"This is a string for test!");
	NTSTATUS status;
	// 初始化事件
	KeInitializeEvent(&kEvent, SynchronizationEvent, FALSE);
	status = PsCreateSystemThread(&hThread, 0, NULL, NULL, NULL, MyThreadFunc, (PVOID)&ustrTest);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("PsCreateSystemThread failed!");
		return;
	}
	ZwClose(hThread);
	// 等待事件
	KeWaitForSingleObject(&kEvent, Executive, KernelMode, FALSE, NULL);
	DbgPrint("CreateThreadTest OVER!\n");
}




PVOID ExpLookupHandleTableEntry(IN ULONG_PTR TableCode, IN ULONG_PTR tHandle)
{
	// 一大堆局部变量
	ULONG_PTR i, j, k;
	ULONG_PTR CapturedTable;
	ULONG TableLevel;
	PVOID Entry = NULL;
	ULONG_PTR Handle;

	PUCHAR TableLevel1;
	PUCHAR TableLevel2;
	PUCHAR TableLevel3;


	Handle = tHandle;

#define MAX_HANDLES (1<<24)
#define HANDLE_VALUE_INC 4
#define HANDLE_TABLE_ENTRY_SIZE 16
#define LOWLEVEL_COUNT (PAGE_SIZE/ HANDLE_TABLE_ENTRY_SIZE)
#define MIDLEVEL_COUNT (PAGE_SIZE/ HANDLE_TABLE_ENTRY_SIZE)

	//
	// 得到当前的索引等级 -- 即 CapturedTable 的最后2位
	// 而 (CapturedTable - TableLevel) 便是这个3层表的起始地址。
	// 通过Handle.Value中的后30位保存的索引号，找到进程ID对应的HANDLE_TABLE_ENTRY
	//
	CapturedTable = (ULONG_PTR)TableCode;
	TableLevel = (ULONG)(CapturedTable & 3);
	CapturedTable -= TableLevel;

	//DbgBreakPoint();

	// 有3种情况: 0、1、2
	switch (TableLevel) {

	case 0:

		TableLevel1 = (PUCHAR)CapturedTable;

		// 就一层表。这层表中保存的就是一堆HANDLE_TABLE_ENTRY
		// 索引号*2 得到在其中的偏移量
		Entry = (PVOID)&TableLevel1[Handle * (HANDLE_TABLE_ENTRY_SIZE / HANDLE_VALUE_INC)];

		break;

	case 1:

		TableLevel2 = (PUCHAR)CapturedTable;

		i = Handle % (LOWLEVEL_COUNT * HANDLE_VALUE_INC);

		Handle -= i;
		j = Handle / ((LOWLEVEL_COUNT * HANDLE_VALUE_INC) / sizeof(PVOID));

		TableLevel1 = (PUCHAR) *(PVOID *)&TableLevel2[j];
		Entry = (PVOID)&TableLevel1[i * (HANDLE_TABLE_ENTRY_SIZE / HANDLE_VALUE_INC)];

		break;


	case 2:

		TableLevel3 = (PUCHAR)CapturedTable;

		i = Handle % (LOWLEVEL_COUNT * HANDLE_VALUE_INC);

		Handle -= i;

		k = Handle / ((LOWLEVEL_COUNT * HANDLE_VALUE_INC) / sizeof(PVOID));

		j = k % (MIDLEVEL_COUNT * sizeof(PVOID));

		k -= j;

		k /= MIDLEVEL_COUNT;

		TableLevel2 = (PUCHAR) *(PVOID *)&TableLevel3[k];
		TableLevel1 = (PUCHAR) *(PVOID *)&TableLevel2[j];
		Entry = (PVOID)&TableLevel1[i * (HANDLE_TABLE_ENTRY_SIZE / HANDLE_VALUE_INC)];

		break;

	default:
		break;
	}

	return Entry;
}
