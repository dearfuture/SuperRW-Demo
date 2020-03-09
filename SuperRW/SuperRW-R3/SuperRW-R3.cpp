// SuperRW-R3.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <string.h>
#include <process.h>

#define	DEVICE_NAME			L"\\\\.\\MyDriver"
#define IOCTL_ReplaceObject	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS) //Replace Object from HandleTable by Handle

typedef struct _REPLACE_ENTRY
{
	HANDLE Handle;
	DWORD TargetPid;
}REPLACE_ENTRY, *PREPLACE_ENTRY;

int main()
{
	//printf("%d\n", sizeof(REPLACE_ENTRY));
	HANDLE handle = 0;
	DWORD BytesReturned, success;
	
	/*
	STARTUPINFO StartupInfo;
	ZeroMemory(&StartupInfo, sizeof(StartupInfo));
	StartupInfo.cb = sizeof(StartupInfo);
	PROCESS_INFORMATION ProcessInfo;
	ZeroMemory(&ProcessInfo, sizeof(ProcessInfo));
	
	WCHAR NormalProcess[260] = { 0 };
	wcscpy_s(NormalProcess, L"NormalProcess.exe");
	if (!CreateProcess(NormalProcess, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
	{
		DWORD ErrorCode = GetLastError();
		return EXIT_FAILURE;
	}
	*/

	DWORD pid = 0;
	pid = _getpid();
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	REPLACE_ENTRY replaceEntry = { 0 };
	replaceEntry.Handle = hProcess;

	printf("Input TargetProcessId: \n");

	DWORD targetPid = 0;
	scanf_s("%d", &targetPid);
	replaceEntry.TargetPid = targetPid;
	
	std::cout << "Handle: " << replaceEntry.Handle << "\n";
	std::cout << "TargetPid: " << replaceEntry.TargetPid << "\n";

	handle = CreateFile(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (handle == INVALID_HANDLE_VALUE)
	{
		DWORD ErrorCode = GetLastError();
		return EXIT_FAILURE;
	}

	success = DeviceIoControl(handle, IOCTL_ReplaceObject, &replaceEntry, sizeof(replaceEntry), NULL, 0, &BytesReturned, (LPOVERLAPPED)NULL);
	
	if (success)
	{
		printf("DeviceIoControl success\n");
		printf("Input Target Address To Read: \n");

		PVOID address;
		scanf_s("%p", &address);
		
		ULONG_PTR result = 0;
		BOOL read = ReadProcessMemory(replaceEntry.Handle, address, &result, sizeof(ULONG_PTR), NULL);
		if (read)
		{
			printf("ReadProcessMemory: %llx\n", result);
		}
		else
		{
			printf("ReadProcessMemory failed\n");
		}
		
	}
	else
	{
		printf("DeviceIoControl failed\n");
	}
	
	printf("Read End\n");

	getchar();
	getchar();
	//success = DeviceIoControl(handle, IOCTL_Restore, &replaceEntry, sizeof(replaceEntry), NULL, 0, &BytesReturned, (LPOVERLAPPED)NULL);
	CloseHandle(replaceEntry.Handle);
	CloseHandle(handle);


	return 0;
}

