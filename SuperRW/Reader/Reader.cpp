// Reader.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>
#include <windows.h>
int main()
{
	DWORD pid;
	scanf_s("%d", &pid);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);


	PVOID address;
	std::cin >> address;

	ULONG_PTR result = 0;
	SIZE_T bytesRead;
	BOOL read = ReadProcessMemory(hProcess, address, &result, sizeof(ULONG_PTR), &bytesRead);
	if (read)
	{
		printf("ReadProcessMemory: %llx\n", result);
	}
	else
	{
		printf("eadProcessMemory failed\n");
	}

	getchar();
	getchar();
	return 0;
}

