// TargetProcess.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>
#include <Windows.h>

int main()
{
	ULONGLONG data = 0x12345678;
	printf("%p: %llx\n", &data, data);


	getchar();
	getchar();
	/*
	while (1)
	{
		Sleep(1000);
	}
	*/
	return 0;
}
