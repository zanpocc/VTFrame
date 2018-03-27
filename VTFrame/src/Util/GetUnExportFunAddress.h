#pragma once
#include <ntddk.h>

//结构体
typedef struct _SYSTEM_SERVICE_TABLE {
	PVOID ServiceTableBase;
	PVOID ServiceCounterTableBase;
	SIZE_T NumberOfServices;
	PVOID ParamTableBase;
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;


//获得函数中被调用函数的地址
ULONG64 GetSubFunInFunction(
	PVOID pFun, //主函数地址
	ULONG index //函数的第几个子函数地址,从0开始
);

//获得SSDT表中函数的地址
ULONGLONG GetSSDTFunAddrress(ULONG id);

//获得Zw函数地址
SIZE_T GetZwFunAddress(ULONG id);