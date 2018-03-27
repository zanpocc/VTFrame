#pragma once
#include <ntddk.h>


#pragma pack(2)
typedef struct {
	USHORT Limit;
	ULONG64 Base;
}IDT_INFO, *PIDT_INFO; 
#pragma pack()

typedef union _KIDTENTRY64
{
	struct
	{
		USHORT OffsetLow;
		USHORT Selector;
		USHORT IstIndex : 3;
		USHORT Reserved0 : 5;
		USHORT Type : 5;
		USHORT Dpl : 2;
		USHORT Present : 1;
		USHORT OffsetMiddle;
		ULONG OffsetHigh;
		ULONG Reserved1;
	};
	UINT64 Alignment;
} KIDTENTRY64, *PKIDTENTRY64;

typedef union _TRAPADDR
{
	ULONG64 All;
	struct 
	{
		ULONG64 low : 16;
		ULONG64 mid : 16;
		ULONG64 hig : 32;
	}field;
}TRAPADDR,PTRAPADDR;

KIRQL WPOFFx64();
void WPONx64(KIRQL irql);

VOID PrintIdt();

ULONG64 GetTrap03Address();

extern ULONG64 GetSubFunInFunction2(
	PVOID pFun, //主函数地址
	ULONG index //函数的第几个子函数地址,从0开始
);