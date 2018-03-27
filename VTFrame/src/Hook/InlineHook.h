#pragma once
#include <ntddk.h>

//hook用到的jmp结构,通过堆栈进行跳转
#pragma pack(push, 1)
typedef struct _JUMP_THUNK
{
	UCHAR PushOp;           // 0x68
	ULONG AddressLow;       // 
	ULONG MovOp;            // 0x042444C7
	ULONG AddressHigh;      // 
	UCHAR RetOp;            // 0xC3
} JUMP_THUNK, *PJUMP_THUNK;
#pragma pack(pop)

//外部函数声明
KIRQL WPOFFx64();
void WPONx64(KIRQL irql);

VOID InitJumpThunk(IN OUT PJUMP_THUNK pThunk, IN ULONG64 To);

//返回新的原始函数地址
ULONG64 SetLineHook(PVOID Ori,PVOID Fun);
BOOLEAN RemoveLineHook(PVOID Ori, PVOID Fun);
