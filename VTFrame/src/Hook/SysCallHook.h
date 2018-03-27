#pragma once
#include <ntddk.h>

#define HYPERCALL_HOOK_LSTAR        0x2
#define HYPERCALL_UNHOOK_LSTAR      0x3//UNHOOK SysCall

// SSDT中函数是否HOOK
CHAR HookEnabled[0x1000];
// SSDT被HOOK函数的参数个数
CHAR ArgTble[0x1000];
// SSDT被HOOK函数的新函数地址
PVOID HookTable[0x1000];

extern VOID __vmx_vmcall(ULONG index, ULONG64 arg1, ULONG64 arg2, ULONG64 arg3);

ULONG64 KiSystemCall64Ptr;    // 原始的系统调用地址
ULONG64 KiServiceCopyEndPtr;    // KiSystemServiceCopyEnd地址

VOID AddSSDTHook(ULONG index, PVOID pNewFunc, CHAR ParameterNum);
VOID InitSysCallHook();
VOID UnHookSysCall();