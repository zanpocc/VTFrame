#pragma once
#include <ntddk.h>
#include "../Util/GetUnExportFunAddress.h"



//APC读写进程内存，可过DXF内存读写
#define MALLOC_NPP(_s)        ExAllocatePool(NonPagedPool, _s)
#define FREE(_p)        ExFreePool(_p)

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertKernelApcEnvironment
} KAPC_ENVIRONMENT;

typedef struct _RWPM_INFO
{
	PVOID fun;//需要运行的函数
	ULONG64 ret;//传出的参数
	KEVENT Event;//事件对象
}RWPM_INFO, *PRWPM_INFO;

typedef VOID(*PFUNCTION)(PRWPM_INFO parame);

ULONG64 ExecFun(PFUNCTION pfun, ULONG p);
VOID HookEpt(PRWPM_INFO parame);



NTKERNELAPI UCHAR* PsGetProcessImageFileName(PEPROCESS process);
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE Id, PEPROCESS *Process);

NTKERNELAPI PEPROCESS IoThreadToProcess(
	_In_ PETHREAD Thread
);
NTKERNELAPI NTSTATUS KeInitializeApc(PKAPC a1, PETHREAD a2, KAPC_ENVIRONMENT a3, PVOID a4, __int64 a5, __int64 a6, MODE a7, __int64 a8);
NTKERNELAPI char __fastcall KeInsertQueueApc(PKAPC a1, __int64 a2, __int64 a3, __int64 a4);
VOID __vmx_vmcall(ULONG index, ULONG64 arg1, ULONG64 arg2, ULONG64 arg3);

typedef NTSTATUS (*PsSuspendThreadx)(IN PETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL);
PsSuspendThreadx PsSuspendThread;

typedef NTSTATUS (*PsResumeThreadx)
(PETHREAD Thread, //线程 ETHREAD
	OUT PULONG PreviousCount); //恢复的次数，每恢复一次此值减 1，为 0 时线程才正常
PsResumeThreadx PsResumeThread;

NTKERNELAPI NTSTATUS
PsGetContextThread(
	__in PETHREAD Thread,
	__inout PCONTEXT ThreadContext,
	__in KPROCESSOR_MODE Mode
);

ULONG64 GetGameFakeCr3();
ULONG64 GetGameRealCr3();