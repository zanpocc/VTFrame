#pragma once
#include <ntddk.h>

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

BOOLEAN ForceWriteProcessMemory2(IN PEPROCESS Process, IN PVOID Address, IN UINT32 Length, IN PVOID Buffer);
BOOLEAN ForceReadProcessMemory2(IN PEPROCESS Process, IN PVOID Address, IN UINT32 Length, OUT PVOID Buffer);
BOOLEAN GetDxfCr3Real(IN PVOID Address, IN UINT32 Length, IN PVOID Buffer);
ULONG64 GetDxfCr3Fake();
BOOLEAN RestoreDate(IN PVOID Address, IN UINT32 Length, IN PVOID Buffer);
BOOLEAN threeS(IN PVOID Address, IN UINT32 Length, IN PVOID Buffer);

NTKERNELAPI UCHAR* PsGetProcessImageFileName(PEPROCESS process);
NTKERNELAPI NTSTATUS PsLookupThreadByThreadId(HANDLE, PETHREAD*);
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE Id, PEPROCESS *Process);

NTKERNELAPI PEPROCESS IoThreadToProcess(
	_In_ PETHREAD Thread
);
NTKERNELAPI NTSTATUS KeInitializeApc(PRKAPC a1, PETHREAD a2, KAPC_ENVIRONMENT a3, ULONG64 KernelRoutine, ULONG64 RundownRoutine, ULONG64 NormalRoutine, KPROCESSOR_MODE ApcMode, PVOID NormalContext);
NTKERNELAPI BOOLEAN __fastcall KeInsertQueueApc(PRKAPC Apc, PVOID SystemArgument1, PVOID SystemArgument2, KPRIORITY Increment);
VOID __vmx_vmcall(ULONG index, ULONG64 arg1, ULONG64 arg2, ULONG64 arg3);