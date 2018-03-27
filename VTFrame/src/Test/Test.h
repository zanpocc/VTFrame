#pragma once
#include <ntddk.h>
#include "../Debug/DebugAPI.h"

typedef
NTSTATUS
(*OriDbgkpQueueMessagex)(
	IN PEPROCESS Process,
	IN PETHREAD Thread,
	IN OUT PDBGKM_MSG ApiMsg,
	IN ULONG Flags,
	IN PDEBUG_OBJECT TargetDebugObject
	);
OriDbgkpQueueMessagex OriDbgkpQueueMessage;

VOID TestSSDTHook();
VOID UnloadTest();
VOID TestCallBack();
VOID TestInlineHook();
VOID TestPageHook();

extern ULONG64 oriDbgkForwardException;
extern ULONG64 GetTrap03Address();
ULONG64 TestFn(ULONG64 in1, ULONG64 in2);