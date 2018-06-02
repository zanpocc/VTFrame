#include "APC.h"
#include "../Hook/PageHook.h"
#include "../Include/common.h"

extern HANDLE GamePid;
NTKERNELAPI NTSTATUS PsLookupThreadByThreadId(HANDLE Id, PETHREAD *Process);
PETHREAD LookupThread(HANDLE Tid)
{
	PETHREAD ethread;
	if (NT_SUCCESS(PsLookupThreadByThreadId(Tid, &ethread)))
		return ethread;
	else
		return NULL;
}

PEPROCESS LookupProcess(HANDLE pid)
{
	PEPROCESS Process;
	if (NT_SUCCESS(PsLookupProcessByProcessId(pid, &Process)))
		return Process;
	else
		return NULL;
}

PEPROCESS GetProcessByName(UCHAR* ProcessName) 
{
	ULONG i = 0;
	UCHAR szName[16] = { 0 };
	//从4到2^18开始枚举进程,步进为4
	for (i = 4; i <= 262144; i += 4)
	{
		PEPROCESS process = LookupProcess((HANDLE)i);
		if (process != NULL)
		{
			if (strcmp(ProcessName, PsGetProcessImageFileName(process)) == 0)
			{
				return process;
			}
		}
	}
	return NULL;
	
}

//APC函数体
VOID APCFuntion(PKAPC pApc, ULONG64 *NormalRoutine, PVOID *NormalContext, PVOID *SystemArgument1, PVOID *SystemArgument2)
{
	PRWPM_INFO pInfo = (PRWPM_INFO)(pApc->NormalContext);
	__try
	{
		DbgPrint("APC函数运行中\n");
		ULONG temp = *(ULONG*)0x400500;
		((PFUNCTION)pInfo->fun)(pInfo);
	}
	__except (1)
	{
		DbgPrint("错误的内存访问异常\n");;
		pInfo->ret = 0;
	}
	KeSetEvent(&(pInfo->Event), IO_NO_INCREMENT, FALSE);
	ExFreePool(pApc);
}

//插入APC
NTSTATUS InsertKernelApc(PETHREAD Thread, PRWPM_INFO pInfo)
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	PKAPC pApc = 0;
	if (MmIsAddressValid(Thread))
	{
		pApc = MALLOC_NPP(sizeof(KAPC));
		if (pApc)
		{
			LARGE_INTEGER interval = { 0 };

			//APC初始化,内核模式
			KeInitializeApc(pApc,
				Thread,	//插入的线程
				OriginalApcEnvironment,
				APCFuntion,  //APC函数
				0, 0, KernelMode, 0);

			pApc->NormalContext = pInfo;
			KeInitializeEvent(&(pInfo->Event), NotificationEvent, TRUE);
			KeClearEvent(&(pInfo->Event));
			if (KeInsertQueueApc(pApc, 0, 0, 0))
			{
				interval.QuadPart = -10000;//DELAY_ONE_MILLISECOND;
				interval.QuadPart *= 1000;
				st = KeWaitForSingleObject(&(pInfo->Event), Executive, KernelMode, 0, &interval);
			}
			else
			{
				ExFreePool(pApc);
			}
		}
	}
	return st;
}

ULONG64 ExecFun(PFUNCTION pfun)
{
	ULONG i;
	ULONG64 ret = 0;
	PEPROCESS Process = LookupProcess(GamePid);
	if (Process == NULL)
	{
		DbgPrint("未找到DNF进程\n");
		return FALSE;
	}

	for (i = 4; i < 1048576; i = i + 4)
	{
		PETHREAD ethrd = LookupThread((HANDLE)i);
		if (ethrd != NULL)
		{
			PEPROCESS eproc = IoThreadToProcess(ethrd);
			ObDereferenceObject(ethrd);
			if (eproc == Process)
			{
				PRWPM_INFO pInfo = MALLOC_NPP(sizeof(RWPM_INFO));
				pInfo->fun = pfun;
				if (NT_SUCCESS(InsertKernelApc(ethrd, pInfo)))
				{
					FREE(pInfo);
					ret = pInfo->ret;
					break;
				}
			}
		}
	}
	return ret;
}


ULONG64 GetGameFakeCr3() 
{
	PEPROCESS Process = LookupProcess(GamePid);
	return *(ULONG64*)((ULONG64)Process + 0x28);
}

VOID Empty(PRWPM_INFO parame) {
	parame->ret = __readcr3();
}

ULONG64 GetGameRealCr3()
{
	return ExecFun(Empty);
}


VOID Function()
{
	//自动拾取物品
	PVOID add1 = (PVOID)0x023159F7;
	UCHAR code1[2] = "\x90\x90";

	//拾取范围
	PVOID add2 = (PVOID)0x023159C5;
	UCHAR code2[6] = "\x90\x90\x90\x90\x90\x90";
	ModifyAddressValue2(add2, code2, 6, add1, code1, 2);
}