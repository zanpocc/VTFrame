#include "APC.h"

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
			if (strcmp(ProcessName, PsGetProcessImageFileName(process)) == NULL)
			{
				return process;
			}
		}
	}

	return NULL;
	
}



//UserAPC函数体
VOID UsrtAPCFuntion(PKAPC pApc, ULONG64 *NormalRoutine, PVOID *NormalContext, PVOID *SystemArgument1, PVOID *SystemArgument2)
{
	__debugbreak();
	PRWPM_INFO pInfo = 0;
	__try
	{
		pInfo = (PRWPM_INFO)(pApc->NormalContext);
		DbgPrint("用户模式APC\n");
	}
	__except (1)
	{
		DbgPrint("异常\n");
	}
	KeSetEvent(&(pInfo->Event), IO_NO_INCREMENT, FALSE);
	ExFreePool(pApc);
}

//APC函数体
VOID APCFuntion(PKAPC pApc, ULONG64 *NormalRoutine, PVOID *NormalContext, PVOID *SystemArgument1, PVOID *SystemArgument2)
{
	PRWPM_INFO pInfo = (PRWPM_INFO)(pApc->NormalContext);
	__try
	{
		DbgPrint("APC函数运行中\n");
		ULONG temp = *(ULONG*)0x00400000;
		((PFUNCTION)pInfo->fun)();
	}
	__except (1)
	{
		;
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

//插入用户层APC
NTSTATUS InsertUserApc(PETHREAD Thread, PRWPM_INFO pInfo,ULONG64 pUserApc)
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	PKAPC pApc = 0;
	PVOID userAocAddr = 0;

	DbgPrint("pUserApc:%llx\n", pUserApc);
	userAocAddr = (~pUserApc + 1) << 2;
	DbgPrint("userAocAddr:%llx\n", userAocAddr);
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
				UsrtAPCFuntion,  //APC函数
				0,
				userAocAddr,//用户层APC地址
				UserMode,//用户模式
				0	//参数
			);

			pApc->NormalContext = pInfo;
			KeInitializeEvent(&(pInfo->Event), NotificationEvent, TRUE);
			KeClearEvent(&(pInfo->Event));
			if (KeInsertQueueApc(pApc, 0, 0, 0))
			{
				interval.QuadPart = -10000;//DELAY_ONE_MILLISECOND;
				interval.QuadPart *= 1000;
				st = KeWaitForSingleObject(&(pInfo->Event), Executive, KernelMode, 0, &interval);
				DbgPrint("KeInsertQueueAp成功c\n");
			}
			else
			{
				ExFreePool(pApc);
				DbgPrint("KeInsertQueueAp失败c\n");
			}
		}
	}
	return st;
}

BOOLEAN ExecFun(PFUNCTION pfun)
{
	ULONG i;
	BOOLEAN b = 0;
	PEPROCESS Process = GetProcessByName("dnf.exe");
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
					b = 1; break;
				}
			}
		}
	}
	return b;
}

BOOLEAN ExecFun1(PVOID pfun)
{
	ULONG i;
	BOOLEAN b = 0;
	PEPROCESS Process = GetProcessByName("dnf.exe");
	if (Process == NULL)
		return FALSE;

	for (i = 4; i < 1048576; i = i + 4)
	{
		PETHREAD ethrd = LookupThread((HANDLE)i);
		if (ethrd != NULL)
		{
			ULONG count = 0;
			//挂起线程
			NTSTATUS st = PsSuspendThread(ethrd,&count);
			if (!NT_SUCCESS(st))
			{
				DbgPrint("挂起线程失败\n");
			}
			else
			{
				DbgPrint("挂起线程成功\n");
			}
			//获得线程CONTEXT
			//修改线程CONTEXT
			//恢复线程运行
		}
	}
	return b;
}

VOID GetThreadFunAdd()
{
	__try {
		PVOID pNtSuspendThread, pPsSuspendThread, pNtDebugContinue, pDbgkpWakeTarget, pResumeThread;
		
		pNtSuspendThread = GetSSDTFuncCurAddr(379);
		pNtDebugContinue = GetSSDTFuncCurAddr(174);

		pPsSuspendThread = GetSubFunInFunction(pNtSuspendThread, 1);

		pDbgkpWakeTarget = GetSubFunInFunction(pNtDebugContinue, 5);
		
		pResumeThread = GetSubFunInFunction(pDbgkpWakeTarget, 0);
		
		DbgPrint("PsSuspendThread:%llx,pResumeThread:%llx\n", pPsSuspendThread,pResumeThread);

		PsSuspendThread = pPsSuspendThread;
		PsResumeThread = pResumeThread;
	}
	__except (1)
	{
		DbgPrint("异常\n");
	}
}

VOID ThreadEipInsert() 
{
	ULONG i;
	BOOLEAN b = 0;
	GetThreadFunAdd();
	PEPROCESS Process = GetProcessByName("dnf.exe");
	if (Process == NULL)
		return FALSE;

	for (i = 4; i < 1048576; i = i + 4)
	{
		PETHREAD ethrd = LookupThread((HANDLE)i);
		if (ethrd != NULL)
		{
			PEPROCESS eproc = IoThreadToProcess(ethrd);
			//ObDereferenceObject(ethrd);
			if (eproc == Process)
			{
				ULONG count = 0;
				NTSTATUS st = PsSuspendThread(ethrd,&count);
				__debugbreak();
				if (NT_SUCCESS(st))
				{
					DbgPrint("暂停线程成功\n");
					
					CONTEXT context = { 0 };
					context.ContextFlags = CONTEXT_FULL;
					st = PsGetContextThread(ethrd,&context,KernelMode);
					DbgPrint("PsGetContextThread return %x\n", st);
					if (NT_SUCCESS(st))
					{
						DbgPrint("获得线程Context结构成功\n");
						st = PsResumeThread(ethrd, &count);
						if (NT_SUCCESS(st))
						{
							DbgPrint("恢复线程运行成功\n");
						}
					}
				}
			}
		}
	}
	
}