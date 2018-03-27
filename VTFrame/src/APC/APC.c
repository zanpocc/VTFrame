#include "APC.h"


ULONG oldBeg = 0;
ULONG oldEnd = 0;


//APC读写进程内存，可过DXF
#define MALLOC_NPP(_s)        ExAllocatePool(NonPagedPool, _s)
#define FREE(_p)        ExFreePool(_p)



typedef struct _RWPM_INFO
{
	void* Address;
	void* Buffer;
	SIZE_T Length;
	SIZE_T Type;//0=read;1=write
	KEVENT Event;
}RWPM_INFO, *PRWPM_INFO;


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

	//从4到2^18开始枚举进程,步进为4
	for (i = 4; i <= 262144; i += 4)
	{
		PEPROCESS process = LookupProcess((HANDLE)i);
		if (process != NULL)
		{
			if (strcmp((const char*)ProcessName, (const char*)PsGetProcessImageFileName(process)) == 0)
			{
				return process;
			}
		}
	}

	return NULL;
	
}

//APC函数体
VOID GetDxfRealCr3Apc(PKAPC pApc, ULONG64 *NormalRoutine, PVOID *NormalContext, PVOID *SystemArgument1, PVOID *SystemArgument2)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	PRWPM_INFO pInfo = (PRWPM_INFO)(pApc->NormalContext);
	
	__try
	{
		DbgPrint("APC例程执行,当前进程:%s\n", PsGetProcessImageFileName(PsGetCurrentProcess()));
		
		RtlCopyMemory(pInfo->Buffer, pInfo->Address, pInfo->Length);

		ULONG64 cr3 = __readcr3();
	
		RtlCopyMemory(pInfo->Buffer,&cr3, pInfo->Length);
	}
	__except (1)
	{
		;
	}
	pInfo->Type = 2;
	KeSetEvent(&(pInfo->Event), IO_NO_INCREMENT, FALSE);
	ExFreePool(pApc);
}


//APC函数体3
VOID RestoreDateApc(PKAPC pApc, ULONG64 *NormalRoutine, PVOID *NormalContext, PVOID *SystemArgument1, PVOID *SystemArgument2)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	PRWPM_INFO pInfo = (PRWPM_INFO)(pApc->NormalContext);

	__try
	{
		RtlCopyMemory(pInfo->Buffer, pInfo->Address, pInfo->Length);
	
		PULONG base = (PULONG)0x100100;
		//0冰冻  1骷髅
		*base = 0;
		//伤害100104
		*(base + 1) = 0;
		//范围100108
		*(base + 2) = 0;
		//频率10010c
		*(base + 3) = 0;
		//时间100110
		*(base + 4) = 0;
		//几率100114
		*(base + 5) = 0;
		//冰冻等级100118
		*(base + 6) = 0;
		//伤害倍数10011c
		*(base + 7) = 0;

		//人物基址
		ULONG RoleBase = 0x044D39B0;
		//物品栏偏移
		ULONG offset1 = 0x6118;
		//不变
		ULONG offset2 = 0x58;
		//物品栏1偏移
		ULONG offset3 = 0xc;

		//冰冻开始
		ULONG offset4 = 0xb54;
		//冰冻结束
		ULONG offset5 = 0xb58;


		*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)RoleBase) + offset1)) + offset2)) + offset3)) + offset4) = oldBeg;
		*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)RoleBase) + offset1)) + offset2)) + offset3)) + offset5) = oldEnd;

		ULONG64 cr3 = __readcr3();
		
		RtlCopyMemory(pInfo->Buffer, &cr3, pInfo->Length);
	}
	__except (1)
	{
		;
	}
	pInfo->Type = 2;
	KeSetEvent(&(pInfo->Event), IO_NO_INCREMENT, FALSE);
	ExFreePool(pApc);
}


//APC函数体3
VOID ThreeSApc(PKAPC pApc, ULONG64 *NormalRoutine, PVOID *NormalContext, PVOID *SystemArgument1, PVOID *SystemArgument2)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	PRWPM_INFO pInfo = (PRWPM_INFO)(pApc->NormalContext);

	__try
	{
		RtlCopyMemory(pInfo->Buffer, pInfo->Address, pInfo->Length);

		//评分基址
		PULONG base = (PULONG)0x043C56AC;
		//评分偏移
		ULONG offset = 0x110;

		*(PULONG)((*base) + offset) = 9999999;

		ULONG64 cr3 = __readcr3();

		RtlCopyMemory(pInfo->Buffer, &cr3, pInfo->Length);
	}
	__except (1)
	{
		;
	}
	pInfo->Type = 2;
	KeSetEvent(&(pInfo->Event), IO_NO_INCREMENT, FALSE);
	ExFreePool(pApc);
}

//APC函数体
VOID ReadWriteProcessMemoryApc(PKAPC pApc, ULONG64 *NormalRoutine, PVOID *NormalContext, PVOID *SystemArgument1, PVOID *SystemArgument2)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	PRWPM_INFO pInfo = (PRWPM_INFO)(pApc->NormalContext);

	if (pInfo->Type == 0)
	{
		__try
		{
			/*DbgPrint("APC例程执行,当前进程:%s\n", PsGetProcessImageFileName(PsGetCurrentProcess()));
			ULONG64 cr3 = __readcr3();
			DbgPrint("cr3:%llx,DirPageTable:%llx\n", cr3, *(PULONG64)((ULONG64)PsGetCurrentProcess() + 0x28));*/

			RtlCopyMemory(pInfo->Buffer, pInfo->Address, pInfo->Length);

			/*DbgPrint("APC例程执行,当前进程:%s\n", PsGetProcessImageFileName(PsGetCurrentProcess()));
			cr3 = __readcr3();
			*(PULONG64)((ULONG64)PsGetCurrentProcess() + 0x28) = cr3;
			DbgPrint("cr3:%llx,DirPageTable:%llx\n", cr3, *(PULONG64)((ULONG64)PsGetCurrentProcess() + 0x28));*/
		}
		__except (1)
		{
			;
		}
	}
	else
	{
		__try
		{
			_disable();
			__writecr0(__readcr0() & 0xfffffffffffeffff);
			RtlCopyMemory(pInfo->Address, pInfo->Buffer, pInfo->Length);
			__writecr0(__readcr0() | 0x10000);
			_enable();
		}
		__except (1)
		{
			;
		}
	}
	pInfo->Type = 2;
	KeSetEvent(&(pInfo->Event), IO_NO_INCREMENT, FALSE);
	ExFreePool(pApc);
}

//插入APC
NTSTATUS InsertReadWriteProcessMemoryApc(PETHREAD Thread, PRWPM_INFO pInfo)
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	PKAPC pApc = 0;
	if (MmIsAddressValid(Thread))
	{
		pApc = MALLOC_NPP(sizeof(KAPC));
		if (pApc)
		{
			LARGE_INTEGER interval = { 0 };
			//APC初始化
			KeInitializeApc(pApc,
				Thread,	//插入的线程
				OriginalApcEnvironment,
				(ULONG64)ReadWriteProcessMemoryApc,  //APC函数
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

//插入APC2
NTSTATUS InsertGetDxfRealCr3Apc(PETHREAD Thread, PRWPM_INFO pInfo)
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	PKAPC pApc = 0;
	if (MmIsAddressValid(Thread))
	{
		pApc = MALLOC_NPP(sizeof(KAPC));
		if (pApc)
		{
			LARGE_INTEGER interval = { 0 };
			//APC初始化
			KeInitializeApc(pApc,
				Thread,	//插入的线程
				OriginalApcEnvironment,
				(ULONG64)GetDxfRealCr3Apc,  //APC函数
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

//插入APC3
NTSTATUS InsertRestoreDateApc(PETHREAD Thread, PRWPM_INFO pInfo)
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	PKAPC pApc = 0;
	if (MmIsAddressValid(Thread))
	{
		pApc = MALLOC_NPP(sizeof(KAPC));
		if (pApc)
		{
			LARGE_INTEGER interval = { 0 };
			//APC初始化
			KeInitializeApc(pApc,
				Thread,	//插入的线程
				OriginalApcEnvironment,
				(ULONG64)RestoreDateApc,  //APC函数
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

//插入APC4
NTSTATUS InsertThreeSApc(PETHREAD Thread, PRWPM_INFO pInfo)
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	PKAPC pApc = 0;
	if (MmIsAddressValid(Thread))
	{
		pApc = MALLOC_NPP(sizeof(KAPC));
		if (pApc)
		{
			LARGE_INTEGER interval = { 0 };
			//APC初始化
			KeInitializeApc(pApc,
				Thread,	//插入的线程
				OriginalApcEnvironment,
				(ULONG64)ThreeSApc,  //APC函数
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

BOOLEAN ForceReadProcessMemory2(IN PEPROCESS Process, IN PVOID Address, IN UINT32 Length, OUT PVOID Buffer)
{
	ULONG i;
	BOOLEAN b = 0;
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
				pInfo->Address = Address;
				pInfo->Buffer = Buffer;
				pInfo->Length = Length;
				pInfo->Type = 0;
				if (NT_SUCCESS(InsertReadWriteProcessMemoryApc(ethrd, pInfo)))
				{
					FREE(pInfo);
					b = 1; break;
				}
			}
		}
	}
	return b;
}

BOOLEAN ForceWriteProcessMemory2(IN PEPROCESS Process, IN PVOID Address, IN UINT32 Length, IN PVOID Buffer)
{
	ULONG i;
	BOOLEAN b = 0;
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
				pInfo->Address = Address;
				pInfo->Buffer = Buffer;
				pInfo->Length = Length;
				pInfo->Type = 1;
				if (NT_SUCCESS(InsertReadWriteProcessMemoryApc(ethrd, pInfo)))
				{
					FREE(pInfo);
					b = 1; break;
				}
			}
		}
	}
	return b;
}

BOOLEAN GetDxfCr3Real(IN PVOID Address, IN UINT32 Length, IN PVOID Buffer)
{
	ULONG i;
	BOOLEAN b = 0;
	PEPROCESS Process = GetProcessByName((UCHAR*)"dnf.exe");
	if (Process == NULL)
		return FALSE;

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
				pInfo->Address = Address;
				pInfo->Buffer = Buffer;
				pInfo->Length = Length;
				pInfo->Type = 1;
				if (NT_SUCCESS(InsertGetDxfRealCr3Apc(ethrd, pInfo)))
				{
					FREE(pInfo);
					b = 1; break;
				}
			}
		}
	}
	return b;
}


BOOLEAN threeS(IN PVOID Address, IN UINT32 Length, IN PVOID Buffer)
{
	ULONG i;
	BOOLEAN b = 0;
	PEPROCESS Process = GetProcessByName((UCHAR*)"dnf.exe");
	if (Process == NULL)
		return FALSE;

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
				pInfo->Address = Address;
				pInfo->Buffer = Buffer;
				pInfo->Length = Length;
				pInfo->Type = 1;
				if (NT_SUCCESS(InsertThreeSApc(ethrd, pInfo)))
				{
					FREE(pInfo);
					b = 1; break;
				}
			}
		}
	}
	return b;
}

BOOLEAN RestoreDate(IN PVOID Address, IN UINT32 Length, IN PVOID Buffer)
{
	ULONG i;
	BOOLEAN b = 0;
	PEPROCESS Process = GetProcessByName((UCHAR*)"dnf.exe");
	if (Process == NULL)
		return FALSE;

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
				pInfo->Address = Address;
				pInfo->Buffer = Buffer;
				pInfo->Length = Length;
				pInfo->Type = 1;
				if (NT_SUCCESS(InsertRestoreDateApc(ethrd, pInfo)))
				{
					FREE(pInfo);
					b = 1; break;
				}
			}
		}
	}
	return b;
}

ULONG64 GetDxfCr3Fake() 
{
	PEPROCESS Process = GetProcessByName((UCHAR*)"dnf.exe");
	if (Process != NULL)
	{
		return *(PULONG64)((ULONG64)Process + 0x28);
	}
	else
		return 0;
	
}