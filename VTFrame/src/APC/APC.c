#include "APC.h"
#include "../Hook/PageHook.h"
#include "../Include/common.h"

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
		ULONG temp = *(ULONG*)0x00400000;
		((PFUNCTION)pInfo->fun)(pInfo);
	}
	__except (1)
	{
		DbgPrint("错误的内存访问异常\n");;
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
					ret = pInfo->ret;
					break;
				}
			}
		}
	}
	return ret;
}


VOID Function()
{
	//自动拾取物品
	PVOID add1 = (PVOID)0x023159F7;
	UCHAR code1[2] = "\x90\x90";
	

	//拾取范围
	PVOID add2 = (PVOID)0x023159C5;
	UCHAR code2[6] = "\x90\x90\x90\x90\x90\x90";
	ModifyAddressValue2(add2,  code2, 6,add1,code1,2);

	

	////技能无CD
	//PVOID add3 = (PVOID)0x0227BE86;
	//UCHAR code3[1] = "\xEB";
	//ModifyAddressValue(add3, code3, 1);
	
}

//卡邮件
VOID Function1()
{
	//鼠标基址
	PVOID base = 0x04DF7CEC;
	//修改物品代码为断念剑
	*(PULONG)(*(PULONG)base + 0x20) = 101010047;
}

typedef union _FLOAT
{
	ULONG32 All;
	struct
	{
		ULONG32 sig : 1;
		ULONG32 integer : 8;    
		ULONG32 xiaoshu : 23;
		
	} Fields;
} FLOAT, *PFLOAT;

VOID Function2()
{
	
	//人物基址
	PVOID base = 0x04DCD598;

	//得到物品栏1装备B94结构地址
	ULONG B94 = ((*(PULONG)((*(PULONG)((*(PULONG)(*(PULONG)base + 0x6324)) + 0x58)) + 0xc))+0xb94);
	
	/*PFLOAT p1 = (PFLOAT)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94) + 0x18)) + 0x4)) + 0x18)) + 0x4);
	PFLOAT p2 = (PFLOAT)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94) + 0x18)) + 0x4)) + 0x40)) + 0x8);
	PFLOAT p3 = (PFLOAT)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94) + 0x18)) + 0x4)) + 0x4)) + 0x4);
	PFLOAT p4 = (PFLOAT)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94) + 0x18)) + 0x4)) + 0x54)) + 0xc);
	PFLOAT p5 = (PFLOAT)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94) + 0x18)) + 0x4)) + 0x54)) + 0x4);
	PFLOAT p6 = (PFLOAT)((*(PULONG)((*(PULONG)((*(PULONG)B94) + 0x4)) + 0x4)) + 0x0);

	DbgPrint("几率:%d\n", *(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94) + 0x18)) + 0x4)) + 0x18)) + 0x4));
	DbgPrint("存在时间:%d\n", *(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94) + 0x18)) + 0x4)) + 0x40)) + 0x8));
	DbgPrint("全屏:%d\n", *(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94) + 0x18)) + 0x4)) + 0x4)) + 0x4));
	DbgPrint("伤害:%d\n", *(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94) + 0x18)) + 0x4)) + 0x54)) + 0xc));
	DbgPrint("异常类型:%d\n", *(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94) + 0x18)) + 0x4)) + 0x54)) + 0x4));
	DbgPrint("触发方式:%d\n", (*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94) + 0x4)) + 0x4)) + 0x0)));
*/
	//得到自身武器B94结构地址
	PVOID B94_Self = ((*(PULONG)((*(PULONG)base) + 0x3110)) + 0xb94);


	DbgPrint("自身装备B94地址:%llx\n",B94_Self);
	DbgPrint("function address:%llx\n", Function2);

	

	UCHAR code[10] = { 0 };
	RtlCopyMemory(code, B94,10);
	
	ModifyAddressValue(B94_Self, code, 10);

	//99
	*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94_Self) + 0x18)) + 0x4)) + 0x18)) + 0x4) = 1120272384;
	//5000
	*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94_Self) + 0x18)) + 0x4)) + 0x40)) + 0x8) = 1161527296;
	//4
	*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94_Self) + 0x18)) + 0x4)) + 0x4)) + 0x4) = 1082130432;
	//1000000	1232348160一百万	1259902592一千万	九千万1286318416
	*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94_Self) + 0x18)) + 0x4)) + 0x54)) + 0xc) = 1286318416;
	//2毒1073741824 1冰1065353216	11出血
	*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94_Self) + 0x18)) + 0x4)) + 0x54)) + 0x4) = 1073741824;
	//20打怪 22自动1102053376
	(*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94_Self) + 0x4)) + 0x4)) + 0x0)) = 22;


	//写入我们自己的武器
	//RtlCopyMemory(B94_Self, B94,10);

	///*
	//触发几率 +18+4+18+4
	//存在时间 +18+4+40+8
	//全屏 +18+4+4+4
	//伤害	 +18+4+54+c
	//异常类型  +18+4+54+4
	//触发方式  +4+4+0
	//*/

}

//3S评分
VOID Function3()
{
	*(PULONG)((*(PULONG)0x04CD511C) + 0xc0c) = (ULONG)21546666;
}

//怪物猎杀者重组
VOID Function4()
{

	//人物基址
	PVOID base = 0x04DCD598;
	//空白地址
	PVOID kbadd = 0x400550;

	//7异常	17技能 float
	*(PULONG)kbadd = 0x0;
	//2个技能或者生效
	*(PULONG)((ULONG)kbadd+0x4) = 0x0;
	//技能代码
	*(PULONG)((ULONG)kbadd + 0x8) = 0x0;
	//伤害
	*(PULONG)((ULONG)kbadd + 0x18) = 0x0;
	//伤害
	*(PULONG)((ULONG)kbadd + 0x24) = 0x0;

	//怪物猎杀者B94结构
	PVOID B94_Self = ((*(PULONG)((*(PULONG)base) + 0x311c)) + 0xb94);



	//99几率
	*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94_Self) + 0x18)) + 0x4)) + 0x18)) + 0x4) = 1120272384;
	//5000存在时间
	*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94_Self) + 0x18)) + 0x4)) + 0x40)) + 0x8) = 1161527296;
	//4全屏
	*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94_Self) + 0x18)) + 0x4)) + 0x4)) + 0x4) = 1082130432;
	//20打怪 22自动1102053376
	(*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94_Self) + 0x4)) + 0x4)) + 0x0)) = 22;
	//频率	600
	(*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94_Self) + 0x4)) + 0x4)) + 0x4)) = 22;


	*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94_Self) + 0x18)) + 0x4)) + 0x18)) + 0x4) = 1120272384;
	*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94_Self) + 0x18)) + 0x4)) + 0x18)) + 0x4) = 1120272384;


	//1000000	1232348160一百万	1259902592一千万	九千万1286318416
	*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94_Self) + 0x18)) + 0x4)) + 0x54)) + 0xc) = 1286318416;
	//2毒1073741824 1冰1065353216	11出血
	*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)B94_Self) + 0x18)) + 0x4)) + 0x54)) + 0x4) = 1073741824;
	

}