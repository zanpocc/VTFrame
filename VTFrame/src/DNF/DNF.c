#include "DNF.h"

//Global
//装备对象
ULONG EquipObj = 0;
//无敌偏移处原始值
ULONG oldInvincibleValue = 0;
//顺图函数地址
pShunTu = 0;
//物品栏2设计图对象
ULONG LayoutObj = 0;
ULONG oldLayoutValue = 0;

UCHAR shellcode[50] =
"\x60"							//pushad
"\x8B\x0D\xA0\x71\x3C\x04"		//mov ecx,[043C71A8-8]
"\x8B\x89\x28\xA0\x20\x00"		//mov ecx,[ecx+0020A028]
"\x8B\x89\x8C\x00\x00\x00"		//mov ecx,[ecx+8C]
"\x6A\xFF"						//push -1
"\x6A\xFF"						//push -1
"\x6A\x00"						//push 0
"\x6A\x00"						//push 0
"\x6A\x00"						//push 0
"\x6A\x00"						//push 0
"\x6A\x00"						//push 0
"\x6A\x00"						//push 0  0是左1是右上是2下是3
"\xB8\x00\xBA\x1D\x01"			//mov eax,011DBA00
"\xFF\xD0"						//call eax
"\x61"							//popad
"\xC3"							//ret
;

UCHAR shellcode1[50] =
"\xB8\x00\x01\x10\x00"		//mov eax,0x100100
"\xC7\x00\x99\x99\x99\x99"
"\xC3"; //mov dword ptr ds[eax],0x99999999

//武器冰冻
VOID Function1()
{
	/*
	400600=0                         F2
	0代表冰冻=0
	400600+4 Y轴 数据  50            F2
	400600+8 x轴 数据  1500          F2
	400600+c 冰冻频率  300	         F2
	400600+10 持续时间 200           F2
	400600+14 冰冻几率 99            F2
	400600+18 冰冻等级 100           F2
	400600+1c 冰冻伤害 200W          F2
	*/

	//空白地址
	PULONG base = (PULONG)0x100100;
	//0冰冻  1骷髅
	*base = 0;
	//Y轴范围
	*(base + 1) = 999;
	//X轴范围
	*(base + 2) = 999;
	//频率10010c
	*(base + 3) = 99;
	//时间
	*(base + 4) = 9999;
	//几率
	*(base + 5) = 99;
	//冰冻等级
	*(base + 6) = 99;
	//伤害
	*(base + 7) = 999989;

	//第一次保存武器对象的地址和武器对象冰冻开始结束偏移处的值
	if (EquipObj == 0)
	{
		EquipObj = (*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)RoleBase) + GoodsOffset)) + PackOffset)) + GoodOne));
	}
	
	*(PULONG)(EquipObj + FrozenBegOffset) = 0x00100100;
	*(PULONG)(EquipObj + FrozenEndOffset) = 0x00100120;
}

//恢复冰冻
VOID Function2()
{
	//把空白处内存清空
	RtlZeroMemory((PVOID)0x100100,32);

	//武器对象有值
	if (EquipObj != 0)
	{
		//恢复原来的值
		*(PULONG)(EquipObj + FrozenBegOffset) = 0;
		*(PULONG)(EquipObj + FrozenEndOffset) = 0;
		//将武器对象设置为空
		EquipObj = 0;
	}

}

//3S评分
VOID Function3()
{
	*(PULONG)((*(PULONG)ScoreBase) + ScoreOffset) = (ULONG)ScoreValue;
}


//无敌霸体
VOID Function4() 
{
	if (oldInvincibleValue == 0)
	{
		oldInvincibleValue = *(PULONG)((*(PULONG)RoleBase) + InvincibleOffset);
		*(PULONG)((*(PULONG)RoleBase) + InvincibleOffset) = 100;
		*(PULONG)((*(PULONG)RoleBase) + btpianyi) = 1;
	}
	
}

//取消无敌
VOID Function5()
{
	if (oldInvincibleValue != 0)
	{
		*(PULONG)((*(PULONG)RoleBase) + InvincibleOffset) = oldInvincibleValue;
		*(PULONG)((*(PULONG)RoleBase) + btpianyi) = 0;
		oldInvincibleValue = 0;
	}
	
}
//物品栏2设计图召唤人偶
VOID Function6()
{
	PULONG base = 0x400600;
	//人偶代码
	*base = 36405;
	//人偶等级
	*(base + 1) = 90;
	//人偶等级
	*(base + 2) = 90;
	//存在时间
	*(base + 3) = 100000;

	//拿到设计图对象
	if (LayoutObj == 0)
	{
		LayoutObj = (*(PULONG)((*(PULONG)((*(PULONG)((*(PULONG)RoleBase) + GoodsOffset)) + PackOffset)) + GoodTwo));
		oldLayoutValue = *(PULONG)(LayoutObj + 0x000004B8);
	}

	*(PULONG)(LayoutObj + 0x000004B8) = 0x400600;

}

//恢复
VOID Function7()
{
	PULONG base = 0x400600;
	RtlZeroMemory(base,16);

	//拿到设计图对象
	if (LayoutObj != 0)
	{
		*(PULONG)(LayoutObj + 0x000004B8) = oldLayoutValue;
		LayoutObj = 0;
	}

}



VOID AllocateMem() 
{
	PVOID pMem = NULL;
	SIZE_T len = 0x1000;
	NTSTATUS st;
	
	st = ZwAllocateVirtualMemory(NtCurrentProcess(), &pMem, 0, &len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NT_SUCCESS(st))
	{
		DbgPrint("申请虚拟内存成功:%llx\n",pMem);
		//拷贝shell code到我们申请的内存
		ULONG p = (ULONG)pMem + 0x100;
		RtlCopyMemory(&shellcode1[1],&p,4);
		RtlCopyMemory(pMem,shellcode1,50);
		pShunTu = pMem;
	}
	else
	{
		DbgPrint("申请内存失败\n");
		DbgPrint("错误码:%x\n", st);
	}
	
}

VOID StartThread() 
{
	NTSTATUS st;
	HANDLE hThread = 0;
	OBJECT_ATTRIBUTES att = { 0 };

	InitializeObjectAttributes(&att, NULL, OBJ_KERNEL_HANDLE, 0, 0);

	st = ZwCreateThreadEx(&hThread, 0x1F03FF, &att, NtCurrentProcess(), (ULONG64)pShunTu, 0, 0, 0, 0, 0, 0);

	if (NT_SUCCESS(st))
	{
		DbgPrint("ZwCreateThreadEx成功\n");
		ZwClose(hThread);
		DbgPrint("0x100100:%x\n",*(PULONG)0x100100);
	}
	else
	{
		DbgPrint("ZwCreateThreadEx失败:%x\n", st);
		ZwClose(hThread);
	}
}

typedef union _Alertable
{
	ULONG All;
	struct
	{
		ULONG a : 5; //0-4 
		ULONG b : 1; //5
		ULONG c : 26;
	}u;
}Alertable,*PAlertable;

#define DELAY_ONE_MICROSECOND (-10)
#define DELAY_ONE_MILLISECOND (DELAY_ONE_MICROSECOND*1000)
VOID MySleep(LONG msec)
{
	LARGE_INTEGER my_interval;
	my_interval.QuadPart = DELAY_ONE_MILLISECOND;
	my_interval.QuadPart *= msec;
	KeDelayExecutionThread(KernelMode, 1, &my_interval);
}

VOID SetThreadAlertable()
{
	
	/*Alertable a = { 0 };
	PETHREAD thread = PsGetCurrentThread();
	
	a.All = *(PULONG)((ULONG64)thread + 0x4c);
	DbgPrint("原始:%d\n",a.u.b);
	a.u.b = 1;
	*(PULONG)((ULONG64)thread + 0x4c) = a.All;
	DbgPrint("修改后:%d\n", a.u.b);*/
	MySleep(500);
}