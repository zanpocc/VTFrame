#include "SysCallHook.h"

#include "../Include/Native.h"
#include "../Include/CPU.H"
#include "../VMX/VMX.h"



ULONG64 GetKiSystemServiceCopyEndaddress64()
{
	//搜索系统调用入口
	PUCHAR StarAddress = (PUCHAR)__readmsr(0xc0000082);
	PUCHAR EndAddress = StarAddress + 0x1000;

	PUCHAR i = NULL;
	UCHAR b1, b2, b3;
	ULONG temp;
	ULONG64 addr;

	// F7 05 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? 0F 85 ? ? ? ? ? ? ? ? 41 FF D2
	for (i = StarAddress; i < EndAddress; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) /*&& MmIsAddressValid(i + 18)*/)
		{
			b1 = *i;
			b2 = *(i + 1);

			if (b1 == 0xF7 && b2 == 0x05)
			{
				addr = (ULONG64)i;
				return addr;
			}
		}

	}
	return 0;
}

VOID InitSysCallHook()
{
	// 清空数组元素
	RtlZeroMemory(HookEnabled,0x1000);
	RtlZeroMemory(ArgTble, 0x1000);
	RtlZeroMemory(HookTable, 0x1000*8);

	// 获取原系统调用地址
	KiSystemCall64Ptr = 0;
	KiSystemCall64Ptr = __readmsr(MSR_LSTAR);

	// 获取KiSystemServiceCopyEnd地址,这个地址会在我们自定义的系统调用中用到.见系统调用分析
	KiServiceCopyEndPtr = 0;
	KiServiceCopyEndPtr = GetKiSystemServiceCopyEndaddress64();

	for (int i = 0; i < KeNumberProcessors; i++)
	{
		KeSetSystemAffinityThread((KAFFINITY)(1 << i));//00000000 00000001 00000010 00000100 

		__vmx_vmcall(HYPERCALL_HOOK_LSTAR,KiSystemCall64Ptr,0,0);

		KeRevertToUserAffinityThread();
	}

	for (int i = 0; i <= (g_data->vcpus-1); i++)
	{
		if (g_data->cpu_data[i].OriginalLSTAR != 0)
		{
			DbgPrint("VTFrame:CPU:%d开启系统调用HOOK成功\n", i);
		}
	}
}

//VMCALL指令陷入VMM中，将系统调用入口设置为原来的
VOID UnHookSysCall()
{
	for (int i = 0; i < KeNumberProcessors; i++)
	{
		KeSetSystemAffinityThread((KAFFINITY)(1 << i));//00000000 00000001 00000010 00000100 

		__vmx_vmcall(HYPERCALL_UNHOOK_LSTAR, 0, 0, 0);

		KeRevertToUserAffinityThread();
	}
}

//此函数用来添加HOOK,此函数调用前必须开启系统调用HOOK,否则没有效果
//index表示你想HOOK的函数在SSDT表中的索引
//pNewFunc表示你的HOOK函数地址
//ParameterNum表示你想HOOK函数的参数个数
VOID AddSSDTHook(ULONG index,PVOID pNewFunc, CHAR ParameterNum)
{
	InterlockedExchange64((PLONG64)&HookTable[index], (LONG64)pNewFunc);
	InterlockedExchange8(&ArgTble[index], ParameterNum);
	InterlockedExchange8(&HookEnabled[index], TRUE);
}