#include "Monitor.h"

#include "../VMX/VMX.h"
#include "../Test/Test.h"
#include "../IDT/idt.h"

VOID MonitorDriverLoad(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,                // pid into which image is being mapped
	_In_ PIMAGE_INFO ImageInfo
) 
{
	//驱动加载
	if (ProcessId == 0)
	{
		
		//如果TP加载就开启我们的VT
		if (wcsstr(FullImageName->Buffer,L"TesSafe.sys") != NULL)
		{
			DbgPrint("检测到TP加载\n");	
			// 开启VT主要代码
			if (!StartVT())
				return ;

			// 是否开启VT成功
			for (int i = 0;i<=(g_data->vcpus-1);i++)
			{
				if (g_data->cpu_data[i].VmxState == VMX_STATE_ON)
				{
					DbgPrint("VTFrame:CPU:%d开启VT成功\n", i);
				}
			}
			//开启SSDT HOOK
			/*PrintIdt();
			TestPageHook();
			TestSSDTHook();*/
			

		}
	}
	
}


NTSTATUS addDriverMonitor()
{
	return PsSetLoadImageNotifyRoutine(MonitorDriverLoad);
}

NTSTATUS removeDriverMonitor()
{
	return PsRemoveLoadImageNotifyRoutine(MonitorDriverLoad);
}
