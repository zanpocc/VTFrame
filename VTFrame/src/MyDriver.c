#include <ntddk.h>
#include "VMX/VMX.h"
#include "Test/Test.h"
#include "Monitor/Monitor.h"
#include "Include/DriverDef.h"
#include "IDT/idt.h"

VOID Unload(PDRIVER_OBJECT DriverObject);


//让驱动可以创建回调
VOID BypassCheckSign(PDRIVER_OBJECT pDriverObj)
{
	//STRUCT FOR WIN64
	typedef struct _LDR_DATA                         			// 24 elements, 0xE0 bytes (sizeof)
	{
		struct _LIST_ENTRY InLoadOrderLinks;                     // 2 elements, 0x10 bytes (sizeof)
		struct _LIST_ENTRY InMemoryOrderLinks;                   // 2 elements, 0x10 bytes (sizeof)
		struct _LIST_ENTRY InInitializationOrderLinks;           // 2 elements, 0x10 bytes (sizeof)
		VOID*        DllBase;
		VOID*        EntryPoint;
		ULONG32      SizeOfImage;
		UINT8        _PADDING0_[0x4];
		struct _UNICODE_STRING FullDllName;                      // 3 elements, 0x10 bytes (sizeof)
		struct _UNICODE_STRING BaseDllName;                      // 3 elements, 0x10 bytes (sizeof)
		ULONG32      Flags;
	}LDR_DATA, *PLDR_DATA;
	PLDR_DATA ldr;
	ldr = (PLDR_DATA)(pDriverObj->DriverSection);
	ldr->Flags |= 0x20;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;

	// 查询硬件是否支持VT
	if (!IsVTSupport())
		return STATUS_UNSUCCESSFUL;

	// 申请全局变量的内存
	if (!AllocGlobalMemory())
		return STATUS_UNSUCCESSFUL;

	// 开启VT主要代码
	if (!StartVT())
		return STATUS_UNSUCCESSFUL;

	// 是否开启VT成功
	for (int i = 0; i <= (g_data->vcpus - 1); i++)
	{
		if (g_data->cpu_data[i].VmxState == VMX_STATE_ON)
			DbgPrint("VTFrame:CPU:%d开启VT成功\n", i);
	}

	
	TestSSDTHook();
	TestPageHook();

	//符号链接
	status = CreateDeviceAndSymbol(DriverObject);
	if (!NT_SUCCESS(status))
		return status;

	//IRP
	DriverObject->MajorFunction[IRP_MJ_CREATE] = CREATE_DISPATCH;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DEVICE_CONTROL_DISPATCH;
	DriverObject->DriverUnload = Unload;
	

	return status;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	//卸载流程，先在DPC例程中调用VMCALL执行__vmx_off和一些寄存器的处理，接着释放申请的内存
	// 此处也使用了KeSetSystemAffinityThread函数，不同时卸载,而是依次卸载
	//removeMonitor();
	//UnloadTest();
	//removeDriverMonitor();
	//removeProcessMonitor();

	for (int i = 0; i < KeNumberProcessors; i++)
	{
		KeSetSystemAffinityThread((KAFFINITY)(1 << i));

		SetupVT(NULL);

		KeRevertToUserAffinityThread();
	}

	FreeGlobalData(g_data);
	DeleteDeviceAndSymbol();
	DbgPrint("VTFrame:卸载VT成功\n");
	DbgPrint("VTFrame:Driver Unload\n");
}