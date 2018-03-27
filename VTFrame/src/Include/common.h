#pragma once
#include <ntddk.h>

#include "Native.h"

/************************************************************************/
/* 此文件主要存放一些全局数据结构和常量定义                                                                     */
/************************************************************************/

#define DPRINT(format, ...)         DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
//#define DPRINT(format, ...)        
#define VF_POOL_TAG                '0mVZ'


/************************************************************************/
/* VMCALL的索引                                                         */
/************************************************************************/
#define VTFrame_UNLOAD            0x1//卸载VT
#define VTFrame_HOOK_LSTAR        0x2//HOOK SysCall
#define VTFrame_UNHOOK_LSTAR      0x3//UNHOOK SysCall
#define VTFrame_HOOK_PAGE         0x4//页异常HOOK
#define VTFrame_UNHOOK_PAGE       0x5//页异常UNHOOK
#define VTFrame_Test			  0x6//测试
#define VTFrame_Test2			  0x7//测试



//BUG
#define BUG_CHECK_UNSPECIFIED       0
#define BUG_CHECK_INVALID_VM        1
#define BUG_CHECK_TRIPLE_FAULT      2
#define BUG_CHECK_EPT_MISCONFIG     3
#define BUG_CHECK_EPT_VIOLATION     4
#define BUG_CHECK_EPT_NO_PAGES      5

//当前CPU的ID
#define CPU_IDX                     (KeGetCurrentProcessorNumberEx( NULL ))
//物理地址页帧
#define PFN(addr)                   (ULONG64)((addr) >> PAGE_SHIFT)


/************************************************************************/
/* CPU开启VT的状态                                                      */
/************************************************************************/
typedef enum _VCPU_VMX_STATE
{
	VMX_STATE_OFF = 0,   //未虚拟化
	VMX_STATE_TRANSITION = 1,   //虚拟化中，还未恢复上下文
	VMX_STATE_ON = 2    //虚拟化成功
} VCPU_VMX_STATE;



/************************************************************************/
/* VMCS和VMXON区域结构体                                                */
/************************************************************************/
typedef struct _VMX_VMCS
{
	ULONG RevisionId;//版本标识
	ULONG AbortIndicator;
	UCHAR Data[PAGE_SIZE - 2 * sizeof(ULONG)];	//4KB大小
} VMX_VMCS, *PVMX_VMCS;



typedef struct _VMX_FEATURES
{
	ULONG64 SecondaryControls : 1;  // Secondary controls are enabled
	ULONG64 TrueMSRs : 1;           // True VMX MSR values are supported
	ULONG64 EPT : 1;                // EPT supported by CPU
	ULONG64 VPID : 1;               // VPID supported by CPU
	ULONG64 ExecOnlyEPT : 1;        // EPT translation with execute-only access is supported
	ULONG64 InvSingleAddress : 1;   // IVVPID for single address
	ULONG64 VMFUNC : 1;             // VMFUNC is supported
} VMX_FEATURES, *PVMX_FEATURES;




/************************************************************************/
/* 关键的一个数据结构，里面是每个逻辑CPU的VMCS表填写需要内容            */
/************************************************************************/
typedef struct _VCPU
{
	KPROCESSOR_STATE HostState;             // 在进行虚拟化之前主机的状态域，包括一些通用寄存器和特殊寄存器
	volatile VCPU_VMX_STATE VmxState;       // CPU的VMX开启状态,分为三个：1.off未开启  2.transition开启中 3.on开启成功
	ULONG64 SystemDirectoryTableBase;       // 这个要不要无所谓,同样是为了兼容...懒得改
	PVMX_VMCS VMXON;                        // VMXON region
	PVMX_VMCS VMCS;                         // VMCS region
	PVOID VMMStack;                         // VMM的栈内存区
	ULONG64 *ept_PML4T;						// EPT页表
	ULONG64 OriginalLSTAR;                  // 原来的系统调用入口
	ULONG64 TpHookSTAR;						//TPHook的系统调用入口
} VCPU, *PVCPU;

/************************************************************************/
/*                                                                      */
/************************************************************************/
typedef struct _GLOBAL_DATA
{
	LONG vcpus;                             //虚拟CPU的个数
	PUCHAR MSRBitmap;
	VCPU cpu_data[ANYSIZE_ARRAY];           //每个CPU的VT结构,这里是个数组，有几个CPU就有几个VCPU结构
} GLOBAL_DATA, *PGLOBAL_DATA;

extern PGLOBAL_DATA g_Data;

