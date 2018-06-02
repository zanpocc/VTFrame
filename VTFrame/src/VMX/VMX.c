#include "VMX.h"

#include "../Include/CPU.h"
#include "../Include/Native.h"
#include "../Include/VMCS.h"
#include "vtasm.h"
#include "ept.h"
#include "VmxEvent.h"

//关键的数据结构指针，有每个CPU的VCPU结构和CPU个数
PGLOBAL_DATA g_data = NULL;


NTSTATUS UtilProtectNonpagedMemory(IN PVOID ptr, IN ULONG64 size, IN ULONG protection)
{
	NTSTATUS status = STATUS_SUCCESS;
	PMDL pMdl = IoAllocateMdl(ptr, (ULONG)size, FALSE, FALSE, NULL);
	if (pMdl)
	{
		MmBuildMdlForNonPagedPool(pMdl);
		pMdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;
		status = MmProtectMdlSystemAddress(pMdl, protection);
		IoFreeMdl(pMdl);
		return status;
	}

	return STATUS_UNSUCCESSFUL;
}


VOID VmxpConvertGdtEntry(IN PVOID GdtBase, IN USHORT Selector, OUT PVMX_GDTENTRY64 VmxGdtEntry)
{
	PKGDTENTRY64 gdtEntry = NULL;

	// Read the GDT entry at the given selector, masking out the RPL bits. x64
	// Windows does not use an LDT for these selectors in kernel, so the TI bit
	// should never be set.
	NT_ASSERT((Selector & SELECTOR_TABLE_INDEX) == 0);
	gdtEntry = (PKGDTENTRY64)((ULONG_PTR)GdtBase + (Selector & ~RPL_MASK));

	// Write the selector directly 
	VmxGdtEntry->Selector = Selector;

	// Use the LSL intrinsic to read the segment limit
	VmxGdtEntry->Limit = __segmentlimit(Selector);

	// Build the full 64-bit effective address, keeping in mind that only when
	// the System bit is unset, should this be done.
	//
	// NOTE: The Windows definition of KGDTENTRY64 is WRONG. The "System" field
	// is incorrectly defined at the position of where the AVL bit should be.
	// The actual location of the SYSTEM bit is encoded as the highest bit in
	// the "Type" field.
	VmxGdtEntry->Base = ((gdtEntry->Bytes.BaseHigh << 24) | (gdtEntry->Bytes.BaseMiddle << 16) | (gdtEntry->BaseLow)) & MAXULONG;
	VmxGdtEntry->Base |= ((gdtEntry->Bits.Type & 0x10) == 0) ? ((ULONG_PTR)gdtEntry->BaseUpper << 32) : 0;

	// Load the access rights
	VmxGdtEntry->AccessRights = 0;
	VmxGdtEntry->Bytes.Flags1 = gdtEntry->Bytes.Flags1;
	VmxGdtEntry->Bytes.Flags2 = gdtEntry->Bytes.Flags2;

	// Finally, handle the VMX-specific bits
	VmxGdtEntry->Bits.Reserved = 0;
	VmxGdtEntry->Bits.Unusable = !gdtEntry->Bits.Present;
}


ULONG VmxpAdjustMsr(IN LARGE_INTEGER ControlValue, ULONG DesiredValue)
{
	// VMX feature/capability MSRs encode the "must be 0" bits in the high word
	// of their value, and the "must be 1" bits in the low word of their value.
	// Adjust any requested capability/feature based on these requirements.
	DesiredValue &= ControlValue.HighPart;
	DesiredValue |= ControlValue.LowPart;
	return DesiredValue;
}


/************************************************************************/
/* 判断处理器硬件是否支持VT：1.处理器是否是Intel处理器，2.处理器是否支持VT  3.是否BIOS上关闭了VT功能 
                             4.处理器是否支持TRUE系列MSR寄存器*/
/************************************************************************/
BOOLEAN IsVTSupport()
{
	
	CPUID data = { 0 };
	char vendor[0x20] = { 0 };
	__cpuid((int*)&data, 0);
	*(int*)(vendor) = data.ebx;
	*(int*)(vendor + 4) = data.edx;
	*(int*)(vendor + 8) = data.ecx;



	//如果CPU不是Intel的，直接返回失败
	if (!memcmp(vendor, "GenuineIntel", 12) == 0) {
		DbgPrint("不是Intel CPU\n");
		return FALSE;
	}
		

	RtlZeroMemory(&data,sizeof(CPUID));

	//如果CPU不支持VT，返回失败
	__cpuid((int*)&data, 1);
	if ((data.ecx & (1 << 5)) == 0) {
		DbgPrint("CPU不支持VT\n");
		DbgPrint("cpuid 1:%x", data.ecx);
		return FALSE;
	}
	//DbgPrint("cpuid 1:%x", data.ecx);

	IA32_FEATURE_CONTROL_MSR Control = { 0 };
	Control.All = __readmsr(MSR_IA32_FEATURE_CONTROL);
	//DbgPrint("MSR_IA32_FEATURE_CONTROL:%lx", Control.All);
	//如果在BIOS上禁用VT，返回失败
	if (Control.Fields.Lock == 0)
	{
		Control.Fields.Lock = TRUE;
		Control.Fields.EnableVmxon = TRUE;
		__writemsr(MSR_IA32_FEATURE_CONTROL, Control.All);
	}
	else if (Control.Fields.EnableVmxon == FALSE)
	{
		DbgPrint("VTFrame:在BIOS未开启VMX\n");
		return FALSE;
	}

	//如果CPU不支持TRUE系列MSR寄存器，后续代码无意义，因为我们后面VMCS填充的某些结构是从TRUE系列MSR上获取的
	IA32_VMX_BASIC_MSR base;
	base.All = __readmsr(MSR_IA32_VMX_BASIC);
	if (base.Fields.VmxCapabilityHint != 1)
	{
		DbgPrint("VTFrame:此CPU不支持True系列寄存器\n");
		return FALSE;
	}

	DbgPrint("VTFrame:CPU支持VT\n");

	return TRUE;
}


/*
主要的对VMM中的虚拟机的控制就在这里,此处开启控制,具体的处理则在ExitHandle中
此处开启了对应的功能,就必须在ExitHandle中进行处理,不然则会导致蓝屏死机.
*/
VOID VmxSetupVMCS(IN PVCPU Vcpu)
{
	PKPROCESSOR_STATE state = &Vcpu->HostState;
	VMX_GDTENTRY64 vmxGdtEntry = { 0 };
	VMX_VM_ENTER_CONTROLS vmEnterCtlRequested = { 0 };
	VMX_VM_EXIT_CONTROLS vmExitCtlRequested = { 0 };
	VMX_PIN_BASED_CONTROLS vmPinCtlRequested = { 0 };
	VMX_CPU_BASED_CONTROLS vmCpuCtlRequested = { 0 };
	VMX_SECONDARY_CPU_BASED_CONTROLS vmCpuCtl2Requested = { 0 };
	LARGE_INTEGER msrVmxPin = { 0 }, msrVmxCpu = { 0 }, msrVmxEntry = { 0 }, msrVmxExit = { 0 }, msrVmxSec = {0};

	//读取VMX相关MSR寄存器，获得CPU支持的功能，如果我们设置的功能CPU不支持的，就必须按照CPU的要求来

	//下面两个是VM运行控制域的PIN和PROCESS字段
	msrVmxPin.QuadPart = __readmsr(MSR_IA32_VMX_TRUE_PINBASED_CTLS);
	msrVmxCpu.QuadPart = __readmsr(MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
	//cpu secondary
	msrVmxSec.QuadPart = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
	//VM Exit
	msrVmxExit.QuadPart = __readmsr(MSR_IA32_VMX_TRUE_EXIT_CTLS);
	//VM Entry
	msrVmxEntry.QuadPart = __readmsr(MSR_IA32_VMX_TRUE_ENTRY_CTLS);
	
	
	/////////////////////////////////////////////////////////////////////////////////////////////
	////////////////虽然VMCS大部分的内容,我们都可以从MSR中读取,但是我们想要实现某些功能,还是需要自己修改开启
	////////////////以下代码则是开启功能,有些为必须,有些则是我们定制的功能,修改完后,再将其写入到VMCS区域中

	//首要的CPU控制
	vmCpuCtlRequested.Fields.CR3LoadExiting = TRUE;//在写入CR3时发生VM-EXIT
	//vmCpuCtlRequested.Fields.CR3StoreExiting = TRUE;//在读取CR3时发生VM-EXIT
	vmCpuCtlRequested.Fields.ActivateSecondaryControl = TRUE;//开启次要的CPU控制
    vmCpuCtlRequested.Fields.UseMSRBitmaps = TRUE;//启用MSR BitMap功能
	vmCpuCtlRequested.Fields.MovDRExiting = TRUE;//对DR寄存器的操作发生VM EXIT
	

	//次要的CPU控制
	vmCpuCtl2Requested.Fields.EnableRDTSCP = TRUE;	// for Win10
	vmCpuCtl2Requested.Fields.EnableXSAVESXSTORS = TRUE;	// for Win10
	vmCpuCtl2Requested.Fields.EnableINVPCID = TRUE;	// for Win10
	//vmCpuCtl2Requested.Fields.EnableVPID = TRUE;	

	//进入虚拟机控制
	vmEnterCtlRequested.Fields.IA32eModeGuest = TRUE;//只有为TRUE时，VM ENTRY才能进入IA32E模式
	vmEnterCtlRequested.Fields.LoadDebugControls = TRUE;	//配合DR

	//退出虚拟机控制
	vmExitCtlRequested.Fields.HostAddressSpaceSize = TRUE;//返回到IA32E模式的HOST中，64位下设置为TRUE
	vmExitCtlRequested.Fields.AcknowledgeInterruptOnExit = TRUE;
	
	//////////////////////////////////////////////////////////////////////////////////////////////
	

	//开启对MSR寄存器的写入监控,不用MSR Bitmap就会监控所有MSR寄存器的读写
	// Load the MSR bitmap. Unlike other bitmaps, not having an MSR bitmap will
	// trap all MSRs, so have to allocate an empty one.
	PUCHAR bitMapReadLow = g_data->MSRBitmap;       // 0x00000000 - 0x00001FFF
	PUCHAR bitMapReadHigh = bitMapReadLow + 1024;   // 0xC0000000 - 0xC0001FFF
	PUCHAR bitMapWriteLow = bitMapReadHigh + 1024;
	PUCHAR bitMapWriteHigh = bitMapWriteLow + 1024;

	RTL_BITMAP bitMapReadLowHeader = { 0 };
	RTL_BITMAP bitMapReadHighHeader = { 0 };
	RTL_BITMAP bitMapWriteLowHeader = { 0 };
	RTL_BITMAP bitMapWriteHighHeader = { 0 };


	RtlInitializeBitMap(&bitMapReadLowHeader, (PULONG)bitMapReadLow, 1024 * 8);
	RtlInitializeBitMap(&bitMapReadHighHeader, (PULONG)bitMapReadHigh, 1024 * 8);
	RtlInitializeBitMap(&bitMapWriteLowHeader, (PULONG)bitMapWriteLow, 1024 * 8);
	RtlInitializeBitMap(&bitMapWriteHighHeader, (PULONG)bitMapWriteHigh, 1024 * 8);

	RtlSetBit(&bitMapReadLowHeader, MSR_IA32_FEATURE_CONTROL);    // MSR_IA32_FEATURE_CONTROL
	RtlSetBit(&bitMapReadLowHeader, MSR_IA32_DEBUGCTL);          // MSR_DEBUGCTL
	RtlSetBit(&bitMapReadHighHeader, MSR_LSTAR - 0xC0000000);     // MSR_LSTAR

	RtlSetBit(&bitMapWriteLowHeader, MSR_IA32_FEATURE_CONTROL);    // MSR_IA32_FEATURE_CONTROL
	RtlSetBit(&bitMapWriteLowHeader, MSR_IA32_DEBUGCTL);          // MSR_DEBUGCTL
	RtlSetBit(&bitMapWriteHighHeader, MSR_LSTAR - 0xC0000000);     // MSR_LSTAR

																  // VMX MSRs
	for (ULONG i = MSR_IA32_VMX_BASIC; i <= MSR_IA32_VMX_VMFUNC; i++)
	{
		RtlSetBit(&bitMapReadLowHeader, i);
		RtlSetBit(&bitMapWriteLowHeader, i);
	}

	__vmx_vmwrite(MSR_BITMAP, MmGetPhysicalAddress(g_data->MSRBitmap).QuadPart);

	//Page faults (exceptions with vector 14) are specially treated. When a page fault occurs, a processor consults 
	//(1) bit 14 of the exception bitmap; 
	//(2) the error code produced with the page fault[PFEC]; 
	//(3) the page - fault error - code mask field[PFEC_MASK]; 
	//and (4) the page - fault error - code match field[PFEC_MATCH].It checks if
	//PFEC & PFEC_MASK = PFEC_MATCH.If there is equality, the specification of bit 14 in the exception bitmap is
	//followed(for example, a VM exit occurs if that bit is set).If there is inequality, the meaning of that bit is
	//reversed(for example, a VM exit occurs if that bit is clear)

	/*
		//要监控异常是需要将这两个字段设置为0的，但是我们申请VMCS内存时已经清零了内存，所以没有设置的字段，默认值都是0，我们也可以不设置
		PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
		PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
	*/

	////转发1号异常
	ULONG ExceptionBitmap = 0;
	ExceptionBitmap |= 1 << 1;
	__vmx_vmwrite(EXCEPTION_BITMAP, ExceptionBitmap);
	

	// If the “VMCS shadowing” VM-execution control is 1, the VMREAD and VMWRITE 
	//instructions access the VMCS referenced by this pointer.Otherwise, software should set
	//this field to FFFFFFFF_FFFFFFFFH to avoid VM - entry failures
	__vmx_vmwrite(VMCS_LINK_POINTER, MAXULONG64);

	//运行控制域
	//Secondary
	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL,
		VmxpAdjustMsr(msrVmxSec, vmCpuCtl2Requested.All)
	);

	//PIN
	__vmx_vmwrite(
		PIN_BASED_VM_EXEC_CONTROL,
		VmxpAdjustMsr(msrVmxPin, vmPinCtlRequested.All)
	);
	//CPU
	__vmx_vmwrite(
		CPU_BASED_VM_EXEC_CONTROL,
		VmxpAdjustMsr(msrVmxCpu, vmCpuCtlRequested.All)
	);
	//VM Exit
	__vmx_vmwrite(
		VM_EXIT_CONTROLS,
		VmxpAdjustMsr(msrVmxExit, vmExitCtlRequested.All)
	);
	//VM Entry
	__vmx_vmwrite(
		VM_ENTRY_CONTROLS,
		VmxpAdjustMsr(msrVmxEntry, vmEnterCtlRequested.All)
	);

	//下面是对Guest和Host的一些寄存器填写

	// CS (Ring 0 Code)
	VmxpConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegCs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_CS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_CS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_CS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_CS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_CS_SELECTOR, state->ContextFrame.SegCs & ~RPL_MASK);

	// SS (Ring 0 Data)
	VmxpConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegSs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_SS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_SS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_SS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_SS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_SS_SELECTOR, state->ContextFrame.SegSs & ~RPL_MASK);

	// DS (Ring 3 Data)
	VmxpConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegDs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_DS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_DS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_DS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_DS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_DS_SELECTOR, state->ContextFrame.SegDs & ~RPL_MASK);

	// ES (Ring 3 Data)
	VmxpConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegEs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_ES_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_ES_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_ES_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_ES_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_ES_SELECTOR, state->ContextFrame.SegEs & ~RPL_MASK);

	// FS (Ring 3 Compatibility-Mode TEB)
	VmxpConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegFs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_FS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_FS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_FS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_FS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_FS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_FS_SELECTOR, state->ContextFrame.SegFs & ~RPL_MASK);

	// GS (Ring 3 Data if in Compatibility-Mode, MSR-based in Long Mode)
	VmxpConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegGs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_GS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_GS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_GS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_GS_BASE, state->SpecialRegisters.MsrGsBase);
	__vmx_vmwrite(HOST_GS_BASE, state->SpecialRegisters.MsrGsBase);
	__vmx_vmwrite(HOST_GS_SELECTOR, state->ContextFrame.SegGs & ~RPL_MASK);

	// Task Register (Ring 0 TSS)
	VmxpConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->SpecialRegisters.Tr, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_TR_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_TR_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_TR_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_TR_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_TR_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_TR_SELECTOR, state->SpecialRegisters.Tr & ~RPL_MASK);

	// LDT
	VmxpConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->SpecialRegisters.Ldtr, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_LDTR_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_LDTR_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_LDTR_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_LDTR_BASE, vmxGdtEntry.Base);

	// GDT
	__vmx_vmwrite(GUEST_GDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Gdtr.Base);
	__vmx_vmwrite(GUEST_GDTR_LIMIT, state->SpecialRegisters.Gdtr.Limit);
	__vmx_vmwrite(HOST_GDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Gdtr.Base);

	// IDT
	__vmx_vmwrite(GUEST_IDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Idtr.Base);
	__vmx_vmwrite(GUEST_IDTR_LIMIT, state->SpecialRegisters.Idtr.Limit);
	__vmx_vmwrite(HOST_IDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Idtr.Base);

	// CR0
	__vmx_vmwrite(CR0_READ_SHADOW, state->SpecialRegisters.Cr0);
	__vmx_vmwrite(HOST_CR0, state->SpecialRegisters.Cr0);
	__vmx_vmwrite(GUEST_CR0, state->SpecialRegisters.Cr0);

	//CR3此处需注意这里填写的是我们开启DPC传入的参数，也就是我们此驱动程序的CR3,这里也可以直接通过__readmsr指令获取,兼容兼容兼容
	__vmx_vmwrite(HOST_CR3,  __readcr3());
	__vmx_vmwrite(GUEST_CR3, __readcr3());

	// CR4
	__vmx_vmwrite(HOST_CR4, state->SpecialRegisters.Cr4);
	__vmx_vmwrite(GUEST_CR4, state->SpecialRegisters.Cr4);
	__vmx_vmwrite(CR4_GUEST_HOST_MASK, 0x2000);
	__vmx_vmwrite(CR4_READ_SHADOW, state->SpecialRegisters.Cr4 & ~0x2000);

	// Debug MSR and DR7
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, state->SpecialRegisters.DebugControl);
	__vmx_vmwrite(GUEST_DR7, state->SpecialRegisters.KernelDr7);


	//下面两行比较关键,一个是VM的入口,一个则是VMM的入口. VM其实就是我们真实的CPU,而VMM则是CPU执行某些指令后会陷入到的处理函数中
	//VM我们并不需要怎么处理,只需要填入相应的信息即可;而VMM我们则需要编写对应处理,如果有误,则很容易导致蓝屏死机的情况

	// 这里是Guest的内容，是我们Native函数保存的上下文信息
	__vmx_vmwrite(GUEST_RSP, state->ContextFrame.Rsp);
	__vmx_vmwrite(GUEST_RIP, state->ContextFrame.Rip);
	__vmx_vmwrite(GUEST_RFLAGS, state->ContextFrame.EFlags);

	
	//VMM的入口和它的堆栈
	NT_ASSERT((KERNEL_STACK_SIZE - sizeof(CONTEXT)) % 16 == 0);
	//
	//__vmx_vmwrite(HOST_RSP, (ULONG_PTR)Vcpu->VMMStack + KERNEL_STACK_SIZE - sizeof(CONTEXT));
	__vmx_vmwrite(HOST_RSP, (ULONG_PTR)Vcpu->VMMStack + KERNEL_STACK_SIZE - sizeof(VOID*)*2);
	__vmx_vmwrite(HOST_RIP, (ULONG_PTR)AsmVmmEntryPoint);
}



/*
虚拟机启动之前,必须使得CPU进入VMX Root模式,才能执行后面的VMX指令
*/
BOOLEAN VmxEnterRoot(IN PVCPU Vcpu)
{
	IA32_VMX_BASIC_MSR pBasic;
	LARGE_INTEGER cr0Fix0 = { 0 }, cr0Fix1 = { 0 }, cr4Fix0 = { 0 }, cr4Fix1 = { 0 };

	//读取各MSR寄存器中的值
	pBasic.All = __readmsr(MSR_IA32_VMX_BASIC);
	cr0Fix0.QuadPart = __readmsr(MSR_IA32_VMX_CR0_FIXED0);
	cr0Fix1.QuadPart = __readmsr(MSR_IA32_VMX_CR0_FIXED1);
	cr4Fix0.QuadPart = __readmsr(MSR_IA32_VMX_CR4_FIXED0);
	cr4Fix1.QuadPart = __readmsr(MSR_IA32_VMX_CR4_FIXED1);

	//获取VT的版本标识赋值给VMCS和VMXON区域,必须做的一步,见VMCS和VMXON内存要求
	Vcpu->VMXON->RevisionId = pBasic.Fields.RevisionIdentifier;
	Vcpu->VMCS->RevisionId = pBasic.Fields.RevisionIdentifier;

	//根据Intel手册的附录，CR0和CR4寄存器中的一些位必须为0和必须为1的要求
	Vcpu->HostState.SpecialRegisters.Cr0 &= cr0Fix1.LowPart;
	Vcpu->HostState.SpecialRegisters.Cr0 |= cr0Fix0.LowPart;

	Vcpu->HostState.SpecialRegisters.Cr4 &= cr4Fix1.LowPart;
	Vcpu->HostState.SpecialRegisters.Cr4 |= cr4Fix0.LowPart;


	//更新CR0和CR4寄存器
	__writecr0(Vcpu->HostState.SpecialRegisters.Cr0);
	__writecr4(Vcpu->HostState.SpecialRegisters.Cr4);

	//进入VMX模式
	//VMX_ON指令的参数是我们申请的VMXON区域的物理地址
	PHYSICAL_ADDRESS phys = MmGetPhysicalAddress(Vcpu->VMXON);
	int res = __vmx_on((PULONG64)&phys);
	if (res)
	{
		DbgPrint("VTFrame:__vmx_on指令执行失败：%d",res);
		return FALSE;
	}

	// 清除VMCS的状态，将它设置为不活跃的
	phys = MmGetPhysicalAddress(Vcpu->VMCS);
	if (__vmx_vmclear((PULONG64)&phys))
	{
		DbgPrint("VTFrame:__vmx_vmclear指令执行失败");
		return FALSE;
	}

	// 加载VMCS，将它的状态设置为活跃的
	if (__vmx_vmptrld((PULONG64)&phys))
	{
		DbgPrint("VTFrame:__vmx_vmclear指令执行失败");
		return FALSE;
	}

	//VMX Root模式已启用，并且VMCS是活跃的
	return TRUE;
}

VOID VmxSubvertCPU(IN PVCPU Vcpu)
{
	PHYSICAL_ADDRESS phys = { 0 };
	phys.QuadPart = MAXULONG64;

	//前面虽然我们也是申请了全局内存,但是我们申请的是g_data的内存，而g_data的成员VCPU中的成员大部分是指针
	//所以我们这里要申请指针所指向的内存

	//申请VMX所需的内存区域,参数是大小和申请的范围
	Vcpu->VMXON = MmAllocateContiguousMemory(sizeof(VMX_VMCS), phys);
	Vcpu->VMCS = MmAllocateContiguousMemory(sizeof(VMX_VMCS), phys);
	Vcpu->VMMStack = MmAllocateContiguousMemory(KERNEL_STACK_SIZE, phys);

	if (!Vcpu->VMXON || !Vcpu->VMCS || !Vcpu->VMMStack)
	{
		DbgPrint("VTFrame:VMX内存区域申请失败\n");
		goto failed;
	}

	//保护非分页内存   说实话,我不太懂是什么意思 MDL还没弄懂。。。。。
	UtilProtectNonpagedMemory(Vcpu->VMXON, sizeof(VMX_VMCS), PAGE_READWRITE);
	UtilProtectNonpagedMemory(Vcpu->VMCS, sizeof(VMX_VMCS), PAGE_READWRITE);
	UtilProtectNonpagedMemory(Vcpu->VMMStack, KERNEL_STACK_SIZE, PAGE_READWRITE);

	//清空内存区域
	RtlZeroMemory(Vcpu->VMXON, sizeof(VMX_VMCS));
	RtlZeroMemory(Vcpu->VMCS, sizeof(VMX_VMCS));
	RtlZeroMemory(Vcpu->VMMStack, KERNEL_STACK_SIZE);

	// 试图在这个处理器上进入VMX模式
	if (VmxEnterRoot(Vcpu))
	{
		//VMCS数据区域的设置
		VmxSetupVMCS(Vcpu);
	
		// 构建EPT页表
		//Vcpu->ept_PML4T = BuildEPTTable();


		////开启EPT功能
		//EptEnable(Vcpu->ept_PML4T);

		//在vmlauch之前设置CPU的状态，如果开启成功，则会调到保存上下文的Native函数处，将状态改为ON
		Vcpu->VmxState = VMX_STATE_TRANSITION;

		DbgPrint("VTFrame:CPU:%d:正在开启VT\n", CPU_IDX);
		
		//CPU个数+1
		InterlockedIncrement(&g_data->vcpus);
		int res = __vmx_vmlaunch();
		
		
		//执行到这里就表示开启VT失败了,CPU个数-1
		InterlockedDecrement(&g_data->vcpus);
		Vcpu->VmxState = VMX_STATE_OFF;

		DbgPrint("VTFrame:CPU:%d:__vmx_vmlaunch执行失败,错误码:%d", CPU_IDX, res);

		//关闭VMX模式
		__vmx_off();

	}

	//释放内存
failed:;
	if (Vcpu->VMXON)
		MmFreeContiguousMemory(Vcpu->VMXON);
	if (Vcpu->VMCS)
		MmFreeContiguousMemory(Vcpu->VMCS);
	if (Vcpu->VMMStack)
		MmFreeContiguousMemory(Vcpu->VMMStack);

	Vcpu->VMXON = NULL;
	Vcpu->VMCS = NULL;
	Vcpu->VMMStack = NULL;
}

VOID VmxShutdown(IN PVCPU Vcpu)
{
	//先到VMM中进行处理
	__vmx_vmcall(VTFrame_UNLOAD, 0, 0, 0);
	VmxVMCleanup(KGDT64_R3_DATA | RPL_MASK, KGDT64_R3_CMTEB | RPL_MASK);

	//释放掉VCPU中的VMXON VMCS VMMStack的内存
	if (Vcpu->VMXON)
		MmFreeContiguousMemory(Vcpu->VMXON);
	if (Vcpu->VMCS)
		MmFreeContiguousMemory(Vcpu->VMCS);
	if (Vcpu->VMMStack)
		MmFreeContiguousMemory(Vcpu->VMMStack);
	
	//将指针设置为NULL
	Vcpu->VMXON = NULL;
	Vcpu->VMCS = NULL;
	Vcpu->VMMStack = NULL;
}


inline VOID IntelRestoreCPU(IN PVCPU Vcpu)
{
	// 当前CPU开启了VT则卸载
	if (Vcpu->VmxState > VMX_STATE_OFF)
		VmxShutdown(Vcpu);
}

VOID VmxInitializeCPU(IN PVCPU Vcpu, IN ULONG64 SystemDirectoryTableBase)
{
	//此函数可以保存一些我们填写VMCS表必须的一些特殊寄存器的值
	KeSaveStateForHibernate(&Vcpu->HostState);
	
	//此函数保存了一些上下文信息，如RIP，RSP等一些通用寄存器的值
	RtlCaptureContext(&Vcpu->HostState.ContextFrame);
	
	//当我们执行vmlauch导致vm entry到这里,也就是RtlCaptureContext函数的下一句
	//因为VMCS表的GUEST_RIP是由上叙函数RtlCaptureContext保存的

	
	//每个CPU的结构中有一个标识CPU开启状态的变量VmxState。
	//它的取值初始化为0，也就是VMX_STATE_OFF，在vmlauch指令执行前，他的值被赋值为VMX_STATE_TRANSITION
	if (g_data->cpu_data[CPU_IDX].VmxState == VMX_STATE_TRANSITION)
	{
		//到这里表示CPU执行vmlauch成功了
		//将CPU的状态标识为VMX_STATE_ON
		g_data->cpu_data[CPU_IDX].VmxState = VMX_STATE_ON;
		//下面这个函数与RtlCaptureContext相对应，上叙是保存，下面这个是恢复
		//再次恢复上下文，程序将运行至RtlCaptureContext函数下面,这句代码相当于一句goto到了if判断的上面
		RtlRestoreContext(&g_data->cpu_data[CPU_IDX].HostState.ContextFrame, NULL);
	}
	else if (g_data->cpu_data[CPU_IDX].VmxState == VMX_STATE_OFF)
	{
		
		//到这里表示此CPU是还没有开启VT
		//将CR3保存到CPU结构VCPU中
		Vcpu->SystemDirectoryTableBase = SystemDirectoryTableBase;
		//开启VT的主要内容，VMX颠覆CPU的政权
		VmxSubvertCPU(Vcpu);
	}
	
	//到这里就表示这个CPU开启VT成功了。。。。。。。
}

inline VOID IntelSubvertCPU(IN PVCPU Vcpu,IN PVOID SystemDirectoryTableBase)
{
	VmxInitializeCPU(Vcpu,(ULONG64)SystemDirectoryTableBase);
}


//开启VT和卸载VT的DPC例程
//如果第二个参数为我们驱动程序的CR3，则是开启VT
//为NULL，则是卸载VT
/*
VOID HvmpHVCallbackDPC(PRKDPC Dpc, PVOID Context, PVOID SystemArgument1, PVOID SystemArgument2)
{
	//获取当前CPU的VCPU结构
	PVCPU pVCPU = &g_data->cpu_data[CPU_IDX];

	//ARGUMENT_PRESENT宏是判断参数是否不为NULL
	if (ARGUMENT_PRESENT(Context))
	{
		//开启VT
		//传入当前CPU的VCPU结构和我们驱动程序的CR3
		IntelSubvertCPU(pVCPU,Context);
	}
	else
	{
		//卸载VT
		//传入当前CPU的VCPU结构
		IntelRestoreCPU(pVCPU);
	}

	
	//等待所有的DPC同步
	KeSignalCallDpcSynchronize(SystemArgument2);
	//标记DPC状态为已完成
	KeSignalCallDpcDone(SystemArgument1);
}
*/

/*
走到这个函数，就代表是不同的CPU在调用了，这个函数和调用的函数里面就需要添加多核处理
*/
VOID SetupVT(PVOID Context)
{
	
	//获取当前CPU的VCPU结构
	PVCPU pVCPU = &g_data->cpu_data[CPU_IDX];

	//ARGUMENT_PRESENT宏是判断参数是否不为NULL
	if (ARGUMENT_PRESENT(Context))
	{
		//开启VT
		//传入当前CPU的VCPU结构和我们驱动程序的CR3
		IntelSubvertCPU(pVCPU, Context);
	}
	else
	{
		//卸载VT
		//传入当前CPU的VCPU结构
		IntelRestoreCPU(pVCPU);
	}
}

/************************************************************************/
/* 对每一个逻辑CPU都申请内存，就是VCPU这个结构的大小*CPU个数+ULONG大小的CPU个数*/
/************************************************************************/
BOOLEAN  AllocGlobalMemory()
{
	//获取CPU数
	ULONG cpu_count = KeNumberProcessors;

	
	//全局变量g_data是一个CPU数量和CPU结构的数组的结构体

	//下面两句是等价的，FIELD_OFFSET(type,field)宏的作用是获取type结构体中除field字段外,其它字段的总大小
	//为了可扩展性，应该使用下面这句
	ULONG_PTR size = FIELD_OFFSET(GLOBAL_DATA, cpu_data) + cpu_count * sizeof(VCPU);
	//ULONG_PTR size = sizeof(LONG) + cpu_count * sizeof(VCPU);

	//申请内存
	g_data = (PGLOBAL_DATA)ExAllocatePoolWithTag(NonPagedPoolNx, size, VF_POOL_TAG);
	RtlZeroMemory(g_data, size);

	//MSRBitmap
	g_data->MSRBitmap = ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE, VF_POOL_TAG);
	RtlZeroMemory(g_data->MSRBitmap, PAGE_SIZE);


	if (g_data == NULL)
	{
		DbgPrint("VTFrame:全局变量内存申请失败\n");
		return FALSE;
	}

	DbgPrint("VTFrame:全局变量内存申请成功\n");
	return TRUE;
}



VOID FreeGlobalData(IN PGLOBAL_DATA pData)
{
	if (pData == NULL)
		return;

	ULONG cpu_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	for (ULONG i = 0; i < cpu_count; i++)
	{
		PVCPU Vcpu = &pData->cpu_data[i];
		if (Vcpu->VMXON)
			MmFreeContiguousMemory(Vcpu->VMXON);
		if (Vcpu->VMCS)
			MmFreeContiguousMemory(Vcpu->VMCS);
		if (Vcpu->VMMStack)
			MmFreeContiguousMemory(Vcpu->VMMStack);

	}

	ExFreePoolWithTag(pData, VF_POOL_TAG);
}

BOOLEAN StartVT()
{

	for (int i = 0; i < KeNumberProcessors; i++)
	{
		KeSetSystemAffinityThread((KAFFINITY)(1 << i));

		//这里其实不用传入cr3 为了兼容，懒得改了
		SetupVT((PVOID)__readcr3());

		KeRevertToUserAffinityThread();
	}
	// 用下面方法函数进行VT的多核处理时，多个线程会同时调用，进行EPT页表内存的申请时会卡顿，还是用上面那个好

	//调用内核模块导出的API KeGenericCallDpc创建一个DPC,参数传入本软件的CR3
	//这个函数的作用是在每一个CPU都调用这个DPC例程，这样可以实现VT对多核的支持
	//传入CR3是因为DPC例程可能是别的内核或应用层的程序在调用，这可能会导致在填写VMCS表时，CR3的填写出现错误

	//KeGenericCallDpc(HvmpHVCallbackDPC,(PVOID)__readcr3());
	return TRUE;
}