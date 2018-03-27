#include "ExitHandle.h"

#include "../Include/VMCS.h"
#include "VmxEvent.h"
#include "../VMX/vtasm.h"
#include "ept.h"

extern ULONG64 KiSystemCall64Ptr;    // 原始的系统调用地址
extern ULONG64 KiServiceCopyEndPtr;    // KiSystemServiceCopyEnd地址
extern VOID SyscallEntryPoint();

ULONG64 real_Cr3 = 0;
ULONG64 fake_Cr3 = 0;
BOOLEAN cr3bool = FALSE;
BOOLEAN int1bool = FALSE;
ULONG64 phyOri = 0;

//调用此方法的事件都是VMM模拟执行，直接跳到下一条指令处执行
//更改发生Exit事件处的RIP=指令地址+指令长度
inline VOID VmxpAdvanceEIP(IN PGUEST_STATE GuestState)
{
	GuestState->GuestRip += VmcsRead(VM_EXIT_INSTRUCTION_LEN);
	__vmx_vmwrite(GUEST_RIP, GuestState->GuestRip);
}

//开启MTF
inline VOID ToggleMTF(IN BOOLEAN State)
{
	VMX_CPU_BASED_CONTROLS vmCpuCtlRequested = { 0 };
	__vmx_vmread(CPU_BASED_VM_EXEC_CONTROL, (size_t*)&vmCpuCtlRequested.All);
	vmCpuCtlRequested.Fields.MonitorTrapFlag = State;
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, vmCpuCtlRequested.All);
}


VOID VmExitEvent(IN PGUEST_STATE GuestState)
{
	UNREFERENCED_PARAMETER(GuestState);
	INTERRUPT_INFO_FIELD Event = { 0 };
	ULONG64 ErrorCode = 0,ErrorAddress = 0;
//	ULONG InstructionLength = (ULONG)VmcsRead(VM_EXIT_INSTRUCTION_LEN);
	

	//读取错误信息
	Event.All = (ULONG32)VmcsRead(VM_EXIT_INTR_INFO);

	//错误码
	ErrorCode = VmcsRead(VM_EXIT_INTR_ERROR_CODE);

	//发生错误的地址
	ErrorAddress = VmcsRead(EXIT_QUALIFICATION);

	//是否有错误码
	if (Event.Fields.ErrorCodeValid)
		__vmx_vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, ErrorCode);//写入原始错误码
	

	switch (Event.Fields.Type)
	{

	case INTERRUPT_HARDWARE_EXCEPTION:
		//INT 1中断
		if (Event.Fields.Vector == VECTOR_DEBUG_EXCEPTION)
		{
			//1 调试异常 转发到0f
			INTERRUPT_INJECT_INFO_FIELD InjectEvent = { 0 };

			InjectEvent.Fields.Type = INTERRUPT_HARDWARE_EXCEPTION;
			InjectEvent.Fields.DeliverErrorCode = 0;
			InjectEvent.Fields.Valid = 1;
			if (int1bool)
				InjectEvent.Fields.Vector = 0x0f;
			else
				InjectEvent.Fields.Vector = 0x01;
			
			DbgPrint("VTFrame: Cr3 %p produce int 1 transfer to %p Current Eip:%p\n",VmcsRead(GUEST_CR3),0x0f,VmcsRead(GUEST_RIP));
			__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, InjectEvent.All);

			break;
		}
		
	}

}


VOID VmExitVmCall(IN PGUEST_STATE GuestState)
{
	
	EPT_CTX ctx = { 0 };
	//获取第一个参数，功能类型编号
	ULONG32 HypercallNumber = (ULONG32)(GuestState->GpRegs->Rcx & 0xFFFF);

	//判断VMCALL类型
	switch (HypercallNumber)
	{
	//VT卸载
	case VTFrame_UNLOAD:
	{
		GuestState->ExitPending = TRUE;
		break;
	}
	//页面异常
	case VTFrame_HOOK_PAGE: 
	{
		ULONG64 data = GuestState->GpRegs->Rdx;
		ULONG64 code = GuestState->GpRegs->R8;
		PteModify(data, code);
		__invept(INV_ALL_CONTEXTS, &ctx);
		break;
	}
	case VTFrame_UNHOOK_PAGE:
	{
		break;
	}
	//SYSCALL HOOK
	case VTFrame_HOOK_LSTAR:
	{
		__writemsr(MSR_LSTAR, (ULONG64)SyscallEntryPoint);
		GuestState->Vcpu->OriginalLSTAR = GuestState->GpRegs->Rdx;
		break;
	}
	case VTFrame_UNHOOK_LSTAR:
	{
		__writemsr(MSR_LSTAR, GuestState->Vcpu->OriginalLSTAR);
		GuestState->Vcpu->OriginalLSTAR = 0;
		break;
	}
	//Test
	case VTFrame_Test:
	{
		//暂做测试DXF CR3切换
		fake_Cr3 = (ULONG64)GuestState->GpRegs->R8;
		real_Cr3 = (ULONG64)GuestState->GpRegs->Rdx;
		cr3bool = TRUE;
		int1bool = TRUE;
		break;
	}
	default: 
	{
		DbgPrint("VTFrame:不支持的VMCALL类型\n");
		break; 
	}
	}

	VmxpAdvanceEIP(GuestState);
}

//必须处理的事件,我们不关心
VOID VmExitRdtsc(IN PGUEST_STATE GuestState)
{
	ULARGE_INTEGER tsc = { 0 };
	tsc.QuadPart = __rdtsc();
	GuestState->GpRegs->Rdx = tsc.HighPart;
	GuestState->GpRegs->Rax = tsc.LowPart;

	VmxpAdvanceEIP(GuestState);
}

//必须处理的事件,我们不关心
VOID VmExitRdtscp(IN PGUEST_STATE GuestState)
{
	unsigned int tscAux = 0;

	ULARGE_INTEGER tsc = { 0 };
	tsc.QuadPart = __rdtscp(&tscAux);
	GuestState->GpRegs->Rdx = tsc.HighPart;
	GuestState->GpRegs->Rax = tsc.LowPart;
	GuestState->GpRegs->Rcx = tscAux;

	VmxpAdvanceEIP(GuestState);
}

VOID VmExitCPUID(IN PGUEST_STATE GuestState)
{
	CPUID cpu_info = { 0 };

	__cpuidex((int*)&cpu_info, (int)GuestState->GpRegs->Rax, (int)GuestState->GpRegs->Rcx);

	if ((int)GuestState->GpRegs->Rax == 1)
	{
		//DbgPrint("%s正在调用CPUID\n",PsGetProcessImageFileName(PsGetCurrentProcess()));
		GuestState->GpRegs->Rax = cpu_info.eax;
		GuestState->GpRegs->Rbx = cpu_info.ebx;
		//GuestState->GpRegs->Rcx = cpu_info.ecx;
		GuestState->GpRegs->Rcx = 0xfffa3203;
		GuestState->GpRegs->Rdx = cpu_info.edx;
	}else{

		GuestState->GpRegs->Rax = cpu_info.eax;
		GuestState->GpRegs->Rbx = cpu_info.ebx;
		GuestState->GpRegs->Rcx = cpu_info.ecx;
		GuestState->GpRegs->Rdx = cpu_info.edx;
	}
	VmxpAdvanceEIP(GuestState);
}

//必须处理的事件,我们不关心
VOID VmExitINVD(IN PGUEST_STATE GuestState)
{
	__wbinvd();
	VmxpAdvanceEIP(GuestState);
}

//CR寄存器访问
VOID VmExitCR(IN PGUEST_STATE GuestState)
{
	PMOV_CR_QUALIFICATION data = (PMOV_CR_QUALIFICATION)&GuestState->ExitQualification;
	PULONG64 regPtr = (PULONG64)&GuestState->GpRegs->Rax + data->Fields.Register;
	VPID_CTX ctx = { 0 };
	switch (data->Fields.AccessType)
	{
	//CR寄存器写入
	case TYPE_MOV_TO_CR:
	{
		switch (data->Fields.ControlRegister)
		{
		case 0:
			__vmx_vmwrite(GUEST_CR0, *regPtr);
			__vmx_vmwrite(CR0_READ_SHADOW, *regPtr);
			DbgPrint("cr0写入\n");
			break;
		case 3:
			//开启VPID后对CR3的写操作都必须使得TLB缓存失效

			if (cr3bool)
			{
				if (fake_Cr3 == *regPtr)
					__vmx_vmwrite(GUEST_CR3, real_Cr3);
				else
					__vmx_vmwrite(GUEST_CR3, *regPtr);
				
			}else
				__vmx_vmwrite(GUEST_CR3, *regPtr);

			//DbgPrint("%s正在进行Cr3写入", PsGetProcessImageFileName(PsGetCurrentProcess()));
			//__vmx_vmwrite(GUEST_CR3, *regPtr);
			__invvpid(INV_ALL_CONTEXTS, &ctx);
			break;
		case 4:
			__vmx_vmwrite(GUEST_CR4, *regPtr);
			__vmx_vmwrite(CR4_READ_SHADOW, *regPtr);
			DbgPrint("cr4写入\n");
			break;
		default:
			DPRINT("HyperBone: CPU %d: %s: Unsupported register %d\n", CPU_IDX, __FUNCTION__, data->Fields.ControlRegister);
			ASSERT(FALSE);
			DbgPrint("其它cr写入\n");
			break;
		}
	}
	break;
	//CR寄存器读取
	case TYPE_MOV_FROM_CR:
	{
		switch (data->Fields.ControlRegister)
		{
		case 0:
			__vmx_vmread(GUEST_CR0, regPtr);
			DbgPrint("cr0读取\n");
			break;
		case 3:
			__vmx_vmread(GUEST_CR3, regPtr);
			break;
		case 4:
			__vmx_vmread(GUEST_CR4, regPtr);
			DbgPrint("cr4读取\n");
			break;
		default:
			DPRINT("HyperBone: CPU %d: %s: Unsupported register %d\n", CPU_IDX, __FUNCTION__, data->Fields.ControlRegister);
			ASSERT(FALSE);
			DbgPrint("其它cr读取\n");
			break;
		}
	}
	break;

	default:
		DPRINT("HyperBone: CPU %d: %s: Unsupported operation %d\n", CPU_IDX, __FUNCTION__, data->Fields.AccessType);
		ASSERT(FALSE);
		DbgPrint("其它cr操作\n");
		break;
	}

	VmxpAdvanceEIP(GuestState);
}


//MSR读取
VOID VmExitMSRRead(IN PGUEST_STATE GuestState)
{
	LARGE_INTEGER MsrValue = { 0 };
	//获取要读取的MSR代号
	ULONG32 ecx = (ULONG32)GuestState->GpRegs->Rcx;

	switch (ecx)
	{

	//对系统调用MSR的读取
	case MSR_LSTAR:
		//一直让它读取到原来的MSR_LSTAR寄存器的值
		if (GuestState->Vcpu->OriginalLSTAR == 0)
		{
			MsrValue.QuadPart = __readmsr(MSR_LSTAR);
		}else
		{	
			MsrValue.QuadPart = GuestState->Vcpu->OriginalLSTAR;
		}
		break;

	case MSR_GS_BASE:
		MsrValue.QuadPart = VmcsRead(GUEST_GS_BASE);
		break;
	case MSR_FS_BASE:
		MsrValue.QuadPart = VmcsRead(GUEST_FS_BASE);
		break;
	case MSR_IA32_DEBUGCTL:
		MsrValue.QuadPart = VmcsRead(GUEST_IA32_DEBUGCTL);
		break;

		// Report VMX as locked
	case MSR_IA32_FEATURE_CONTROL:
		DbgPrint("MSR_IA32_FEATURE_CONTROL读取\n");
		MsrValue.QuadPart = __readmsr(ecx);
		PIA32_FEATURE_CONTROL_MSR pMSR = (PIA32_FEATURE_CONTROL_MSR)&MsrValue.QuadPart;
		pMSR->Fields.EnableVmxon = FALSE;
		pMSR->Fields.Lock = TRUE;
		break;

		// Virtualize VMX register access
	case MSR_IA32_VMX_BASIC:
	case MSR_IA32_VMX_PINBASED_CTLS:
	case MSR_IA32_VMX_PROCBASED_CTLS:
	case MSR_IA32_VMX_EXIT_CTLS:
	case MSR_IA32_VMX_ENTRY_CTLS:
	case MSR_IA32_VMX_MISC:
	case MSR_IA32_VMX_CR0_FIXED0:
	case MSR_IA32_VMX_CR0_FIXED1:
	case MSR_IA32_VMX_CR4_FIXED0:
	case MSR_IA32_VMX_CR4_FIXED1:
	case MSR_IA32_VMX_VMCS_ENUM:
	case MSR_IA32_VMX_PROCBASED_CTLS2:
	case MSR_IA32_VMX_EPT_VPID_CAP:
	case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
	case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
	case MSR_IA32_VMX_TRUE_EXIT_CTLS:
	case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
	case MSR_IA32_VMX_VMFUNC:
		DbgPrint("其它VMX相关MSR寄存器的读取:%x\n", ecx);
		break;

	default:
		DbgPrint("其它MSR寄存器的读取:%x\n", ecx);
		MsrValue.QuadPart = __readmsr(ecx);
	}

	GuestState->GpRegs->Rax = MsrValue.LowPart;
	GuestState->GpRegs->Rdx = MsrValue.HighPart;

	
	VmxpAdvanceEIP(GuestState);
}

//MSR写入
VOID VmExitMSRWrite(IN PGUEST_STATE GuestState)
{
	LARGE_INTEGER MsrValue = { 0 };
	ULONG32 ecx = (ULONG32)GuestState->GpRegs->Rcx;

	MsrValue.LowPart = (ULONG32)GuestState->GpRegs->Rax;
	MsrValue.HighPart = (ULONG32)GuestState->GpRegs->Rdx;

	switch (ecx)
	{
	//对其系统调用MSR寄存器写入
	case MSR_LSTAR:
		//如果我们未开启系统调用HOOK,则OriginalLSTAR为0,让其写入
		//如果我们已经开启了系统调用HOOK,则让它的写入不做任何处理,程序不会出错,但是没有效果
		if (GuestState->Vcpu->OriginalLSTAR == 0)
			__writemsr(MSR_LSTAR, MsrValue.QuadPart);
		else
			DbgPrint("对MSR_LSTAR的写入已被拦截");
		break;
	case MSR_GS_BASE:
		__vmx_vmwrite(GUEST_GS_BASE, MsrValue.QuadPart);
		break;
	case MSR_FS_BASE:
		__vmx_vmwrite(GUEST_FS_BASE, MsrValue.QuadPart);
		break;
	case MSR_IA32_DEBUGCTL:
		__vmx_vmwrite(GUEST_IA32_DEBUGCTL, MsrValue.QuadPart);
		__writemsr(MSR_IA32_DEBUGCTL, MsrValue.QuadPart);
		break;

		// Virtualize VMX register access
	case MSR_IA32_VMX_BASIC:
	case MSR_IA32_VMX_PINBASED_CTLS:
	case MSR_IA32_VMX_PROCBASED_CTLS:
	case MSR_IA32_VMX_EXIT_CTLS:
	case MSR_IA32_VMX_ENTRY_CTLS:
	case MSR_IA32_VMX_MISC:
	case MSR_IA32_VMX_CR0_FIXED0:
	case MSR_IA32_VMX_CR0_FIXED1:
	case MSR_IA32_VMX_CR4_FIXED0:
	case MSR_IA32_VMX_CR4_FIXED1:
	case MSR_IA32_VMX_VMCS_ENUM:
	case MSR_IA32_VMX_PROCBASED_CTLS2:
	case MSR_IA32_VMX_EPT_VPID_CAP:
	case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
	case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
	case MSR_IA32_VMX_TRUE_EXIT_CTLS:
	case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
	case MSR_IA32_VMX_VMFUNC:
		DbgPrint("其它VMX相关MSR寄存器的写入,%x\n",ecx);
		break;

	default:
		DbgPrint("其它MSR寄存器的写入,%x\n",ecx);
		__writemsr(ecx, MsrValue.QuadPart);
	}

	VmxpAdvanceEIP(GuestState);
}



//VMM主要处理
DECLSPEC_NORETURN EXTERN_C VOID VmxpExitHandler(IN PCONTEXT Context)
{
	GUEST_STATE guestContext = { 0 };

	//提升IRQL到最高，VMM需要有最高等级的CPU控制权
	KeRaiseIrql(HIGH_LEVEL, &guestContext.GuestIrql);

	//因为调用了Native函数，所以原始的RCX在堆栈中，将它获取出来
	Context->Rcx = *(PULONG64)((ULONG_PTR)Context - sizeof(Context->Rcx));

	PVCPU Vcpu = &g_data->cpu_data[CPU_IDX];

	//获取处理Exit事件时必须的一些参数
	guestContext.Vcpu = Vcpu;
	guestContext.GuestEFlags.All = VmcsRead(GUEST_RFLAGS);
	guestContext.GuestRip = VmcsRead(GUEST_RIP);
	guestContext.GuestRsp = VmcsRead(GUEST_RSP);
	guestContext.ExitReason = VmcsRead(VM_EXIT_REASON) & 0xFFFF;
	guestContext.ExitQualification = VmcsRead(EXIT_QUALIFICATION);
	guestContext.LinearAddress = VmcsRead(GUEST_LINEAR_ADDRESS);
	guestContext.PhysicalAddress.QuadPart = VmcsRead(GUEST_PHYSICAL_ADDRESS);
	guestContext.GpRegs = Context;
	//卸载VT的标志
	guestContext.ExitPending = FALSE;

	
	switch (guestContext.ExitReason)
	{
		case EXIT_REASON_CPUID:
		{
			VmExitCPUID(&guestContext);
			break;
		}
		case EXIT_REASON_INVD:
		{
			VmExitINVD(&guestContext);
			break;
		}
		case EXIT_REASON_MSR_READ:
		{
			DbgPrint("%x,msr寄存器读取,%s\n", (ULONG32)guestContext.GpRegs->Rcx,PsGetProcessImageFileName(PsGetCurrentProcess()));
			VmExitMSRRead(&guestContext);
			break;
		}
		case EXIT_REASON_MSR_WRITE:
		{	
			DbgPrint("%x,msr寄存器写入,%s\n", (ULONG32)guestContext.GpRegs->Rcx, PsGetProcessImageFileName(PsGetCurrentProcess()));
			VmExitMSRWrite(&guestContext);
			break;
		}
		case EXIT_REASON_VMCALL:
		{
			VmExitVmCall(&guestContext);
			break;
		}
		case EXIT_REASON_CR_ACCESS:
		{
			VmExitCR(&guestContext);
			break;
		}
		case EXIT_REASON_GETSEC:
		{
			VmExitRdtsc(&guestContext);
			break;
		}
		case EXIT_REASON_RDTSCP:
		{
			VmExitRdtscp(&guestContext);
			break;
		}
		case EXIT_REASON_EPT_VIOLATION:
		{
			VmExitEptViolation(&guestContext);
			break;
		}
		case EXIT_REASON_EPT_MISCONFIG:
		{
			VmExitEptMisconfig(&guestContext);
			break;
		}
		case EXIT_REASOM_MTF:
		{
			VmExitMTF(&guestContext);
			break;
		}
		case EXIT_REASON_EXCEPTION_NMI:
		{
			VmExitEvent(&guestContext);
			break;
		}
		default: {
			DbgPrint("其它的VMExit事件类型:%x", guestContext.ExitReason);
			break;
		}
	
	}

	//如果ExitPending为TRUE则表示需要处理VT的卸载
	if (guestContext.ExitPending)
	{
		_lgdt(&Vcpu->HostState.SpecialRegisters.Gdtr.Limit);
		__lidt(&Vcpu->HostState.SpecialRegisters.Idtr.Limit);

		
		__writecr3(VmcsRead(GUEST_CR3));

		Context->Rsp = guestContext.GuestRsp;
		Context->Rip = (ULONG64)guestContext.GuestRip;

		__vmx_off();
		Vcpu->VmxState = VMX_STATE_OFF;
	}
	else
	{
		Context->Rsp += sizeof(Context->Rcx);
		Context->Rip = (ULONG64)VmxpResume;
	}

	KeLowerIrql(guestContext.GuestIrql);
	RtlRestoreContext(Context, NULL);
}


