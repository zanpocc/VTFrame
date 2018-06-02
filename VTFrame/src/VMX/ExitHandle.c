#include "ExitHandle.h"

#include "../Include/VMCS.h"
#include "VmxEvent.h"
#include "../VMX/vtasm.h"
#include "ept.h"

extern ULONG64 KiSystemCall64Ptr;    // 原始的系统调用地址
extern ULONG64 KiServiceCopyEndPtr;    // KiSystemServiceCopyEnd地址
extern VOID SyscallEntryPoint();
extern HANDLE GamePid;

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
			InjectEvent.Fields.Vector = 1;

			if (GamePid == PsGetProcessId(PsGetCurrentProcess()))
			{
				//硬件断点异常
				if (ErrorAddress == 1)
				{
					DbgPrint("%llx地址发生硬件断点异常\n", GuestState->GuestRip);
					InjectEvent.Fields.Vector = 0x0f;
				}

				//单步异常
				if (GuestState->GuestEFlags.Fields.DF == TRUE)
				{
					DbgPrint("调试器单步异常:%llx\n", GuestState->GuestRip);
					InjectEvent.Fields.Vector = 0x0f;
				}

				GuestState->GuestEFlags.Fields.DF = FALSE;
				__vmx_vmwrite(GUEST_RFLAGS, GuestState->GuestEFlags.All);
			}
			
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
			ULONG64 data = GuestState->GpRegs->Rdx;
			UnPteModify(data);
			break;
		}
		//SYSCALL HOOK
		case VTFrame_HOOK_LSTAR:
		{
			//保存原始MSR_LSTAR寄存器
			GuestState->Vcpu->OriginalLSTAR = GuestState->GpRegs->Rdx;
			__writemsr(MSR_LSTAR, (ULONG64)SyscallEntryPoint);
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
	//CPUID cpu_info = { 0 };
	unsigned int cpu_info[4] = {0};
	//rax function_id rcx sub_function_id
	__cpuidex((int*)cpu_info, (int)GuestState->GpRegs->Rax, (int)GuestState->GpRegs->Rcx);

	if ((int)GuestState->GpRegs->Rax == 1)
	{
		CpuFeaturesEcx ecx = {0};
		ecx.all = cpu_info[2];
		ecx.fields.not_used = TRUE;
		cpu_info[2] = ecx.all;
	}
	
	GuestState->GpRegs->Rax = cpu_info[0];
	GuestState->GpRegs->Rbx = cpu_info[1];
	GuestState->GpRegs->Rcx = cpu_info[2];
	GuestState->GpRegs->Rdx = cpu_info[3];

	VmxpAdvanceEIP(GuestState);
}

//必须处理的事件,我们不关心
VOID VmExitINVD(IN PGUEST_STATE GuestState)
{
	__wbinvd();
	VmxpAdvanceEIP(GuestState);
}

PULONG_PTR VmmpSelectRegister(ULONG index, PGUEST_STATE guest_context)
{
	PULONG_PTR register_used = NULL;
	switch (index)
	{
	case 0: register_used = &guest_context->GpRegs->Rax; break;
	case 1: register_used = &guest_context->GpRegs->Rcx; break;
	case 2: register_used = &guest_context->GpRegs->Rdx; break;
	case 3: register_used = &guest_context->GpRegs->Rbx; break;
	case 4: register_used = &guest_context->GpRegs->Rsp; break;
	case 5: register_used = &guest_context->GpRegs->Rbp; break;
	case 6: register_used = &guest_context->GpRegs->Rsi; break;
	case 7: register_used = &guest_context->GpRegs->Rdi; break;
		//仅仅X64支持
	case 8: register_used = &guest_context->GpRegs->R8; break;
	case 9: register_used = &guest_context->GpRegs->R9; break;
	case 10: register_used = &guest_context->GpRegs->R10; break;
	case 11: register_used = &guest_context->GpRegs->R11; break;
	case 12: register_used = &guest_context->GpRegs->R12; break;
	case 13: register_used = &guest_context->GpRegs->R13; break;
	case 14: register_used = &guest_context->GpRegs->R14; break;
	case 15: register_used = &guest_context->GpRegs->R15; break;
	default: DbgPrint("VmmpSelectRegister错误的寄存器索引\n"); break;
	}

	return register_used;
}


//CR寄存器访问
VOID VmExitCR(IN PGUEST_STATE GuestState)
{
	PMOV_CR_QUALIFICATION data = (PMOV_CR_QUALIFICATION)&GuestState->ExitQualification;
	PULONG64 regPtr = VmmpSelectRegister((ULONG)data->Fields.Register, GuestState);
	EPT_CTX ctx = { 0 };
	switch (data->Fields.AccessType)
	{
		//CR寄存器写入
		case TYPE_MOV_TO_CR:
			switch (data->Fields.ControlRegister)
			{
			case 0:
				__vmx_vmwrite(GUEST_CR0, *regPtr);
				__vmx_vmwrite(CR0_READ_SHADOW, *regPtr);
				DbgPrint("cr0写入\n");
				break;
			case 3:
				if (cr3bool)
				{
					if (fake_Cr3 == *regPtr)
					{
						*regPtr = real_Cr3;
					}
				}
				__invvpid(INV_ALL_CONTEXTS,&ctx);
				__vmx_vmwrite(GUEST_CR3, *regPtr);
				
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
			break;
		//CR寄存器读取
		case TYPE_MOV_FROM_CR:
		
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
			break;
		default:
			DPRINT("HyperBone: CPU %d: %s: Unsupported operation %d\n", CPU_IDX, __FUNCTION__, data->Fields.AccessType);
			ASSERT(FALSE);
			DbgPrint("其它cr操作\n");
			break;
	}
	
	VmxpAdvanceEIP(GuestState);
}



//DR寄存器访问
VOID VmExitDR(IN PGUEST_STATE GuestState)
{
	
	PMOV_DR_QUALIFICATION data = (PMOV_DR_QUALIFICATION)&GuestState->ExitQualification;
	
	PULONG64 regPtr = VmmpSelectRegister((ULONG)data->Fields.Register, GuestState);
	
	switch (data->Fields.AccessType)
	{
		case TYPE_MOV_TO_DR:
			switch (data->Fields.Debugl_Register)
			{
			case 0: __writedr(0, *regPtr); break;;
			case 1: __writedr(1, *regPtr); break;
			case 2: __writedr(2, *regPtr); break;
			case 3: __writedr(3, *regPtr); break;
			case 4: __writedr(4, *regPtr); break;
			case 5: __writedr(5, *regPtr); break;
			case 6: __writedr(6, *regPtr); break;
			case 7:  __vmx_vmwrite(GUEST_DR7, *regPtr); break;
			default: break;
			}
			break;
		
		case TYPE_MOV_FROM_DR:
			switch (data->Fields.Debugl_Register)
			{
			case 0: *regPtr = __readdr(0); break;
			case 1: *regPtr = __readdr(1); break;
			case 2: *regPtr = __readdr(2); break;
			case 3: *regPtr = __readdr(3); break;
			case 4: *regPtr = __readdr(4); break;
			case 5: *regPtr = __readdr(5); break;
			case 6: *regPtr = __readdr(6); break;
			case 7: *regPtr = VmcsRead(GUEST_DR7); break;
			default: break;
			}
			break;

		default:
			DbgPrint("错误的操作\n"); break;
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
		{
			//__writemsr(MSR_LSTAR, MsrValue.QuadPart);
			DbgPrint("对MSR_LSTAR的写入已被拦截");
		}
			
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
EXTERN_C VOID VmxpExitHandler(IN PMYCONTEXT Context)
{
	GUEST_STATE guestContext = { 0 };

	//提升IRQL到最高，VMM需要有最高等级的CPU控制权
	KeRaiseIrql(HIGH_LEVEL, &guestContext.GuestIrql);

	//因为调用了Native函数，所以原始的RCX在堆栈中，将它获取出来
	Context->Rcx = *(PULONG64)((ULONG_PTR)Context + sizeof(MYCONTEXT) - sizeof(ULONG64)*2);

	PVCPU Vcpu = &g_data->cpu_data[CPU_IDX];

	//获取处理Exit事件时必须的一些参数
	guestContext.Vcpu = Vcpu;
	guestContext.GuestEFlags.All = VmcsRead(GUEST_RFLAGS);
	//客户机RIP
	guestContext.GuestRip = VmcsRead(GUEST_RIP);
	guestContext.GuestRsp = VmcsRead(GUEST_RSP);
	guestContext.ExitReason = VmcsRead(VM_EXIT_REASON) & 0xFFFF;
	guestContext.ExitQualification = VmcsRead(EXIT_QUALIFICATION);
	//访问那个线性地址导致的vm-exit
	guestContext.LinearAddress = VmcsRead(GUEST_LINEAR_ADDRESS);
	//访问那个物理地址导致的vm-exit
	guestContext.PhysicalAddress.QuadPart = VmcsRead(GUEST_PHYSICAL_ADDRESS);
	guestContext.GpRegs = Context;
	//卸载VT的标志
	guestContext.ExitPending = FALSE;

	
	switch (guestContext.ExitReason)
	{
		//必须处理
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
		//开启后处理
		case EXIT_REASON_MSR_READ:
		{
			VmExitMSRRead(&guestContext);
			break;
		}
		case EXIT_REASON_MSR_WRITE:
		{	
			VmExitMSRWrite(&guestContext);
			break;
		}
		//自己什么时候使用什么时候处理
		case EXIT_REASON_VMCALL:
		{
			VmExitVmCall(&guestContext);
			break;
		}
		//开启后处理CR
		case EXIT_REASON_CR_ACCESS:
		{
			VmExitCR(&guestContext);
			break;
		}
		//开启后处理DR
		case EXIT_REASON_DR_ACCESS:
		{
			VmExitDR(&guestContext);
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
		//开启EPT HOOK后处理
		case EXIT_REASON_EPT_VIOLATION:
		{
			VmExitEptViolation(&guestContext);
			break;
		}
		//开启EPT HOOK后处理
		case EXIT_REASON_EPT_MISCONFIG:
		{
			VmExitEptMisconfig(&guestContext);
			break;
		}
		//自己什么时候使用什么时候处理
		case EXIT_REASOM_MTF:
		{
			VmExitMTF(&guestContext);
			break;
		}
		//开启异常捕获后处理
		case EXIT_REASON_EXCEPTION_NMI:
		{
			VmExitEvent(&guestContext);
			break;
		}
		default: {
			DbgPrint("其它的VMExit事件类型:%x\n", guestContext.ExitReason);
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
		//Context->Rip = (ULONG64)guestContext.GuestRip;
		__vmx_off();
		Vcpu->VmxState = VMX_STATE_OFF;
	}
	else
	{
		Context->Rsp += sizeof(Context->Rcx);
	}

	KeLowerIrql(guestContext.GuestIrql);
}


