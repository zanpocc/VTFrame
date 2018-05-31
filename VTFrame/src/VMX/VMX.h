#pragma once
#include "../Include/common.h"
#include "../Include/CPU.h"

//VM EXIT事件
enum _VM_EXIT_REASON
{
	EXIT_REASON_EXCEPTION_NMI = 0,    // Exception or non-maskable interrupt (NMI).
	EXIT_REASON_EXTERNAL_INTERRUPT = 1,    // External interrupt.
	EXIT_REASON_TRIPLE_FAULT = 2,    // Triple fault.
	EXIT_REASON_INIT = 3,    // INIT signal.
	EXIT_REASON_SIPI = 4,    // Start-up IPI (SIPI).
	EXIT_REASON_IO_SMI = 5,    // I/O system-management interrupt (SMI).
	EXIT_REASON_OTHER_SMI = 6,    // Other SMI.
	EXIT_REASON_PENDING_INTERRUPT = 7,    // Interrupt window exiting.
	EXIT_REASON_NMI_WINDOW = 8,    // NMI window exiting.
	EXIT_REASON_TASK_SWITCH = 9,    // Task switch.
	EXIT_REASON_CPUID = 10,   // Guest software attempted to execute CPUID.
	EXIT_REASON_GETSEC = 11,   // Guest software attempted to execute GETSEC.
	EXIT_REASON_HLT = 12,   // Guest software attempted to execute HLT.
	EXIT_REASON_INVD = 13,   // Guest software attempted to execute INVD.
	EXIT_REASON_INVLPG = 14,   // Guest software attempted to execute INVLPG.
	EXIT_REASON_RDPMC = 15,   // Guest software attempted to execute RDPMC.
	EXIT_REASON_RDTSC = 16,   // Guest software attempted to execute RDTSC.
	EXIT_REASON_RSM = 17,   // Guest software attempted to execute RSM in SMM.
	EXIT_REASON_VMCALL = 18,   // Guest software executed VMCALL.
	EXIT_REASON_VMCLEAR = 19,   // Guest software executed VMCLEAR.
	EXIT_REASON_VMLAUNCH = 20,   // Guest software executed VMLAUNCH.
	EXIT_REASON_VMPTRLD = 21,   // Guest software executed VMPTRLD.
	EXIT_REASON_VMPTRST = 22,   // Guest software executed VMPTRST.
	EXIT_REASON_VMREAD = 23,   // Guest software executed VMREAD.
	EXIT_REASON_VMRESUME = 24,   // Guest software executed VMRESUME.
	EXIT_REASON_VMWRITE = 25,   // Guest software executed VMWRITE.
	EXIT_REASON_VMXOFF = 26,   // Guest software executed VMXOFF.
	EXIT_REASON_VMXON = 27,   // Guest software executed VMXON.
	EXIT_REASON_CR_ACCESS = 28,   // Control-register accesses.
	EXIT_REASON_DR_ACCESS = 29,   // Debug-register accesses.
	EXIT_REASON_IO_INSTRUCTION = 30,   // I/O instruction.
	EXIT_REASON_MSR_READ = 31,   // RDMSR. Guest software attempted to execute RDMSR.
	EXIT_REASON_MSR_WRITE = 32,   // WRMSR. Guest software attempted to execute WRMSR.
	EXIT_REASON_INVALID_GUEST_STATE = 33,   // VM-entry failure due to invalid guest state.
	EXIT_REASON_MSR_LOADING = 34,   // VM-entry failure due to MSR loading.
	EXIT_REASON_RESERVED_35 = 35,   // Reserved
	EXIT_REASON_MWAIT_INSTRUCTION = 36,   // Guest software executed MWAIT.
	EXIT_REASOM_MTF = 37,   // VM-exit due to monitor trap flag.
	EXIT_REASON_RESERVED_38 = 38,   // Reserved
	EXIT_REASON_MONITOR_INSTRUCTION = 39,   // Guest software attempted to execute MONITOR.
	EXIT_REASON_PAUSE_INSTRUCTION = 40,   // Guest software attempted to execute PAUSE.
	EXIT_REASON_MACHINE_CHECK = 41,   // VM-entry failure due to machine-check.
	EXIT_REASON_RESERVED_42 = 42,   // Reserved
	EXIT_REASON_TPR_BELOW_THRESHOLD = 43,   // TPR below threshold. Guest software executed MOV to CR8.
	EXIT_REASON_APIC_ACCESS = 44,   // APIC access. Guest software attempted to access memory at a physical address on the APIC-access page.
	EXIT_REASON_VIRTUALIZED_EIO = 45,   // EOI virtualization was performed for a virtual interrupt whose vector indexed a bit set in the EOIexit bitmap
	EXIT_REASON_XDTR_ACCESS = 46,   // Guest software attempted to execute LGDT, LIDT, SGDT, or SIDT.
	EXIT_REASON_TR_ACCESS = 47,   // Guest software attempted to execute LLDT, LTR, SLDT, or STR.
	EXIT_REASON_EPT_VIOLATION = 48,   // An attempt to access memory with a guest-physical address was disallowed by the configuration of the EPT paging structures.
	EXIT_REASON_EPT_MISCONFIG = 49,   // An attempt to access memory with a guest-physical address encountered a misconfigured EPT paging-structure entry.
	EXIT_REASON_INVEPT = 50,   // Guest software attempted to execute INVEPT.
	EXIT_REASON_RDTSCP = 51,   // Guest software attempted to execute RDTSCP.
	EXIT_REASON_PREEMPT_TIMER = 52,   // VMX-preemption timer expired. The preemption timer counted down to zero.
	EXIT_REASON_INVVPID = 53,   // Guest software attempted to execute INVVPID.
	EXIT_REASON_WBINVD = 54,   // Guest software attempted to execute WBINVD
	EXIT_REASON_XSETBV = 55,   // Guest software attempted to execute XSETBV.
	EXIT_REASON_APIC_WRITE = 56,   // Guest completed write to virtual-APIC.
	EXIT_REASON_RDRAND = 57,   // Guest software attempted to execute RDRAND.
	EXIT_REASON_INVPCID = 58,   // Guest software attempted to execute INVPCID.
	EXIT_REASON_VMFUNC = 59,   // Guest software attempted to execute VMFUNC.
	EXIT_REASON_RESERVED_60 = 60,   // Reserved
	EXIT_REASON_RDSEED = 61,   // Guest software attempted to executed RDSEED and exiting was enabled.
	EXIT_REASON_RESERVED_62 = 62,   // Reserved
	EXIT_REASON_XSAVES = 63,   // Guest software attempted to executed XSAVES and exiting was enabled.
	EXIT_REASON_XRSTORS = 64,   // Guest software attempted to executed XRSTORS and exiting was enabled.

	VMX_MAX_GUEST_VMEXIT = 65
};
//CR相关
#define TYPE_MOV_TO_CR              0
#define TYPE_MOV_FROM_CR            1
#define TYPE_CLTS                   2
#define TYPE_LMSW                   3
//DR
#define TYPE_MOV_TO_DR              0
#define TYPE_MOV_FROM_DR            1


//自写一个CONTEXT

typedef struct _MYCONTEXT
{
	ULONG64 R15;
	ULONG64 R14;
	ULONG64 R13;
	ULONG64 R12;
	ULONG64 R11;
	ULONG64 R10;
	ULONG64 R9;
	ULONG64 R8;
	ULONG64 Rdi;
	ULONG64 Rsi;
	ULONG64 Rbp;
	ULONG64 Rsp;
	ULONG64 Rbx;
	ULONG64 Rdx;
	ULONG64 Rcx;
	ULONG64 Rax;
} MYCONTEXT, *PMYCONTEXT;


typedef struct _EPT_CTX
{
	ULONG64 PEPT;
	ULONG64 High;
} EPT_CTX, *PEPT_CTX;

typedef enum _INV_TYPE
{
	INV_INDIV_ADDR = 0,  // Invalidate a specific page
	INV_SINGLE_CONTEXT = 1,  // Invalidate one context (specific VPID)
	INV_ALL_CONTEXTS = 2,  // Invalidate all contexts (all VPIDs)
	INV_SINGLE_CONTEXT_RETAIN_GLOBALS = 3   // Invalidate a single VPID context retaining global mappings
} IVVPID_TYPE, INVEPT_TYPE;

typedef struct _VPID_CTX
{
	ULONG64 VPID : 16;      // VPID to effect
	ULONG64 Reserved : 48;      // Reserved
	ULONG64 Address : 64;      // Linear address
} VPID_CTX, *PVPID_CTX;

typedef struct _InvVpidDescriptor {
	USHORT vpid;
	USHORT reserved1;
	ULONG32 reserved2;
	ULONG64 linear_address;
}InvVpidDescriptor,PInvVpidDescriptor;

typedef union _MOV_CR_QUALIFICATION
{
	ULONG_PTR All;
	struct
	{
		ULONG ControlRegister : 4;
		ULONG AccessType : 2;
		ULONG LMSWOperandType : 1;
		ULONG Reserved1 : 1;
		ULONG Register : 4;
		ULONG Reserved2 : 4;
		ULONG LMSWSourceData : 16;
		ULONG Reserved3;
	} Fields;
} MOV_CR_QUALIFICATION, *PMOV_CR_QUALIFICATION;

typedef union _MOV_DR_QUALIFICATION {
	ULONG_PTR All;
	struct {
		ULONG_PTR Debugl_Register : 3;  //访问那个调试寄存器
		ULONG_PTR Reserved1 : 1;        
		ULONG_PTR AccessType : 1;       //0写入DR 1读取DR
		ULONG_PTR Reserved2 : 3;        
		ULONG_PTR Register : 4;			//使用的通用寄存器
		ULONG_PTR Reserved3 : 20;       
		ULONG_PTR Reserved4 : 32;       
	} Fields;
} MOV_DR_QUALIFICATION,*PMOV_DR_QUALIFICATION;

#pragma warning(disable: 4214 4201)
typedef struct _VMX_GDTENTRY64
{
	ULONG_PTR Base;
	ULONG Limit;
	union
	{
		struct
		{
			UCHAR Flags1;
			UCHAR Flags2;
			UCHAR Flags3;
			UCHAR Flags4;
		} Bytes;
		struct
		{
			USHORT SegmentType : 4;
			USHORT DescriptorType : 1;
			USHORT Dpl : 2;
			USHORT Present : 1;

			USHORT Reserved : 4;
			USHORT System : 1;
			USHORT LongMode : 1;
			USHORT DefaultBig : 1;
			USHORT Granularity : 1;

			USHORT Unusable : 1;
			USHORT Reserved2 : 15;
		} Bits;
		ULONG AccessRights;
	};
	USHORT Selector;
} VMX_GDTENTRY64, *PVMX_GDTENTRY64;


typedef union _VMX_PIN_BASED_CONTROLS
{
	ULONG32 All;
	struct
	{
		ULONG32 ExternalInterruptExiting : 1;    // [0]
		ULONG32 Reserved1 : 2;                   // [1-2]
		ULONG32 NMIExiting : 1;                  // [3]
		ULONG32 Reserved2 : 1;                   // [4]
		ULONG32 VirtualNMIs : 1;                 // [5]
		ULONG32 ActivateVMXPreemptionTimer : 1;  // [6]
		ULONG32 ProcessPostedInterrupts : 1;     // [7]
	} Fields;
} VMX_PIN_BASED_CONTROLS, *PVMX_PIN_BASED_CONTROLS;

typedef union _VMX_CPU_BASED_CONTROLS
{
	ULONG32 All;
	struct
	{
		ULONG32 Reserved1 : 2;                 // [0-1]
		ULONG32 InterruptWindowExiting : 1;    // [2]
		ULONG32 UseTSCOffseting : 1;           // [3]
		ULONG32 Reserved2 : 3;                 // [4-6]
		ULONG32 HLTExiting : 1;                // [7]
		ULONG32 Reserved3 : 1;                 // [8]
		ULONG32 INVLPGExiting : 1;             // [9]
		ULONG32 MWAITExiting : 1;              // [10]
		ULONG32 RDPMCExiting : 1;              // [11]
		ULONG32 RDTSCExiting : 1;              // [12]
		ULONG32 Reserved4 : 2;                 // [13-14]
		ULONG32 CR3LoadExiting : 1;            // [15]
		ULONG32 CR3StoreExiting : 1;           // [16]
		ULONG32 Reserved5 : 2;                 // [17-18]
		ULONG32 CR8LoadExiting : 1;            // [19]
		ULONG32 CR8StoreExiting : 1;           // [20]
		ULONG32 UseTPRShadowExiting : 1;       // [21]
		ULONG32 NMIWindowExiting : 1;          // [22]
		ULONG32 MovDRExiting : 1;              // [23]
		ULONG32 UnconditionalIOExiting : 1;    // [24]
		ULONG32 UseIOBitmaps : 1;              // [25]
		ULONG32 Reserved6 : 1;                 // [26]
		ULONG32 MonitorTrapFlag : 1;           // [27]
		ULONG32 UseMSRBitmaps : 1;             // [28]
		ULONG32 MONITORExiting : 1;            // [29]
		ULONG32 PAUSEExiting : 1;              // [30]
		ULONG32 ActivateSecondaryControl : 1;  // [31] 是否启用Secondary字段
	} Fields;
} VMX_CPU_BASED_CONTROLS, *PVMX_CPU_BASED_CONTROLS;


typedef union _VMX_VM_EXIT_CONTROLS
{
	ULONG32 All;
	struct
	{
		ULONG32 Reserved1 : 2;                    // [0-1]
		ULONG32 SaveDebugControls : 1;            // [2]
		ULONG32 Reserved2 : 6;                    // [3-8]
		ULONG32 HostAddressSpaceSize : 1;         // [9]
		ULONG32 Reserved3 : 2;                    // [10-11]
		ULONG32 LoadIA32_PERF_GLOBAL_CTRL : 1;    // [12]
		ULONG32 Reserved4 : 2;                    // [13-14]
		ULONG32 AcknowledgeInterruptOnExit : 1;   // [15]
		ULONG32 Reserved5 : 2;                    // [16-17]
		ULONG32 SaveIA32_PAT : 1;                 // [18]
		ULONG32 LoadIA32_PAT : 1;                 // [19]
		ULONG32 SaveIA32_EFER : 1;                // [20]
		ULONG32 LoadIA32_EFER : 1;                // [21]
		ULONG32 SaveVMXPreemptionTimerValue : 1;  // [22]
	} Fields;
} VMX_VM_EXIT_CONTROLS, *PVMX_VM_EXIT_CONTROLS;

typedef union _VMX_VM_ENTER_CONTROLS
{
	ULONG32 All;
	struct
	{
		ULONG32 Reserved1 : 2;                       // [0-1]
		ULONG32 LoadDebugControls : 1;               // [2]
		ULONG32 Reserved2 : 6;                       // [3-8]
		ULONG32 IA32eModeGuest : 1;                  // [9]
		ULONG32 EntryToSMM : 1;                      // [10]
		ULONG32 DeactivateDualMonitorTreatment : 1;  // [11]
		ULONG32 Reserved3 : 1;                       // [12]
		ULONG32 LoadIA32_PERF_GLOBAL_CTRL : 1;       // [13]
		ULONG32 LoadIA32_PAT : 1;                    // [14]
		ULONG32 LoadIA32_EFER : 1;                   // [15]
	} Fields;
} VMX_VM_ENTER_CONTROLS, *PVMX_VM_ENTER_CONTROLS;

typedef struct _GUEST_STATE
{
	PMYCONTEXT GpRegs;
	PVCPU Vcpu;
	ULONG_PTR GuestRip;
	ULONG_PTR GuestRsp;
	EFLAGS GuestEFlags;
	ULONG_PTR LinearAddress;
	PHYSICAL_ADDRESS PhysicalAddress;
	KIRQL GuestIrql;
	USHORT ExitReason;
	ULONG_PTR ExitQualification;
	BOOLEAN ExitPending;
} GUEST_STATE, *PGUEST_STATE;


typedef union _VMX_SECONDARY_CPU_BASED_CONTROLS
{
	ULONG32 All;
	struct
	{
		ULONG32 VirtualizeAPICAccesses : 1;      // [0]
		ULONG32 EnableEPT : 1;                   // [1]
		ULONG32 DescriptorTableExiting : 1;      // [2]
		ULONG32 EnableRDTSCP : 1;                // [3]
		ULONG32 VirtualizeX2APICMode : 1;        // [4]
		ULONG32 EnableVPID : 1;                  // [5]
		ULONG32 WBINVDExiting : 1;               // [6]
		ULONG32 UnrestrictedGuest : 1;           // [7]
		ULONG32 APICRegisterVirtualization : 1;  // [8]
		ULONG32 VirtualInterruptDelivery : 1;    // [9]
		ULONG32 PAUSELoopExiting : 1;            // [10]
		ULONG32 RDRANDExiting : 1;               // [11]
		ULONG32 EnableINVPCID : 1;               // [12]
		ULONG32 EnableVMFunctions : 1;           // [13]
		ULONG32 VMCSShadowing : 1;               // [14]
		ULONG32 Reserved1 : 1;                   // [15]
		ULONG32 RDSEEDExiting : 1;               // [16]
		ULONG32 Reserved2 : 1;                   // [17]
		ULONG32 EPTViolation : 1;                // [18]
		ULONG32 Reserved3 : 1;                   // [19]
		ULONG32 EnableXSAVESXSTORS : 1;          // [20]
	} Fields;
} VMX_SECONDARY_CPU_BASED_CONTROLS, *PVMX_SECONDARY_CPU_BASED_CONTROLS;

typedef union _KGDTENTRY64                    // 7 elements, 0x10 bytes (sizeof) 
{
	struct                                    // 5 elements, 0x10 bytes (sizeof) 
	{
		/*0x000*/         UINT16       LimitLow;
		/*0x002*/         UINT16       BaseLow;
		union                                 // 2 elements, 0x4 bytes (sizeof)  
		{
			struct                            // 4 elements, 0x4 bytes (sizeof)  
			{
				/*0x004*/                 UINT8        BaseMiddle;
				/*0x005*/                 UINT8        Flags1;
				/*0x006*/                 UINT8        Flags2;
				/*0x007*/                 UINT8        BaseHigh;
			}Bytes;
			struct                            // 10 elements, 0x4 bytes (sizeof) 
			{
				/*0x004*/                 ULONG32      BaseMiddle : 8;  // 0 BitPosition                   
				/*0x004*/                 ULONG32      Type : 5;        // 8 BitPosition                   
				/*0x004*/                 ULONG32      Dpl : 2;         // 13 BitPosition                  
				/*0x004*/                 ULONG32      Present : 1;     // 15 BitPosition                  
				/*0x004*/                 ULONG32      LimitHigh : 4;   // 16 BitPosition                  
				/*0x004*/                 ULONG32      System : 1;      // 20 BitPosition                  
				/*0x004*/                 ULONG32      LongMode : 1;    // 21 BitPosition                  
				/*0x004*/                 ULONG32      DefaultBig : 1;  // 22 BitPosition                  
				/*0x004*/                 ULONG32      Granularity : 1; // 23 BitPosition                  
				/*0x004*/                 ULONG32      BaseHigh : 8;    // 24 BitPosition                  
			}Bits;
		};
		/*0x008*/         ULONG32      BaseUpper;
		/*0x00C*/         ULONG32      MustBeZero;
	};
	/*0x000*/     UINT64       Alignment;
}KGDTENTRY64, *PKGDTENTRY64;


KMUTEX g_GlobalMutex;
PGLOBAL_DATA g_data;
BOOLEAN IsVTSupport();
BOOLEAN StartVT();
VOID SetupVT(PVOID Context);
BOOLEAN  AllocGlobalMemory();
VOID HvmpHVCallbackDPC(PRKDPC Dpc, PVOID Context, PVOID SystemArgument1, PVOID SystemArgument2);
VOID FreeGlobalData(IN PGLOBAL_DATA pData);
VOID __vmx_vmcall(ULONG index, ULONG64 arg1, ULONG64 arg2, ULONG64 arg3);
VOID __invept(INVEPT_TYPE type, PEPT_CTX ctx);
VOID __invvpid(IVVPID_TYPE type, PEPT_CTX ctx);
EXTERN_C  PULONG64  BuildEPTTable();