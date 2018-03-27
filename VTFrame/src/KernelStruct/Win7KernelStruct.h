#pragma once
#include <ntddk.h>

//win7进程和线程所有的成员结构体定义

////////////////////////////////////////线程////////////////////////////////////////////////////////////////////////////////
typedef struct _EX_PUSH_LOCK                 // 7 elements, 0x8 bytes (sizeof) 
{
	union                                    // 3 elements, 0x8 bytes (sizeof) 
	{
		struct                               // 5 elements, 0x8 bytes (sizeof) 
		{
			/*0x000*/             UINT64       Locked : 1;         // 0 BitPosition                  
			/*0x000*/             UINT64       Waiting : 1;        // 1 BitPosition                  
			/*0x000*/             UINT64       Waking : 1;         // 2 BitPosition                  
			/*0x000*/             UINT64       MultipleShared : 1; // 3 BitPosition                  
			/*0x000*/             UINT64       Shared : 60;        // 4 BitPosition                  
		};
		/*0x000*/         UINT64       Value;
		/*0x000*/         VOID*        Ptr;
	};
}EX_PUSH_LOCK, *PEX_PUSH_LOCK;

typedef union _PS_CLIENT_SECURITY_CONTEXT    // 4 elements, 0x8 bytes (sizeof) 
{
	/*0x000*/     UINT64       ImpersonationData;
	/*0x000*/     VOID*        ImpersonationToken;
	struct                                   // 2 elements, 0x8 bytes (sizeof) 
	{
		/*0x000*/         UINT64       ImpersonationLevel : 2; // 0 BitPosition                  
		/*0x000*/         UINT64       EffectiveOnly : 1;      // 2 BitPosition                  
	};
}PS_CLIENT_SECURITY_CONTEXT, *PPS_CLIENT_SECURITY_CONTEXT;


typedef struct _KAPC_STATE             // 5 elements, 0x30 bytes (sizeof) 
{
	/*0x000*/     struct _LIST_ENTRY ApcListHead[2];
	/*0x020*/     struct _KPROCESS* Process;
	/*0x028*/     UINT8        KernelApcInProgress;
	/*0x029*/     UINT8        KernelApcPending;
	/*0x02A*/     UINT8        UserApcPending;
	/*0x02B*/     UINT8        _PADDING0_[0x5];
}KAPC_STATE, *PKAPC_STATE;



typedef union _KWAIT_STATUS_REGISTER // 8 elements, 0x1 bytes (sizeof) 
{
	/*0x000*/     UINT8        Flags;
	struct                           // 7 elements, 0x1 bytes (sizeof) 
	{
		/*0x000*/         UINT8        State : 2;      // 0 BitPosition                  
		/*0x000*/         UINT8        Affinity : 1;   // 2 BitPosition                  
		/*0x000*/         UINT8        Priority : 1;   // 3 BitPosition                  
		/*0x000*/         UINT8        Apc : 1;        // 4 BitPosition                  
		/*0x000*/         UINT8        UserApc : 1;    // 5 BitPosition                  
		/*0x000*/         UINT8        Alert : 1;      // 6 BitPosition                  
		/*0x000*/         UINT8        Unused : 1;     // 7 BitPosition                  
	};
}KWAIT_STATUS_REGISTER, *PKWAIT_STATUS_REGISTER;


typedef struct _KTHREAD                                 // 126 elements, 0x360 bytes (sizeof) 
{
	/*0x000*/     struct _DISPATCHER_HEADER Header;                   // 29 elements, 0x18 bytes (sizeof)   
	/*0x018*/     UINT64       CycleTime;
	/*0x020*/     UINT64       QuantumTarget;
	/*0x028*/     VOID*        InitialStack;
	/*0x030*/     VOID*        StackLimit;
	/*0x038*/     VOID*        KernelStack;
	/*0x040*/     UINT64       ThreadLock;
	/*0x048*/     union _KWAIT_STATUS_REGISTER WaitRegister;          // 8 elements, 0x1 bytes (sizeof)     
	/*0x049*/     UINT8        Running;
	/*0x04A*/     UINT8        Alerted[2];
	union                                               // 2 elements, 0x4 bytes (sizeof)     
	{
		struct                                          // 14 elements, 0x4 bytes (sizeof)    
		{
			/*0x04C*/             ULONG32      KernelStackResident : 1;       // 0 BitPosition                      
			/*0x04C*/             ULONG32      ReadyTransition : 1;           // 1 BitPosition                      
			/*0x04C*/             ULONG32      ProcessReadyQueue : 1;         // 2 BitPosition                      
			/*0x04C*/             ULONG32      WaitNext : 1;                  // 3 BitPosition                      
			/*0x04C*/             ULONG32      SystemAffinityActive : 1;      // 4 BitPosition                      
			/*0x04C*/             ULONG32      Alertable : 1;                 // 5 BitPosition                      
			/*0x04C*/             ULONG32      GdiFlushActive : 1;            // 6 BitPosition                      
			/*0x04C*/             ULONG32      UserStackWalkActive : 1;       // 7 BitPosition                      
			/*0x04C*/             ULONG32      ApcInterruptRequest : 1;       // 8 BitPosition                      
			/*0x04C*/             ULONG32      ForceDeferSchedule : 1;        // 9 BitPosition                      
			/*0x04C*/             ULONG32      QuantumEndMigrate : 1;         // 10 BitPosition                     
			/*0x04C*/             ULONG32      UmsDirectedSwitchEnable : 1;   // 11 BitPosition                     
			/*0x04C*/             ULONG32      TimerActive : 1;               // 12 BitPosition                     
			/*0x04C*/             ULONG32      Reserved : 19;                 // 13 BitPosition                     
		};
		/*0x04C*/         LONG32       MiscFlags;
	};
	union                                               // 2 elements, 0x30 bytes (sizeof)    
	{
		/*0x050*/         struct _KAPC_STATE ApcState;                    // 5 elements, 0x30 bytes (sizeof)    
		struct                                          // 3 elements, 0x30 bytes (sizeof)    
		{
			/*0x050*/             UINT8        ApcStateFill[43];
			/*0x07B*/             CHAR         Priority;
			/*0x07C*/             ULONG32      NextProcessor;
		};
	};
	/*0x080*/     ULONG32      DeferredProcessor;
	/*0x084*/     UINT8        _PADDING0_[0x4];
	/*0x088*/     UINT64       ApcQueueLock;
	/*0x090*/     INT64        WaitStatus;
	/*0x098*/     struct _KWAIT_BLOCK* WaitBlockList;
	union                                               // 2 elements, 0x10 bytes (sizeof)    
	{
		/*0x0A0*/         struct _LIST_ENTRY WaitListEntry;               // 2 elements, 0x10 bytes (sizeof)    
		/*0x0A0*/         struct _SINGLE_LIST_ENTRY SwapListEntry;        // 1 elements, 0x8 bytes (sizeof)     
	};
	/*0x0B0*/     struct _KQUEUE* Queue;
	/*0x0B8*/     VOID*        Teb;
	/*0x0C0*/     struct _KTIMER Timer;                               // 6 elements, 0x40 bytes (sizeof)    
	union                                               // 2 elements, 0x4 bytes (sizeof)     
	{
		struct                                          // 10 elements, 0x4 bytes (sizeof)    
		{
			/*0x100*/             ULONG32      AutoAlignment : 1;             // 0 BitPosition                      
			/*0x100*/             ULONG32      DisableBoost : 1;              // 1 BitPosition                      
			/*0x100*/             ULONG32      EtwStackTraceApc1Inserted : 1; // 2 BitPosition                      
			/*0x100*/             ULONG32      EtwStackTraceApc2Inserted : 1; // 3 BitPosition                      
			/*0x100*/             ULONG32      CalloutActive : 1;             // 4 BitPosition                      
			/*0x100*/             ULONG32      ApcQueueable : 1;              // 5 BitPosition                      
			/*0x100*/             ULONG32      EnableStackSwap : 1;           // 6 BitPosition                      
			/*0x100*/             ULONG32      GuiThread : 1;                 // 7 BitPosition                      
			/*0x100*/             ULONG32      UmsPerformingSyscall : 1;      // 8 BitPosition                      
			/*0x100*/             ULONG32      ReservedFlags : 23;            // 9 BitPosition                      
		};
		/*0x100*/         LONG32       ThreadFlags;
	};
	/*0x104*/     ULONG32      Spare0;
	union                                               // 6 elements, 0xC0 bytes (sizeof)    
	{
		/*0x108*/         struct _KWAIT_BLOCK WaitBlock[4];
		struct                                          // 2 elements, 0xC0 bytes (sizeof)    
		{
			/*0x108*/             UINT8        WaitBlockFill4[44];
			/*0x134*/             ULONG32      ContextSwitches;
			/*0x138*/             UINT8        _PADDING1_[0x90];
		};
		struct                                          // 5 elements, 0xC0 bytes (sizeof)    
		{
			/*0x108*/             UINT8        WaitBlockFill5[92];
			/*0x164*/             UINT8        State;
			/*0x165*/             CHAR         NpxState;
			/*0x166*/             UINT8        WaitIrql;
			/*0x167*/             CHAR         WaitMode;
			/*0x168*/             UINT8        _PADDING2_[0x60];
		};
		struct                                          // 2 elements, 0xC0 bytes (sizeof)    
		{
			/*0x108*/             UINT8        WaitBlockFill6[140];
			/*0x194*/             ULONG32      WaitTime;
			/*0x198*/             UINT8        _PADDING3_[0x30];
		};
		struct                                          // 3 elements, 0xC0 bytes (sizeof)    
		{
			/*0x108*/             UINT8        WaitBlockFill7[168];
			/*0x1B0*/             VOID*        TebMappedLowVa;
			/*0x1B8*/             struct _UMS_CONTROL_BLOCK* Ucb;
			/*0x1C0*/             UINT8        _PADDING4_[0x8];
		};
		struct                                          // 2 elements, 0xC0 bytes (sizeof)    
		{
			/*0x108*/             UINT8        WaitBlockFill8[188];
			union                                       // 2 elements, 0x4 bytes (sizeof)     
			{
				struct                                  // 2 elements, 0x4 bytes (sizeof)     
				{
					/*0x1C4*/                     INT16        KernelApcDisable;
					/*0x1C6*/                     INT16        SpecialApcDisable;
				};
				/*0x1C4*/                 ULONG32      CombinedApcDisable;
			};
		};
	};
	/*0x1C8*/     struct _LIST_ENTRY QueueListEntry;                  // 2 elements, 0x10 bytes (sizeof)    
	/*0x1D8*/     struct _KTRAP_FRAME* TrapFrame;
	/*0x1E0*/     VOID*        FirstArgument;
	union                                               // 2 elements, 0x8 bytes (sizeof)     
	{
		/*0x1E8*/         VOID*        CallbackStack;
		/*0x1E8*/         UINT64       CallbackDepth;
	};
	/*0x1F0*/     UINT8        ApcStateIndex;
	/*0x1F1*/     CHAR         BasePriority;
	union                                               // 2 elements, 0x1 bytes (sizeof)     
	{
		/*0x1F2*/         CHAR         PriorityDecrement;
		struct                                          // 2 elements, 0x1 bytes (sizeof)     
		{
			/*0x1F2*/             UINT8        ForegroundBoost : 4;           // 0 BitPosition                      
			/*0x1F2*/             UINT8        UnusualBoost : 4;              // 4 BitPosition                      
		};
	};
	/*0x1F3*/     UINT8        Preempted;
	/*0x1F4*/     UINT8        AdjustReason;
	/*0x1F5*/     CHAR         AdjustIncrement;
	/*0x1F6*/     CHAR         PreviousMode;
	/*0x1F7*/     CHAR         Saturation;
	/*0x1F8*/     ULONG32      SystemCallNumber;
	/*0x1FC*/     ULONG32      FreezeCount;
	/*0x200*/     struct _GROUP_AFFINITY UserAffinity;                // 3 elements, 0x10 bytes (sizeof)    
	/*0x210*/     struct _KPROCESS* Process;
	/*0x218*/     struct _GROUP_AFFINITY Affinity;                    // 3 elements, 0x10 bytes (sizeof)    
	/*0x228*/     ULONG32      IdealProcessor;
	/*0x22C*/     ULONG32      UserIdealProcessor;
	/*0x230*/     struct _KAPC_STATE* ApcStatePointer[2];
	union                                               // 2 elements, 0x30 bytes (sizeof)    
	{
		/*0x240*/         struct _KAPC_STATE SavedApcState;               // 5 elements, 0x30 bytes (sizeof)    
		struct                                          // 5 elements, 0x30 bytes (sizeof)    
		{
			/*0x240*/             UINT8        SavedApcStateFill[43];
			/*0x26B*/             UINT8        WaitReason;
			/*0x26C*/             CHAR         SuspendCount;
			/*0x26D*/             CHAR         Spare1;
			/*0x26E*/             UINT8        CodePatchInProgress;
			/*0x26F*/             UINT8        _PADDING5_[0x1];
		};
	};
	/*0x270*/     VOID*        Win32Thread;
	/*0x278*/     VOID*        StackBase;
	union                                               // 7 elements, 0x58 bytes (sizeof)    
	{
		/*0x280*/         struct _KAPC SuspendApc;                        // 16 elements, 0x58 bytes (sizeof)   
		struct                                          // 2 elements, 0x58 bytes (sizeof)    
		{
			/*0x280*/             UINT8        SuspendApcFill0[1];
			/*0x281*/             UINT8        ResourceIndex;
			/*0x282*/             UINT8        _PADDING6_[0x56];
		};
		struct                                          // 2 elements, 0x58 bytes (sizeof)    
		{
			/*0x280*/             UINT8        SuspendApcFill1[3];
			/*0x283*/             UINT8        QuantumReset;
			/*0x284*/             UINT8        _PADDING7_[0x54];
		};
		struct                                          // 2 elements, 0x58 bytes (sizeof)    
		{
			/*0x280*/             UINT8        SuspendApcFill2[4];
			/*0x284*/             ULONG32      KernelTime;
			/*0x288*/             UINT8        _PADDING8_[0x50];
		};
		struct                                          // 2 elements, 0x58 bytes (sizeof)    
		{
			/*0x280*/             UINT8        SuspendApcFill3[64];
			/*0x2C0*/             struct _KPRCB* WaitPrcb;
			/*0x2C8*/             UINT8        _PADDING9_[0x10];
		};
		struct                                          // 2 elements, 0x58 bytes (sizeof)    
		{
			/*0x280*/             UINT8        SuspendApcFill4[72];
			/*0x2C8*/             VOID*        LegoData;
			/*0x2D0*/             UINT8        _PADDING10_[0x8];
		};
		struct                                          // 3 elements, 0x58 bytes (sizeof)    
		{
			/*0x280*/             UINT8        SuspendApcFill5[83];
			/*0x2D3*/             UINT8        LargeStack;
			/*0x2D4*/             ULONG32      UserTime;
		};
	};
	union                                               // 2 elements, 0x20 bytes (sizeof)    
	{
		/*0x2D8*/         struct _KSEMAPHORE SuspendSemaphore;            // 2 elements, 0x20 bytes (sizeof)    
		struct                                          // 2 elements, 0x20 bytes (sizeof)    
		{
			/*0x2D8*/             UINT8        SuspendSemaphorefill[28];
			/*0x2F4*/             ULONG32      SListFaultCount;
		};
	};
	/*0x2F8*/     struct _LIST_ENTRY ThreadListEntry;                 // 2 elements, 0x10 bytes (sizeof)    
	/*0x308*/     struct _LIST_ENTRY MutantListHead;                  // 2 elements, 0x10 bytes (sizeof)    
	/*0x318*/     VOID*        SListFaultAddress;
	/*0x320*/     INT64        ReadOperationCount;
	/*0x328*/     INT64        WriteOperationCount;
	/*0x330*/     INT64        OtherOperationCount;
	/*0x338*/     INT64        ReadTransferCount;
	/*0x340*/     INT64        WriteTransferCount;
	/*0x348*/     INT64        OtherTransferCount;
	/*0x350*/     struct _KTHREAD_COUNTERS* ThreadCounters;
	/*0x358*/     struct _XSTATE_SAVE* XStateSave;
}KTHREAD, *PKTHREAD;


typedef struct _ETHREAD                                              // 88 elements, 0x498 bytes (sizeof)  
{
	/*0x000*/     struct _KTHREAD Tcb;                                             // 126 elements, 0x360 bytes (sizeof) 
	/*0x360*/     union _LARGE_INTEGER CreateTime;                                 // 4 elements, 0x8 bytes (sizeof)     
	union                                                            // 2 elements, 0x10 bytes (sizeof)    
	{
		/*0x368*/         union _LARGE_INTEGER ExitTime;                               // 4 elements, 0x8 bytes (sizeof)     
		/*0x368*/         struct _LIST_ENTRY KeyedWaitChain;                           // 2 elements, 0x10 bytes (sizeof)    
	};
	/*0x378*/     LONG32       ExitStatus;
	/*0x37C*/     UINT8        _PADDING0_[0x4];
	union                                                            // 2 elements, 0x10 bytes (sizeof)    
	{
		/*0x380*/         struct _LIST_ENTRY PostBlockList;                            // 2 elements, 0x10 bytes (sizeof)    
		struct                                                       // 2 elements, 0x10 bytes (sizeof)    
		{
			/*0x380*/             VOID*        ForwardLinkShadow;
			/*0x388*/             VOID*        StartAddress;
		};
	};
	union                                                            // 3 elements, 0x8 bytes (sizeof)     
	{
		/*0x390*/         struct _TERMINATION_PORT* TerminationPort;
		/*0x390*/         struct _ETHREAD* ReaperLink;
		/*0x390*/         VOID*        KeyedWaitValue;
	};
	/*0x398*/     UINT64       ActiveTimerListLock;
	/*0x3A0*/     struct _LIST_ENTRY ActiveTimerListHead;                          // 2 elements, 0x10 bytes (sizeof)    
	/*0x3B0*/     struct _CLIENT_ID Cid;                                           // 2 elements, 0x10 bytes (sizeof)    
	union                                                            // 2 elements, 0x20 bytes (sizeof)    
	{
		/*0x3C0*/         struct _KSEMAPHORE KeyedWaitSemaphore;                       // 2 elements, 0x20 bytes (sizeof)    
		/*0x3C0*/         struct _KSEMAPHORE AlpcWaitSemaphore;                        // 2 elements, 0x20 bytes (sizeof)    
	};
	/*0x3E0*/     union _PS_CLIENT_SECURITY_CONTEXT ClientSecurity;                // 4 elements, 0x8 bytes (sizeof)     
	/*0x3E8*/     struct _LIST_ENTRY IrpList;                                      // 2 elements, 0x10 bytes (sizeof)    
	/*0x3F8*/     UINT64       TopLevelIrp;
	/*0x400*/     struct _DEVICE_OBJECT* DeviceToVerify;
	/*0x408*/     union _PSP_CPU_QUOTA_APC* CpuQuotaApc;
	/*0x410*/     VOID*        Win32StartAddress;
	/*0x418*/     VOID*        LegacyPowerObject;
	/*0x420*/     struct _LIST_ENTRY ThreadListEntry;                              // 2 elements, 0x10 bytes (sizeof)    
	/*0x430*/     struct _EX_RUNDOWN_REF RundownProtect;                           // 2 elements, 0x8 bytes (sizeof)     
	/*0x438*/     struct _EX_PUSH_LOCK ThreadLock;                                 // 7 elements, 0x8 bytes (sizeof)     
	/*0x440*/     ULONG32      ReadClusterSize;
	/*0x444*/     LONG32       MmLockOrdering;
	union                                                            // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x448*/         ULONG32      CrossThreadFlags;
		struct                                                       // 14 elements, 0x4 bytes (sizeof)    
		{
			/*0x448*/             ULONG32      Terminated : 1;                             // 0 BitPosition                      
			/*0x448*/             ULONG32      ThreadInserted : 1;                         // 1 BitPosition                      
			/*0x448*/             ULONG32      HideFromDebugger : 1;                       // 2 BitPosition                      
			/*0x448*/             ULONG32      ActiveImpersonationInfo : 1;                // 3 BitPosition                      
			/*0x448*/             ULONG32      SystemThread : 1;                           // 4 BitPosition                      
			/*0x448*/             ULONG32      HardErrorsAreDisabled : 1;                  // 5 BitPosition                      
			/*0x448*/             ULONG32      BreakOnTermination : 1;                     // 6 BitPosition                      
			/*0x448*/             ULONG32      SkipCreationMsg : 1;                        // 7 BitPosition                      
			/*0x448*/             ULONG32      SkipTerminationMsg : 1;                     // 8 BitPosition                      
			/*0x448*/             ULONG32      CopyTokenOnOpen : 1;                        // 9 BitPosition                      
			/*0x448*/             ULONG32      ThreadIoPriority : 3;                       // 10 BitPosition                     
			/*0x448*/             ULONG32      ThreadPagePriority : 3;                     // 13 BitPosition                     
			/*0x448*/             ULONG32      RundownFail : 1;                            // 16 BitPosition                     
			/*0x448*/             ULONG32      NeedsWorkingSetAging : 1;                   // 17 BitPosition                     
		};
	};
	union                                                            // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x44C*/         ULONG32      SameThreadPassiveFlags;
		struct                                                       // 7 elements, 0x4 bytes (sizeof)     
		{
			/*0x44C*/             ULONG32      ActiveExWorker : 1;                         // 0 BitPosition                      
			/*0x44C*/             ULONG32      ExWorkerCanWaitUser : 1;                    // 1 BitPosition                      
			/*0x44C*/             ULONG32      MemoryMaker : 1;                            // 2 BitPosition                      
			/*0x44C*/             ULONG32      ClonedThread : 1;                           // 3 BitPosition                      
			/*0x44C*/             ULONG32      KeyedEventInUse : 1;                        // 4 BitPosition                      
			/*0x44C*/             ULONG32      RateApcState : 2;                           // 5 BitPosition                      
			/*0x44C*/             ULONG32      SelfTerminate : 1;                          // 7 BitPosition                      
		};
	};
	union                                                            // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x450*/         ULONG32      SameThreadApcFlags;
		struct                                                       // 4 elements, 0x4 bytes (sizeof)     
		{
			struct                                                   // 8 elements, 0x1 bytes (sizeof)     
			{
				/*0x450*/                 UINT8        Spare : 1;                              // 0 BitPosition                      
				/*0x450*/                 UINT8        StartAddressInvalid : 1;                // 1 BitPosition                      
				/*0x450*/                 UINT8        EtwPageFaultCalloutActive : 1;          // 2 BitPosition                      
				/*0x450*/                 UINT8        OwnsProcessWorkingSetExclusive : 1;     // 3 BitPosition                      
				/*0x450*/                 UINT8        OwnsProcessWorkingSetShared : 1;        // 4 BitPosition                      
				/*0x450*/                 UINT8        OwnsSystemCacheWorkingSetExclusive : 1; // 5 BitPosition                      
				/*0x450*/                 UINT8        OwnsSystemCacheWorkingSetShared : 1;    // 6 BitPosition                      
				/*0x450*/                 UINT8        OwnsSessionWorkingSetExclusive : 1;     // 7 BitPosition                      
			};
			struct                                                   // 8 elements, 0x1 bytes (sizeof)     
			{
				/*0x451*/                 UINT8        OwnsSessionWorkingSetShared : 1;        // 0 BitPosition                      
				/*0x451*/                 UINT8        OwnsProcessAddressSpaceExclusive : 1;   // 1 BitPosition                      
				/*0x451*/                 UINT8        OwnsProcessAddressSpaceShared : 1;      // 2 BitPosition                      
				/*0x451*/                 UINT8        SuppressSymbolLoad : 1;                 // 3 BitPosition                      
				/*0x451*/                 UINT8        Prefetching : 1;                        // 4 BitPosition                      
				/*0x451*/                 UINT8        OwnsDynamicMemoryShared : 1;            // 5 BitPosition                      
				/*0x451*/                 UINT8        OwnsChangeControlAreaExclusive : 1;     // 6 BitPosition                      
				/*0x451*/                 UINT8        OwnsChangeControlAreaShared : 1;        // 7 BitPosition                      
			};
			struct                                                   // 6 elements, 0x1 bytes (sizeof)     
			{
				/*0x452*/                 UINT8        OwnsPagedPoolWorkingSetExclusive : 1;   // 0 BitPosition                      
				/*0x452*/                 UINT8        OwnsPagedPoolWorkingSetShared : 1;      // 1 BitPosition                      
				/*0x452*/                 UINT8        OwnsSystemPtesWorkingSetExclusive : 1;  // 2 BitPosition                      
				/*0x452*/                 UINT8        OwnsSystemPtesWorkingSetShared : 1;     // 3 BitPosition                      
				/*0x452*/                 UINT8        TrimTrigger : 2;                        // 4 BitPosition                      
				/*0x452*/                 UINT8        Spare1 : 2;                             // 6 BitPosition                      
			};
			/*0x453*/             UINT8        PriorityRegionActive;
		};
	};
	/*0x454*/     UINT8        CacheManagerActive;
	/*0x455*/     UINT8        DisablePageFaultClustering;
	/*0x456*/     UINT8        ActiveFaultCount;
	/*0x457*/     UINT8        LockOrderState;
	/*0x458*/     UINT64       AlpcMessageId;
	union                                                            // 2 elements, 0x8 bytes (sizeof)     
	{
		/*0x460*/         VOID*        AlpcMessage;
		/*0x460*/         ULONG32      AlpcReceiveAttributeSet;
	};
	/*0x468*/     struct _LIST_ENTRY AlpcWaitListEntry;                            // 2 elements, 0x10 bytes (sizeof)    
	/*0x478*/     ULONG32      CacheManagerCount;
	/*0x47C*/     ULONG32      IoBoostCount;
	/*0x480*/     UINT64       IrpListLock;
	/*0x488*/     VOID*        ReservedForSynchTracking;
	/*0x490*/     struct _SINGLE_LIST_ENTRY CmCallbackListHead;                    // 1 elements, 0x8 bytes (sizeof)     
}ETHREAD, *PETHREAD;


////////////////////////////////////////进程/////////////////////////////////////////////////////////////////////////////////
typedef struct _ALPC_PROCESS_CONTEXT  // 3 elements, 0x20 bytes (sizeof) 
{
	/*0x000*/     struct _EX_PUSH_LOCK Lock;        // 7 elements, 0x8 bytes (sizeof)  
	/*0x008*/     struct _LIST_ENTRY ViewListHead;  // 2 elements, 0x10 bytes (sizeof) 
	/*0x018*/     UINT64       PagedPoolQuotaCache;
}ALPC_PROCESS_CONTEXT, *PALPC_PROCESS_CONTEXT;


typedef struct _MMADDRESS_NODE          // 5 elements, 0x28 bytes (sizeof) 
{
	union                               // 2 elements, 0x8 bytes (sizeof)  
	{
		/*0x000*/         INT64        Balance : 2;       // 0 BitPosition                   
		/*0x000*/         struct _MMADDRESS_NODE* Parent;
	}u1;
	/*0x008*/     struct _MMADDRESS_NODE* LeftChild;
	/*0x010*/     struct _MMADDRESS_NODE* RightChild;
	/*0x018*/     UINT64       StartingVpn;
	/*0x020*/     UINT64       EndingVpn;
}MMADDRESS_NODE, *PMMADDRESS_NODE;


typedef struct _MM_AVL_TABLE                          // 6 elements, 0x40 bytes (sizeof) 
{
	/*0x000*/     struct _MMADDRESS_NODE BalancedRoot;              // 5 elements, 0x28 bytes (sizeof) 
	struct                                            // 3 elements, 0x8 bytes (sizeof)  
	{
		/*0x028*/         UINT64       DepthOfTree : 5;                 // 0 BitPosition                   
		/*0x028*/         UINT64       Unused : 3;                      // 5 BitPosition                   
		/*0x028*/         UINT64       NumberGenericTableElements : 56; // 8 BitPosition                   
	};
	/*0x030*/     VOID*        NodeHint;
	/*0x038*/     VOID*        NodeFreeHint;
}MM_AVL_TABLE, *PMM_AVL_TABLE;


typedef struct _MMSUPPORT_FLAGS                 // 15 elements, 0x4 bytes (sizeof) 
{
	struct                                      // 6 elements, 0x1 bytes (sizeof)  
	{
		/*0x000*/         UINT8        WorkingSetType : 3;        // 0 BitPosition                   
		/*0x000*/         UINT8        ModwriterAttached : 1;     // 3 BitPosition                   
		/*0x000*/         UINT8        TrimHard : 1;              // 4 BitPosition                   
		/*0x000*/         UINT8        MaximumWorkingSetHard : 1; // 5 BitPosition                   
		/*0x000*/         UINT8        ForceTrim : 1;             // 6 BitPosition                   
		/*0x000*/         UINT8        MinimumWorkingSetHard : 1; // 7 BitPosition                   
	};
	struct                                      // 4 elements, 0x1 bytes (sizeof)  
	{
		/*0x001*/         UINT8        SessionMaster : 1;         // 0 BitPosition                   
		/*0x001*/         UINT8        TrimmerState : 2;          // 1 BitPosition                   
		/*0x001*/         UINT8        Reserved : 1;              // 3 BitPosition                   
		/*0x001*/         UINT8        PageStealers : 4;          // 4 BitPosition                   
	};
	/*0x002*/     UINT8        MemoryPriority : 8;            // 0 BitPosition                   
	struct                                      // 4 elements, 0x1 bytes (sizeof)  
	{
		/*0x003*/         UINT8        WsleDeleted : 1;           // 0 BitPosition                   
		/*0x003*/         UINT8        VmExiting : 1;             // 1 BitPosition                   
		/*0x003*/         UINT8        ExpansionFailed : 1;       // 2 BitPosition                   
		/*0x003*/         UINT8        Available : 5;             // 3 BitPosition                   
	};
}MMSUPPORT_FLAGS, *PMMSUPPORT_FLAGS;


typedef struct _MMSUPPORT                        // 21 elements, 0x88 bytes (sizeof) 
{
	/*0x000*/     struct _EX_PUSH_LOCK WorkingSetMutex;        // 7 elements, 0x8 bytes (sizeof)   
	/*0x008*/     struct _KGATE* ExitGate;
	/*0x010*/     VOID*        AccessLog;
	/*0x018*/     struct _LIST_ENTRY WorkingSetExpansionLinks; // 2 elements, 0x10 bytes (sizeof)  
	/*0x028*/     ULONG32      AgeDistribution[7];
	/*0x044*/     ULONG32      MinimumWorkingSetSize;
	/*0x048*/     ULONG32      WorkingSetSize;
	/*0x04C*/     ULONG32      WorkingSetPrivateSize;
	/*0x050*/     ULONG32      MaximumWorkingSetSize;
	/*0x054*/     ULONG32      ChargedWslePages;
	/*0x058*/     ULONG32      ActualWslePages;
	/*0x05C*/     ULONG32      WorkingSetSizeOverhead;
	/*0x060*/     ULONG32      PeakWorkingSetSize;
	/*0x064*/     ULONG32      HardFaultCount;
	/*0x068*/     struct _MMWSL* VmWorkingSetList;
	/*0x070*/     UINT16       NextPageColor;
	/*0x072*/     UINT16       LastTrimStamp;
	/*0x074*/     ULONG32      PageFaultCount;
	/*0x078*/     ULONG32      RepurposeCount;
	/*0x07C*/     ULONG32      Spare[2];
	/*0x084*/     struct _MMSUPPORT_FLAGS Flags;               // 15 elements, 0x4 bytes (sizeof)  
}MMSUPPORT, *PMMSUPPORT;


typedef struct _SE_AUDIT_PROCESS_CREATION_INFO      // 1 elements, 0x8 bytes (sizeof) 
{
	/*0x000*/     struct _OBJECT_NAME_INFORMATION* ImageFileName;
}SE_AUDIT_PROCESS_CREATION_INFO, *PSE_AUDIT_PROCESS_CREATION_INFO;


typedef struct _HARDWARE_PTE           // 16 elements, 0x8 bytes (sizeof) 
{
	/*0x000*/     UINT64       Valid : 1;            // 0 BitPosition                   
	/*0x000*/     UINT64       Write : 1;            // 1 BitPosition                   
	/*0x000*/     UINT64       Owner : 1;            // 2 BitPosition                   
	/*0x000*/     UINT64       WriteThrough : 1;     // 3 BitPosition                   
	/*0x000*/     UINT64       CacheDisable : 1;     // 4 BitPosition                   
	/*0x000*/     UINT64       Accessed : 1;         // 5 BitPosition                   
	/*0x000*/     UINT64       Dirty : 1;            // 6 BitPosition                   
	/*0x000*/     UINT64       LargePage : 1;        // 7 BitPosition                   
	/*0x000*/     UINT64       Global : 1;           // 8 BitPosition                   
	/*0x000*/     UINT64       CopyOnWrite : 1;      // 9 BitPosition                   
	/*0x000*/     UINT64       Prototype : 1;        // 10 BitPosition                  
	/*0x000*/     UINT64       reserved0 : 1;        // 11 BitPosition                  
	/*0x000*/     UINT64       PageFrameNumber : 28; // 12 BitPosition                  
	/*0x000*/     UINT64       reserved1 : 12;       // 40 BitPosition                  
	/*0x000*/     UINT64       SoftwareWsIndex : 11; // 52 BitPosition                  
	/*0x000*/     UINT64       NoExecute : 1;        // 63 BitPosition                  
}HARDWARE_PTE, *PHARDWARE_PTE;


typedef struct _EX_FAST_REF      // 3 elements, 0x8 bytes (sizeof) 
{
	union                        // 3 elements, 0x8 bytes (sizeof) 
	{
		/*0x000*/         VOID*        Object;
		/*0x000*/         UINT64       RefCnt : 4; // 0 BitPosition                  
		/*0x000*/         UINT64       Value;
	};
}EX_FAST_REF, *PEX_FAST_REF;

////1
typedef struct _KGUARDED_MUTEX_S              // 7 elements, 0x38 bytes (sizeof) 
{
	/*0x000*/     LONG32       Count;
	/*0x004*/     UINT8        _PADDING0_[0x4];
	/*0x008*/     struct _KTHREAD* Owner;
	/*0x010*/     ULONG32      Contention;
	/*0x014*/     UINT8        _PADDING1_[0x4];
	/*0x018*/     struct _KGATE Gate;                     // 1 elements, 0x18 bytes (sizeof) 
	union                                   // 2 elements, 0x8 bytes (sizeof)  
	{
		struct                              // 2 elements, 0x8 bytes (sizeof)  
		{
			/*0x030*/             INT16        KernelApcDisable;
			/*0x032*/             INT16        SpecialApcDisable;
			/*0x034*/             UINT8        _PADDING2_[0x4];
		};
		/*0x030*/         ULONG32      CombinedApcDisable;
	};
}KGUARDED_MUTEX_S, *PKGUARDED_MUTEX_S;



typedef union _KGDTENTRY64_S                    // 7 elements, 0x10 bytes (sizeof) 
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
}KGDTENTRY64_S, *PKGDTENTRY64_S;



typedef union _KSTACK_COUNT           // 3 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     LONG32       Value;
	struct                            // 2 elements, 0x4 bytes (sizeof) 
	{
		/*0x000*/         ULONG32      State : 3;       // 0 BitPosition                  
		/*0x000*/         ULONG32      StackCount : 29; // 3 BitPosition                  
	};
}KSTACK_COUNT, *PKSTACK_COUNT;


typedef union _KEXECUTE_OPTIONS                           // 9 elements, 0x1 bytes (sizeof) 
{
	struct                                                // 8 elements, 0x1 bytes (sizeof) 
	{
		/*0x000*/         UINT8        ExecuteDisable : 1;                  // 0 BitPosition                  
		/*0x000*/         UINT8        ExecuteEnable : 1;                   // 1 BitPosition                  
		/*0x000*/         UINT8        DisableThunkEmulation : 1;           // 2 BitPosition                  
		/*0x000*/         UINT8        Permanent : 1;                       // 3 BitPosition                  
		/*0x000*/         UINT8        ExecuteDispatchEnable : 1;           // 4 BitPosition                  
		/*0x000*/         UINT8        ImageDispatchEnable : 1;             // 5 BitPosition                  
		/*0x000*/         UINT8        DisableExceptionChainValidation : 1; // 6 BitPosition                  
		/*0x000*/         UINT8        Spare : 1;                           // 7 BitPosition                  
	};
	/*0x000*/     UINT8        ExecuteOptions;
}KEXECUTE_OPTIONS, *PKEXECUTE_OPTIONS;


typedef struct _KAFFINITY_EX // 4 elements, 0x28 bytes (sizeof) 
{
	/*0x000*/     UINT16       Count;
	/*0x002*/     UINT16       Size;
	/*0x004*/     ULONG32      Reserved;
	/*0x008*/     UINT64       Bitmap[4];
}KAFFINITY_EX, *PKAFFINITY_EX;


typedef struct _KPROCESS                       // 37 elements, 0x160 bytes (sizeof) 
{
	/*0x000*/     struct _DISPATCHER_HEADER Header;          // 29 elements, 0x18 bytes (sizeof)  
	/*0x018*/     struct _LIST_ENTRY ProfileListHead;        // 2 elements, 0x10 bytes (sizeof)   
	/*0x028*/     UINT64       DirectoryTableBase;
	/*0x030*/     struct _LIST_ENTRY ThreadListHead;         // 2 elements, 0x10 bytes (sizeof)   
	/*0x040*/     UINT64       ProcessLock;
	/*0x048*/     struct _KAFFINITY_EX Affinity;             // 4 elements, 0x28 bytes (sizeof)   
	/*0x070*/     struct _LIST_ENTRY ReadyListHead;          // 2 elements, 0x10 bytes (sizeof)   
	/*0x080*/     struct _SINGLE_LIST_ENTRY SwapListEntry;   // 1 elements, 0x8 bytes (sizeof)    
	/*0x088*/     struct _KAFFINITY_EX ActiveProcessors;     // 4 elements, 0x28 bytes (sizeof)   
	union                                      // 2 elements, 0x4 bytes (sizeof)    
	{
		struct                                 // 5 elements, 0x4 bytes (sizeof)    
		{
			/*0x0B0*/             LONG32       AutoAlignment : 1;    // 0 BitPosition                     
			/*0x0B0*/             LONG32       DisableBoost : 1;     // 1 BitPosition                     
			/*0x0B0*/             LONG32       DisableQuantum : 1;   // 2 BitPosition                     
			/*0x0B0*/             ULONG32      ActiveGroupsMask : 4; // 3 BitPosition                     
			/*0x0B0*/             LONG32       ReservedFlags : 25;   // 7 BitPosition                     
		};
		/*0x0B0*/         LONG32       ProcessFlags;
	};
	/*0x0B4*/     CHAR         BasePriority;
	/*0x0B5*/     CHAR         QuantumReset;
	/*0x0B6*/     UINT8        Visited;
	/*0x0B7*/     UINT8        Unused3;
	/*0x0B8*/     ULONG32      ThreadSeed[4];
	/*0x0C8*/     UINT16       IdealNode[4];
	/*0x0D0*/     UINT16       IdealGlobalNode;
	/*0x0D2*/     union _KEXECUTE_OPTIONS Flags;             // 9 elements, 0x1 bytes (sizeof)    
	/*0x0D3*/     UINT8        Unused1;
	/*0x0D4*/     ULONG32      Unused2;
	/*0x0D8*/     ULONG32      Unused4;
	/*0x0DC*/     union _KSTACK_COUNT StackCount;            // 3 elements, 0x4 bytes (sizeof)    
	/*0x0E0*/     struct _LIST_ENTRY ProcessListEntry;       // 2 elements, 0x10 bytes (sizeof)   
	/*0x0F0*/     UINT64       CycleTime;
	/*0x0F8*/     ULONG32      KernelTime;
	/*0x0FC*/     ULONG32      UserTime;
	/*0x100*/     VOID*        InstrumentationCallback;
	/*0x108*/     union _KGDTENTRY64_S LdtSystemDescriptor;    // 7 elements, 0x10 bytes (sizeof)   
	/*0x118*/     VOID*        LdtBaseAddress;
	/*0x120*/     struct _KGUARDED_MUTEX_S LdtProcessLock;     // 7 elements, 0x38 bytes (sizeof)   
	/*0x158*/     UINT16       LdtFreeSelectorHint;
	/*0x15A*/     UINT16       LdtTableLength;
	/*0x15C*/     UINT8        _PADDING0_[0x4];
}KPROCESS, *PKPROCESS;


typedef struct _EPROCESS                                               // 135 elements, 0x4D0 bytes (sizeof) 
{
	/*0x000*/     struct _KPROCESS Pcb;                                              // 37 elements, 0x160 bytes (sizeof)  
	/*0x160*/     struct _EX_PUSH_LOCK ProcessLock;                                  // 7 elements, 0x8 bytes (sizeof)     
	/*0x168*/     union _LARGE_INTEGER CreateTime;                                   // 4 elements, 0x8 bytes (sizeof)     
	/*0x170*/     union _LARGE_INTEGER ExitTime;                                     // 4 elements, 0x8 bytes (sizeof)     
	/*0x178*/     struct _EX_RUNDOWN_REF RundownProtect;                             // 2 elements, 0x8 bytes (sizeof)     
	/*0x180*/     VOID*        UniqueProcessId;
	/*0x188*/     struct _LIST_ENTRY ActiveProcessLinks;                             // 2 elements, 0x10 bytes (sizeof)    
	/*0x198*/     UINT64       ProcessQuotaUsage[2];
	/*0x1A8*/     UINT64       ProcessQuotaPeak[2];
	/*0x1B8*/     UINT64       CommitCharge;
	/*0x1C0*/     struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;
	/*0x1C8*/     struct _PS_CPU_QUOTA_BLOCK* CpuQuotaBlock;
	/*0x1D0*/     UINT64       PeakVirtualSize;
	/*0x1D8*/     UINT64       VirtualSize;
	/*0x1E0*/     struct _LIST_ENTRY SessionProcessLinks;                            // 2 elements, 0x10 bytes (sizeof)    
	/*0x1F0*/     VOID*        DebugPort;
	union                                                              // 3 elements, 0x8 bytes (sizeof)     
	{
		/*0x1F8*/         VOID*        ExceptionPortData;
		/*0x1F8*/         UINT64       ExceptionPortValue;
		/*0x1F8*/         UINT64       ExceptionPortState : 3;                           // 0 BitPosition                      
	};
	/*0x200*/     struct _HANDLE_TABLE* ObjectTable;
	/*0x208*/     struct _EX_FAST_REF Token;                                         // 3 elements, 0x8 bytes (sizeof)     
	/*0x210*/     UINT64       WorkingSetPage;
	/*0x218*/     struct _EX_PUSH_LOCK AddressCreationLock;                          // 7 elements, 0x8 bytes (sizeof)     
	/*0x220*/     struct _ETHREAD* RotateInProgress;
	/*0x228*/     struct _ETHREAD* ForkInProgress;
	/*0x230*/     UINT64       HardwareTrigger;
	/*0x238*/     struct _MM_AVL_TABLE* PhysicalVadRoot;
	/*0x240*/     VOID*        CloneRoot;
	/*0x248*/     UINT64       NumberOfPrivatePages;
	/*0x250*/     UINT64       NumberOfLockedPages;
	/*0x258*/     VOID*        Win32Process;
	/*0x260*/     struct _EJOB* Job;
	/*0x268*/     VOID*        SectionObject;
	/*0x270*/     VOID*        SectionBaseAddress;
	/*0x278*/     ULONG32      Cookie;
	/*0x27C*/     ULONG32      UmsScheduledThreads;
	/*0x280*/     struct _PAGEFAULT_HISTORY* WorkingSetWatch;
	/*0x288*/     VOID*        Win32WindowStation;
	/*0x290*/     VOID*        InheritedFromUniqueProcessId;
	/*0x298*/     VOID*        LdtInformation;
	/*0x2A0*/     VOID*        Spare;
	/*0x2A8*/     UINT64       ConsoleHostProcess;
	/*0x2B0*/     VOID*        DeviceMap;
	/*0x2B8*/     VOID*        EtwDataSource;
	/*0x2C0*/     VOID*        FreeTebHint;
	/*0x2C8*/     VOID*        FreeUmsTebHint;
	union                                                              // 2 elements, 0x8 bytes (sizeof)     
	{
		/*0x2D0*/         struct _HARDWARE_PTE PageDirectoryPte;                         // 16 elements, 0x8 bytes (sizeof)    
		/*0x2D0*/         UINT64       Filler;
	};
	/*0x2D8*/     VOID*        Session;
	/*0x2E0*/     UINT8        ImageFileName[15];
	/*0x2EF*/     UINT8        PriorityClass;
	/*0x2F0*/     struct _LIST_ENTRY JobLinks;                                       // 2 elements, 0x10 bytes (sizeof)    
	/*0x300*/     VOID*        LockedPagesList;
	/*0x308*/     struct _LIST_ENTRY ThreadListHead;                                 // 2 elements, 0x10 bytes (sizeof)    
	/*0x318*/     VOID*        SecurityPort;
	/*0x320*/     VOID*        Wow64Process;
	/*0x328*/     ULONG32      ActiveThreads;
	/*0x32C*/     ULONG32      ImagePathHash;
	/*0x330*/     ULONG32      DefaultHardErrorProcessing;
	/*0x334*/     LONG32       LastThreadExitStatus;
	/*0x338*/     struct _PEB* Peb;
	/*0x340*/     struct _EX_FAST_REF PrefetchTrace;                                 // 3 elements, 0x8 bytes (sizeof)     
	/*0x348*/     union _LARGE_INTEGER ReadOperationCount;                           // 4 elements, 0x8 bytes (sizeof)     
	/*0x350*/     union _LARGE_INTEGER WriteOperationCount;                          // 4 elements, 0x8 bytes (sizeof)     
	/*0x358*/     union _LARGE_INTEGER OtherOperationCount;                          // 4 elements, 0x8 bytes (sizeof)     
	/*0x360*/     union _LARGE_INTEGER ReadTransferCount;                            // 4 elements, 0x8 bytes (sizeof)     
	/*0x368*/     union _LARGE_INTEGER WriteTransferCount;                           // 4 elements, 0x8 bytes (sizeof)     
	/*0x370*/     union _LARGE_INTEGER OtherTransferCount;                           // 4 elements, 0x8 bytes (sizeof)     
	/*0x378*/     UINT64       CommitChargeLimit;
	/*0x380*/     UINT64       CommitChargePeak;
	/*0x388*/     VOID*        AweInfo;
	/*0x390*/     struct _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo; // 1 elements, 0x8 bytes (sizeof)     
	/*0x398*/     struct _MMSUPPORT Vm;                                              // 21 elements, 0x88 bytes (sizeof)   
	/*0x420*/     struct _LIST_ENTRY MmProcessLinks;                                 // 2 elements, 0x10 bytes (sizeof)    
	/*0x430*/     VOID*        HighestUserAddress;
	/*0x438*/     ULONG32      ModifiedPageCount;
	union                                                              // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x43C*/         ULONG32      Flags2;
		struct                                                         // 20 elements, 0x4 bytes (sizeof)    
		{
			/*0x43C*/             ULONG32      JobNotReallyActive : 1;                       // 0 BitPosition                      
			/*0x43C*/             ULONG32      AccountingFolded : 1;                         // 1 BitPosition                      
			/*0x43C*/             ULONG32      NewProcessReported : 1;                       // 2 BitPosition                      
			/*0x43C*/             ULONG32      ExitProcessReported : 1;                      // 3 BitPosition                      
			/*0x43C*/             ULONG32      ReportCommitChanges : 1;                      // 4 BitPosition                      
			/*0x43C*/             ULONG32      LastReportMemory : 1;                         // 5 BitPosition                      
			/*0x43C*/             ULONG32      ReportPhysicalPageChanges : 1;                // 6 BitPosition                      
			/*0x43C*/             ULONG32      HandleTableRundown : 1;                       // 7 BitPosition                      
			/*0x43C*/             ULONG32      NeedsHandleRundown : 1;                       // 8 BitPosition                      
			/*0x43C*/             ULONG32      RefTraceEnabled : 1;                          // 9 BitPosition                      
			/*0x43C*/             ULONG32      NumaAware : 1;                                // 10 BitPosition                     
			/*0x43C*/             ULONG32      ProtectedProcess : 1;                         // 11 BitPosition                     
			/*0x43C*/             ULONG32      DefaultPagePriority : 3;                      // 12 BitPosition                     
			/*0x43C*/             ULONG32      PrimaryTokenFrozen : 1;                       // 15 BitPosition                     
			/*0x43C*/             ULONG32      ProcessVerifierTarget : 1;                    // 16 BitPosition                     
			/*0x43C*/             ULONG32      StackRandomizationDisabled : 1;               // 17 BitPosition                     
			/*0x43C*/             ULONG32      AffinityPermanent : 1;                        // 18 BitPosition                     
			/*0x43C*/             ULONG32      AffinityUpdateEnable : 1;                     // 19 BitPosition                     
			/*0x43C*/             ULONG32      PropagateNode : 1;                            // 20 BitPosition                     
			/*0x43C*/             ULONG32      ExplicitAffinity : 1;                         // 21 BitPosition                     
		};
	};
	union                                                              // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x440*/         ULONG32      Flags;
		struct                                                         // 29 elements, 0x4 bytes (sizeof)    
		{
			/*0x440*/             ULONG32      CreateReported : 1;                           // 0 BitPosition                      
			/*0x440*/             ULONG32      NoDebugInherit : 1;                           // 1 BitPosition                      
			/*0x440*/             ULONG32      ProcessExiting : 1;                           // 2 BitPosition                      
			/*0x440*/             ULONG32      ProcessDelete : 1;                            // 3 BitPosition                      
			/*0x440*/             ULONG32      Wow64SplitPages : 1;                          // 4 BitPosition                      
			/*0x440*/             ULONG32      VmDeleted : 1;                                // 5 BitPosition                      
			/*0x440*/             ULONG32      OutswapEnabled : 1;                           // 6 BitPosition                      
			/*0x440*/             ULONG32      Outswapped : 1;                               // 7 BitPosition                      
			/*0x440*/             ULONG32      ForkFailed : 1;                               // 8 BitPosition                      
			/*0x440*/             ULONG32      Wow64VaSpace4Gb : 1;                          // 9 BitPosition                      
			/*0x440*/             ULONG32      AddressSpaceInitialized : 2;                  // 10 BitPosition                     
			/*0x440*/             ULONG32      SetTimerResolution : 1;                       // 12 BitPosition                     
			/*0x440*/             ULONG32      BreakOnTermination : 1;                       // 13 BitPosition                     
			/*0x440*/             ULONG32      DeprioritizeViews : 1;                        // 14 BitPosition                     
			/*0x440*/             ULONG32      WriteWatch : 1;                               // 15 BitPosition                     
			/*0x440*/             ULONG32      ProcessInSession : 1;                         // 16 BitPosition                     
			/*0x440*/             ULONG32      OverrideAddressSpace : 1;                     // 17 BitPosition                     
			/*0x440*/             ULONG32      HasAddressSpace : 1;                          // 18 BitPosition                     
			/*0x440*/             ULONG32      LaunchPrefetched : 1;                         // 19 BitPosition                     
			/*0x440*/             ULONG32      InjectInpageErrors : 1;                       // 20 BitPosition                     
			/*0x440*/             ULONG32      VmTopDown : 1;                                // 21 BitPosition                     
			/*0x440*/             ULONG32      ImageNotifyDone : 1;                          // 22 BitPosition                     
			/*0x440*/             ULONG32      PdeUpdateNeeded : 1;                          // 23 BitPosition                     
			/*0x440*/             ULONG32      VdmAllowed : 1;                               // 24 BitPosition                     
			/*0x440*/             ULONG32      CrossSessionCreate : 1;                       // 25 BitPosition                     
			/*0x440*/             ULONG32      ProcessInserted : 1;                          // 26 BitPosition                     
			/*0x440*/             ULONG32      DefaultIoPriority : 3;                        // 27 BitPosition                     
			/*0x440*/             ULONG32      ProcessSelfDelete : 1;                        // 30 BitPosition                     
			/*0x440*/             ULONG32      SetTimerResolutionLink : 1;                   // 31 BitPosition                     
		};
	};
	/*0x444*/     LONG32       ExitStatus;
	/*0x448*/     struct _MM_AVL_TABLE VadRoot;                                      // 6 elements, 0x40 bytes (sizeof)    
	/*0x488*/     struct _ALPC_PROCESS_CONTEXT AlpcContext;                          // 3 elements, 0x20 bytes (sizeof)    
	/*0x4A8*/     struct _LIST_ENTRY TimerResolutionLink;                            // 2 elements, 0x10 bytes (sizeof)    
	/*0x4B8*/     ULONG32      RequestedTimerResolution;
	/*0x4BC*/     ULONG32      ActiveThreadsHighWatermark;
	/*0x4C0*/     ULONG32      SmallestTimerResolution;
	/*0x4C4*/     UINT8        _PADDING0_[0x4];
	/*0x4C8*/     struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;
}EPROCESS, *PEPROCESS;

