#pragma once
#include <ntddk.h>
#include "VMX.h"

NTKERNELAPI UCHAR* PsGetProcessImageFileName(PEPROCESS process);

EXTERN_C VOID VmxpExitHandler(IN PMYCONTEXT Context);
inline VOID ToggleMTF(IN BOOLEAN State);
VOID VmExitMTF(IN PGUEST_STATE GuestState);
VOID VmExitMSRWrite(IN PGUEST_STATE GuestState);
VOID VmExitMSRRead(IN PGUEST_STATE GuestState);
VOID VmExitCR(IN PGUEST_STATE GuestState);
VOID VmExitDR(IN PGUEST_STATE GuestState);
VOID VmExitINVD(IN PGUEST_STATE GuestState);
VOID VmExitCPUID(IN PGUEST_STATE GuestState);
VOID VmExitRdtscp(IN PGUEST_STATE GuestState);
VOID VmExitRdtsc(IN PGUEST_STATE GuestState);
VOID VmExitVmCall(IN PGUEST_STATE GuestState);
VOID VmExitEptMisconfig(IN PGUEST_STATE GuestState);
VOID VmExitEptViolation(IN PGUEST_STATE GuestState);
//VOID VmxInjectEvent(INTERRUPT_TYPE InterruptType, VECTOR_EXCEPTION Vector, ULONG WriteLength,ULONG valid);
inline VOID VmxpAdvanceEIP(IN PGUEST_STATE GuestState);