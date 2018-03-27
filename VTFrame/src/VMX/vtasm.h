#pragma once
#include "VMX.h"

VOID VmxVMEntry();
VOID VmxpResume();
VOID VmxVMCleanup();
void __stdcall AsmWriteCR2(_In_ ULONG_PTR cr2_value);