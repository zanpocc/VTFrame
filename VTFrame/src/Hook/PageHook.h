#pragma once
#include <ntddk.h>


typedef struct _HOOK_CONTEXT
{
	BOOLEAN Hook;           // TRUE to hook page, FALSE to unhook
	ULONG64 DataPagePFN;    // Physical data page PFN
	ULONG64 CodePagePFN;    // Physical code page PFN
} HOOK_CONTEXT, *PHOOK_CONTEXT;

typedef enum _PAGE_TYPE
{
	DATA_PAGE = 0,
	CODE_PAGE = 1,
} PAGE_TYPE;

typedef struct _PAGE_HOOK_ENTRY
{
	LIST_ENTRY Link;
	PVOID OriginalPtr;      // Original function VA
	PVOID DataPageVA;       // Data page VA
	ULONG64 DataPagePFN;    // Data page PFN
	ULONG64 DataPhys;
	PVOID CodePageVA;       // Executable page VA
	ULONG64 CodePagePFN;    // Executable page PFN
	ULONG OriginalSize;     // Size of original data
	UCHAR OriginalData[80]; // Original bytes + jump
} PAGE_HOOK_ENTRY, *PPAGE_HOOK_ENTRY;


NTSTATUS UnPageHook();
NTSTATUS PHHook(IN PVOID pFunc, IN PVOID pHook);
PPAGE_HOOK_ENTRY PHGetHookEntry(IN PVOID ptr);
NTSTATUS ModifyAddressValue(PVOID address);
NTSTATUS ModifyAddressValue2(PVOID address, PVOID pByte, ULONG length, PVOID address1, PVOID pByte1, ULONG length1);