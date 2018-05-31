#include "PageHook.h"

#include "InlineHook.h"
#include "../Util/LDasm.h"
#include "../Include/common.h"
#include "../VMX/vtasm.h"

LIST_ENTRY g_PageList = { 0 };


PPAGE_HOOK_ENTRY PHGetHookEntry(IN PVOID ptr)
{
	if (g_PageList.Flink == NULL || IsListEmpty(&g_PageList))
		return NULL;

	for (PLIST_ENTRY pListEntry = g_PageList.Flink; pListEntry != &g_PageList; pListEntry = pListEntry->Flink)
	{
		PPAGE_HOOK_ENTRY pEntry = CONTAINING_RECORD(pListEntry, PAGE_HOOK_ENTRY, Link);
		if (pEntry->OriginalPtr == ptr)
			return pEntry;
	}

	return NULL;
}

PPAGE_HOOK_ENTRY PHGetHookEntryByPage(IN PVOID ptr, IN PAGE_TYPE Type)
{
	if (g_PageList.Flink == NULL || IsListEmpty(&g_PageList))
		return NULL;

	PVOID page = PAGE_ALIGN(ptr);
	for (PLIST_ENTRY pListEntry = g_PageList.Flink; pListEntry != &g_PageList; pListEntry = pListEntry->Flink)
	{
		//CONTAINING_RECORD作用是根据结构类型和它的一个实参获得结构的开始位置
		PPAGE_HOOK_ENTRY pEntry = CONTAINING_RECORD(pListEntry, PAGE_HOOK_ENTRY, Link);
		if ((Type == DATA_PAGE && pEntry->DataPageVA == page) || (Type == CODE_PAGE && pEntry->CodePageVA == page))
			return pEntry;
	}

	return NULL;
}

//保存原函数前N字节+跳回到原函数+N后面，pSize是原函数前N个字节大小,OriginalStore是原函数首地址
NTSTATUS PHpCopyCode(IN PVOID pFunc, OUT PUCHAR OriginalStore, OUT PULONG pSize)
{
	ULONG len = 0;
	JUMP_THUNK jmpRet = { 0 };
	ldasm_data data = { 0 };
	KIRQL irql = 0;

	do
	{
		len += ldasm(pFunc, &data, TRUE);
	} while (len < sizeof(JUMP_THUNK));

	//拷贝原始指令处前N个字节到我们Hook结构充当原始函数入口
	RtlCopyMemory(OriginalStore, pFunc, len);

	//跳回到原始函数前N个字节后
	InitJumpThunk(&jmpRet, (ULONG64)pFunc + len);

	RtlCopyMemory((PVOID)((ULONG64)OriginalStore + len), &jmpRet, sizeof(JUMP_THUNK));

	*pSize = len;

	return STATUS_SUCCESS;
}

NTSTATUS PHHook(IN PVOID pFunc, IN PVOID pHook)
{
	PUCHAR CodePage = NULL;
	BOOLEAN Newpage = FALSE;
	PHYSICAL_ADDRESS phys = { 0 };
	phys.QuadPart = MAXULONG64;

	
	//是否已经HOOK了
	PPAGE_HOOK_ENTRY pEntry = PHGetHookEntryByPage(pFunc, DATA_PAGE);
	if (pEntry != NULL)
	{
		CodePage = pEntry->CodePageVA;
	}
	else
	{
		//申请一页内存
		CodePage = MmAllocateContiguousMemory(PAGE_SIZE, phys);
		
		Newpage = TRUE;
	}

	if (CodePage == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	//申请一个PageHookEntry结构插入到PageHook链表
	PPAGE_HOOK_ENTRY pHookEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(PAGE_HOOK_ENTRY), 'VTF');
	if (pHookEntry == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	RtlZeroMemory(pHookEntry, sizeof(PAGE_HOOK_ENTRY));
	RtlCopyMemory(CodePage, PAGE_ALIGN(pFunc), PAGE_SIZE);

	//拷贝原始的数据到PageHookEntry，emmmm保存这个是为了调用原来的函数
	NTSTATUS status = PHpCopyCode(pFunc, pHookEntry->OriginalData, &pHookEntry->OriginalSize);
	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(pHookEntry, 'VTF');
		return status;
	}

	//页面偏移
	//PAGE_ALIGN宏作用其实就是取pFunc的高52位的值（将低12位清零）,这样就得到了虚拟地址的页面偏移
	ULONG_PTR page_offset = (ULONG_PTR)pFunc - (ULONG_PTR)PAGE_ALIGN(pFunc);
	
	//构建一个到Hook函数的跳转
	//这时我们申请的页内存原函数处的值就是一跳到我们Hook函数处的跳转指令
	JUMP_THUNK thunk = { 0 };
	InitJumpThunk(&thunk, (ULONG64)pHook);
	RtlZeroMemory(CodePage + page_offset,pHookEntry->OriginalSize);
	memcpy(CodePage + page_offset, &thunk, sizeof(thunk));

	//原始和目标
	pHookEntry->OriginalPtr = 0;
	pHookEntry->DataPageVA = PAGE_ALIGN(pFunc);
	pHookEntry->DataPagePFN = PFN(MmGetPhysicalAddress(pFunc).QuadPart);
	pHookEntry->CodePageVA = CodePage;
	pHookEntry->CodePagePFN = PFN(MmGetPhysicalAddress(CodePage).QuadPart);

	// 加入PageHook链表
	if (g_PageList.Flink == NULL)
		InitializeListHead(&g_PageList);
	InsertTailList(&g_PageList, &pHookEntry->Link);

	// 进入VMM开启HOOK
	if (Newpage)
	{
		for (int i = 0; i < KeNumberProcessors; i++)
		{
			KeSetSystemAffinityThread((KAFFINITY)(1 << i));

			//执行指定代码
			__vmx_vmcall(VTFrame_HOOK_PAGE, pHookEntry->DataPagePFN, pHookEntry->CodePagePFN,0);

			KeRevertToUserAffinityThread();
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS ModifyAddressValue(PVOID address,PVOID pByte,ULONG length)
{

	PUCHAR CodePage = NULL;
	BOOLEAN Newpage = FALSE;
	PHYSICAL_ADDRESS phys = { 0 };
	phys.QuadPart = MAXULONG64;


	//是否已经HOOK了
	PPAGE_HOOK_ENTRY pEntry = PHGetHookEntryByPage(address, DATA_PAGE);
	if (pEntry != NULL)
	{
		CodePage = pEntry->CodePageVA;
	}
	else
	{
		//申请一页内存
		CodePage = MmAllocateContiguousMemory(PAGE_SIZE, phys);
		Newpage = TRUE;
	}

	if (CodePage == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	//申请一个PageHookEntry结构插入到PageHook链表
	PPAGE_HOOK_ENTRY pHookEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(PAGE_HOOK_ENTRY), 'VTF');
	if (pHookEntry == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	RtlZeroMemory(pHookEntry, sizeof(PAGE_HOOK_ENTRY));
	//拷贝原始页数据到新申请的页面
	
	
	RtlCopyMemory(CodePage, PAGE_ALIGN(address), PAGE_SIZE);

	

	//页面偏移
	//PAGE_ALIGN宏作用其实就是取pFunc的高52位的值（将低12位清零）,这样就得到了虚拟地址的页面偏移
	ULONG_PTR page_offset = (ULONG_PTR)address - (ULONG_PTR)PAGE_ALIGN(address);

	//覆盖原页面处的内存
	RtlCopyMemory(CodePage+page_offset, pByte, length);

	//原始和目标
	pHookEntry->OriginalPtr = address;
	pHookEntry->DataPageVA = PAGE_ALIGN(address);
	pHookEntry->DataPagePFN = PFN(MmGetPhysicalAddress(address).QuadPart);
	pHookEntry->DataPhys = MmGetPhysicalAddress(address).QuadPart;
	pHookEntry->CodePageVA = CodePage;
	pHookEntry->CodePagePFN = PFN(MmGetPhysicalAddress(CodePage).QuadPart);

	// 加入PageHook链表
	if (g_PageList.Flink == NULL)
		InitializeListHead(&g_PageList);
	InsertTailList(&g_PageList, &pHookEntry->Link);
	

	// 进入VMM开启HOOK
	if (Newpage)
	{
		for (int i = 0; i < KeNumberProcessors; i++)
		{
			KeSetSystemAffinityThread((KAFFINITY)(1 << i));

			//执行指定代码
			__vmx_vmcall(VTFrame_HOOK_PAGE, pHookEntry->DataPagePFN, pHookEntry->CodePagePFN, 0);

			KeRevertToUserAffinityThread();
		}
	}

	return STATUS_SUCCESS;
}


NTSTATUS ModifyAddressValue2(PVOID address, PVOID pByte, ULONG length, PVOID address1, PVOID pByte1, ULONG length1)
{

	PUCHAR CodePage = NULL;
	BOOLEAN Newpage = FALSE;
	PHYSICAL_ADDRESS phys = { 0 };
	phys.QuadPart = MAXULONG64;


	//是否已经HOOK了
	PPAGE_HOOK_ENTRY pEntry = PHGetHookEntryByPage(address, DATA_PAGE);
	if (pEntry != NULL)
	{
		CodePage = pEntry->CodePageVA;
	}
	else
	{
		//申请一页内存
		CodePage = MmAllocateContiguousMemory(PAGE_SIZE, phys);
		Newpage = TRUE;
	}

	if (CodePage == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	//申请一个PageHookEntry结构插入到PageHook链表
	PPAGE_HOOK_ENTRY pHookEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(PAGE_HOOK_ENTRY), 'VTF');
	if (pHookEntry == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	RtlZeroMemory(pHookEntry, sizeof(PAGE_HOOK_ENTRY));
	//拷贝原始页数据到新申请的页面

	RtlCopyMemory(CodePage, PAGE_ALIGN(address), PAGE_SIZE);

	//页面偏移
	//PAGE_ALIGN宏作用其实就是取pFunc的高52位的值（将低12位清零）,这样就得到了虚拟地址的页面偏移
	ULONG_PTR page_offset = (ULONG_PTR)address - (ULONG_PTR)PAGE_ALIGN(address);
	ULONG_PTR page_offset1 = (ULONG_PTR)address1 - (ULONG_PTR)PAGE_ALIGN(address1);

	//覆盖原页面处的内存
	RtlCopyMemory(CodePage + page_offset, pByte, length);
	RtlCopyMemory(CodePage + page_offset1, pByte1, length1);

	//原始和目标
	pHookEntry->OriginalPtr = address;
	pHookEntry->DataPageVA = PAGE_ALIGN(address);
	pHookEntry->DataPagePFN = PFN(MmGetPhysicalAddress(address).QuadPart);
	pHookEntry->CodePageVA = CodePage;
	pHookEntry->CodePagePFN = PFN(MmGetPhysicalAddress(CodePage).QuadPart);

	// 加入PageHook链表
	if (g_PageList.Flink == NULL)
		InitializeListHead(&g_PageList);
	InsertTailList(&g_PageList, &pHookEntry->Link);


	// 进入VMM开启HOOK
	if (Newpage)
	{
		for (int i = 0; i < KeNumberProcessors; i++)
		{
			KeSetSystemAffinityThread((KAFFINITY)(1 << i));

			//执行指定代码
			__vmx_vmcall(VTFrame_HOOK_PAGE, pHookEntry->DataPagePFN, pHookEntry->CodePagePFN, 0);

			KeRevertToUserAffinityThread();
		}
	}

	return STATUS_SUCCESS;
}


NTSTATUS UnPageHook() 
{
	for (PLIST_ENTRY pListEntry = g_PageList.Flink; pListEntry != &g_PageList; pListEntry = pListEntry->Flink)
	{
		PPAGE_HOOK_ENTRY pEntry = NULL;
		pEntry = CONTAINING_RECORD(pListEntry, PAGE_HOOK_ENTRY, Link);

		for (int i = 0; i < KeNumberProcessors; i++)
		{
			KeSetSystemAffinityThread((KAFFINITY)(1 << i));

			//执行指定代码
			__vmx_vmcall(VTFrame_UNHOOK_PAGE, pEntry->DataPagePFN, 0, 0);

			KeRevertToUserAffinityThread();
		}
		RemoveEntryList(pListEntry);
		
	}

	return STATUS_SUCCESS;
	
}
