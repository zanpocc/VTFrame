#include "GetUnExportFunAddress.h"

#include "LDasm.h"

//Globel
PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable;

//获取函数中调用的函数地址
ULONG64 GetSubFunInFunction(
	PVOID pFun, //主函数地址
	ULONG index //函数的第几个子函数地址,从0开始
)
{
	ULONG len = 0;
	ULONG i = 0;
	ULONG64 funSize = 0;
	PVOID pCurrent = pFun, pEnd = 0;
	funSize = SizeOfProc(pFun);
	pEnd = (PVOID)(funSize + (ULONG64)pCurrent);

	ldasm_data ld = { 0 };

	do {
		len = ldasm(pCurrent, &ld, TRUE);
		//找到了E8 call调用
		if (len == 5 && *(PUCHAR)pCurrent == 0xE8)
		{
			if (i != index)
			{
				i++;
				pCurrent = (PVOID)((ULONG64)pCurrent + (ULONG64)len);
				continue;
			}
			//获得函数地址
			ULONG64 pTarget = (ULONG64)pCurrent;
			ULONG order = 0;
			memcpy(&order, (PVOID)(pTarget + 1), (size_t)4);
			LARGE_INTEGER temp = { 0 };
			temp.QuadPart = pTarget;
			temp.LowPart = temp.LowPart + order + 5;
			return temp.QuadPart;
		}

		pCurrent = (PVOID)((ULONG64)pCurrent + (ULONG64)len);
	} while ((ULONG64)pCurrent <= (ULONG64)pFun + funSize);

	return 0;

}


//获取函数中调用的函数地址,针对没有返回指令的函数
ULONG64 GetSubFunInFunction2(
	PVOID pFun, //主函数地址
	ULONG index //函数的第几个子函数地址,从0开始
)
{
	ULONG len = 0;
	ULONG i = 0;
	ULONG64 funSize = 0;
	PVOID pCurrent = pFun, pEnd = 0;
	funSize = 0x500;
	pEnd = (PVOID)(funSize + (ULONG64)pCurrent);

	ldasm_data ld = { 0 };

	do {
		len = ldasm(pCurrent, &ld, TRUE);
		//找到了E8 call调用
		if (len == 5 && *(PUCHAR)pCurrent == 0xE8)
		{
			if (i != index)
			{
				i++;
				pCurrent = (PVOID)((ULONG64)pCurrent + (ULONG64)len);
				continue;
			}
	
			//获得函数地址
			ULONG64 pTarget = (ULONG64)pCurrent;
			ULONG order = 0;
			memcpy(&order, (PVOID)(pTarget + 1), (size_t)4);
			LARGE_INTEGER temp = { 0 };
			temp.QuadPart = pTarget;
			temp.LowPart = temp.LowPart + order + 5;
			return temp.QuadPart;
		}

		pCurrent = (PVOID)((ULONG64)pCurrent + (ULONG64)len);
	} while ((ULONG64)pCurrent <= (ULONG64)pFun + funSize);

	return 0;

}

//获得SSDT表的地址
ULONGLONG MyGetKeServiceDescriptorTable64() //我的方法
{
	//获取 KiSystemCall64 的地址
	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
	PUCHAR EndSearchAddress = StartSearchAddress + 0x500;
	PUCHAR i = NULL;
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	ULONG templong = 0;
	ULONGLONG addr = 0;
	for (i = StartSearchAddress; i < EndSearchAddress; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			b1 = *i;
			b2 = *(i + 1);
			b3 = *(i + 2);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15) //4c8d15   SSDT 的特征码
			{
				memcpy(&templong, i + 3, 4);
				addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
				return addr;
			}
		}
	}
	return 0;
}

//获得SSDT表中函数的地址
ULONGLONG GetSSDTFunAddrress(ULONG id)
{
	LONG dwtmp = 0;
	PULONG ServiceTableBase = NULL;

	KeServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)MyGetKeServiceDescriptorTable64();
	ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	dwtmp = ServiceTableBase[id];
	dwtmp = dwtmp >> 4;
	return (LONGLONG)dwtmp + (ULONGLONG)ServiceTableBase;
}

SIZE_T GetNtosFunctionAddress(PCWSTR FunctionName)
{
	UNICODE_STRING UniCodeFunctionName;
	RtlInitUnicodeString(&UniCodeFunctionName, FunctionName);
	return (SIZE_T)MmGetSystemRoutineAddress(&UniCodeFunctionName);
}

//获得Zw函数地址
SIZE_T GetZwFunAddress(ULONG id)
{
	SIZE_T f0Addr = 0, RetAddr = 0, pZwClose = GetNtosFunctionAddress(L"ZwClose");
	ULONG ZwFunLen = 0, ZwCloseIndex = 0;
#ifdef AMD64
	ZwFunLen = 32;
	memcpy(&ZwCloseIndex, (PUCHAR)pZwClose + 21, 4);
#else
	ZwFunLen = 20;
	memcpy(&ZwCloseIndex, (PUCHAR)pZwClose + 1, 4);
#endif
	f0Addr = pZwClose - ZwCloseIndex*ZwFunLen;
	RetAddr = f0Addr + id*ZwFunLen;
	return RetAddr;
}


