#include <Windows.h>
#include "haloshall.h"
#include "Common.h"

#define PREV -32
#define NEXT 32
#define MAX_NEIGHBOURS 500


static DWORD64 djb2(PBYTE str);
static PTEB RtlGetThreadEnvironmentBlock(VOID);


DWORD InitSyscallInfo(_Out_ PSYSCALL_INFO pSyscallInfo, _In_ DWORD64 dwHash)
{
	BYTE low, high;

	PTEB pCurrentTeb;
	PPEB pCurrentPeb;
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry;
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;

	PDWORD pdwFunctions;
	PDWORD pdwNames;
	PWORD pwNameOrdinals;

	PCHAR pcName = NULL;
	PVOID pAddress = NULL;
	ULONG_PTR ulpAddress;

	pSyscallInfo->dwSsn = -1;
	pSyscallInfo->pAddress = NULL;
	pSyscallInfo->pSyscallRet = NULL;

#if _WIN64
	pCurrentTeb = (PTEB)__readgsqword(0x30);
#else
	pCurrentTeb = (PTEB)__readfsdword(0x16);
#endif
	pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;

	if (!pCurrentPeb || pCurrentPeb->OSMajorVersion != 0x0a)
		return -1;

	pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || !pImageExportDirectory)
		return -1;

	PVOID pModuleBase = pLdrDataEntry->DllBase;

	pdwFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	pdwNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	pwNameOrdinals = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD i = 0; i < pImageExportDirectory->NumberOfNames; i++) {
		pcName = (PCHAR)((PBYTE)pModuleBase + pdwNames[i]);
		pAddress = (PBYTE)pModuleBase + pdwFunctions[pwNameOrdinals[i]];

		if (HASH((PBYTE)pcName) != dwHash)
			continue;

		// Unhooked syscall
		if (*(PBYTE)pAddress == 0x4c &&
			*((PBYTE)pAddress + 1) == 0x8b &&
			*((PBYTE)pAddress + 2) == 0xd1 &&
			*((PBYTE)pAddress + 3) == 0xb8 &&
			*((PBYTE)pAddress + 6) == 0x00 &&
			*((PBYTE)pAddress + 7) == 0x00) {

			high = *((PBYTE)pAddress + 5);
			low = *((PBYTE)pAddress + 4);
			pSyscallInfo->pAddress = pAddress;
			pSyscallInfo->dwSsn = (high << 8) | low;
			break;
		}

		// Hooked syscall
		if (*((PBYTE)pAddress) != 0xe9 && *((PBYTE)pAddress + 3) != 0xe9)
			continue;

		for (WORD idx = 1; idx <= MAX_NEIGHBOURS; idx++) {
			if (*((PBYTE)pAddress + 0 + idx * NEXT) == 0x4c &&  
				*((PBYTE)pAddress + 1 + idx * NEXT) == 0x8b &&  
				*((PBYTE)pAddress + 2 + idx * NEXT) == 0xd1 &&  
				*((PBYTE)pAddress + 3 + idx * NEXT) == 0xb8 &&  
				*((PBYTE)pAddress + 6 + idx * NEXT) == 0x00 &&  
				*((PBYTE)pAddress + 7 + idx * NEXT) == 0x00) {

				high = *((PBYTE)pAddress + 5 + idx * NEXT);
				low = *((PBYTE)pAddress + 4 + idx * NEXT);
				pSyscallInfo->pAddress = pAddress;
				pSyscallInfo->dwSsn = ((high << 8) | low) - idx;
				break;
			}

			if (*((PBYTE)pAddress + 0 + idx * PREV) == 0x4c &&  
				*((PBYTE)pAddress + 1 + idx * PREV) == 0x8b &&  
				*((PBYTE)pAddress + 2 + idx * PREV) == 0xd1 &&  
				*((PBYTE)pAddress + 3 + idx * PREV) == 0xb8 &&  
				*((PBYTE)pAddress + 6 + idx * PREV) == 0x00 &&  
				*((PBYTE)pAddress + 7 + idx * PREV) == 0x00) {

				high = *((PBYTE)pAddress + 5 + idx * PREV);
				low = *((PBYTE)pAddress + 4 + idx * PREV);
				pSyscallInfo->pAddress = pAddress;
				pSyscallInfo->dwSsn = ((high << 8) | low) + idx;
				break;
			}
		}
	}

	if (pSyscallInfo->dwSsn < 0)
		return -1;

	ulpAddress = (ULONG_PTR)pSyscallInfo->pAddress + 0x40;
	for (DWORD i = 0, j = 1; i <= 512; i++, j++) {
		if (*((PBYTE)ulpAddress + i) == 0x0f && *((PBYTE)ulpAddress + j) == 0x05) {
			pSyscallInfo->pSyscallRet = (PVOID)((ULONG_PTR)ulpAddress + i);
			break;
		}
	}

	if (!pSyscallInfo->pSyscallRet) {
		pSyscallInfo->pAddress = NULL;
		pSyscallInfo->pSyscallRet = NULL;
		return (pSyscallInfo->dwSsn = -1);
	}

	return pSyscallInfo->dwSsn;
}

DWORD64 djb2(PBYTE str)
{
	DWORD64 dwHash = 0x7734773477347734;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}

static PTEB RtlGetThreadEnvironmentBlock(VOID)
{
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}