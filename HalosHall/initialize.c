#include <Windows.h>

#include "Common.h"
#include "haloshall.h"

NT_SYSCALL SyscallInfoTable = { 0 };


BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	PIMAGE_DOS_HEADER pImageDosHeader;
	PIMAGE_NT_HEADERS pImageNtHeaders;

	pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;

	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);

	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(
		(PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress
		);

	return TRUE;
}

BOOL InitSyscalls(VOID)
{
	PTEB pCurrentTeb;
	PPEB pCurrentPeb;

	PLDR_DATA_TABLE_ENTRY pLdrDataEntry;
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;


#if _WIN64
	pCurrentTeb = (PTEB)__readgsqword(0x30);
#else
	pCurrentTeb = (PTEB)__readfsdword(0x16);
#endif

	pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;

	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0x0a)
		return FALSE;

	pImageExportDirectory = NULL;
	pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return FALSE;


	if (InitSyscallInfo(&SyscallInfoTable.NtAllocateVirtualMemory, NtAllocateVirtualMemory_djb2) < 0)
		return FALSE;


	if (InitSyscallInfo(&SyscallInfoTable.NtProtectVirtualMemory, NtProtectVirtualMemory_djb2) < 0)
		return FALSE;


	if (InitSyscallInfo(&SyscallInfoTable.NtCreateThreadEx, NtCreateThreadEx_djb2) < 0)
		return FALSE;


	if (InitSyscallInfo(&SyscallInfoTable.NtWaitForSingleObject, NtWaitForSingleObject_djb2) < 0)
		return FALSE;


	return TRUE;
}