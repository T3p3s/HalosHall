#pragma once

#include "haloshall.h"
#include <Windows.h>

// Local defs
typedef struct _SYSCALL_INFO {
	DWORD dwSsn;
	PVOID pAddress;
	PVOID pSyscallRet;
} SYSCALL_INFO, * PSYSCALL_INFO;

DWORD64 djb2(PBYTE str);
#define HASH(API)	(djb2((PBYTE)API))

// from halohall.c
//DWORD InitSyscallInfo(PSYSCALL_INFO pSyscallInfo, PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, DWORD64 dwHash);
DWORD InitSyscallInfo(_Out_ PSYSCALL_INFO pSyscallInfo, _In_ DWORD64 dwHash);

// from halosasm.asm
extern VOID SetSSn(DWORD wSsn, PVOID pSyscallRet);
extern SyscallExec();

#define SET_SYSCALL(NtSys)(SetSSn((DWORD)NtSys.dwSsn,(PVOID)NtSys.pSyscallRet))

typedef struct {

	SYSCALL_INFO NtAllocateVirtualMemory;
	SYSCALL_INFO NtCreateThreadEx;
	SYSCALL_INFO NtProtectVirtualMemory;
	SYSCALL_INFO NtWaitForSingleObject;
	SYSCALL_INFO NtWriteVirtualMemory;

} NT_SYSCALL, * PNT_SYSCALL;

#define NtAllocateVirtualMemory_djb2	0xf5bd373480a6b89b
#define NtCreateThreadEx_djb2			0x64dc7db288c5015f
#define NtProtectVirtualMemory_djb2		0x858bcb1046fb6a37
#define NtWaitForSingleObject_djb2		0xc6a2fa174e551bcb
#define NtWriteVirtualMemory_djb2		0x68a3c2ba486f0741


BOOL InitSyscalls(VOID);