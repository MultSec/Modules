#include <windows.h>
#include <stdio.h>
#include "isyscalls.h"

// from isyscalls.c
BOOL FetchNtSyscall(IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys);

extern VOID SetSSn(IN DWORD dwSSn, IN PVOID pSyscallInstAddress);
extern RunSyscall();

//  a macro to make calling 'SetSSn' easier
#define SET_SYSCALL(NtSys)(SetSSn((DWORD)NtSys.dwSSn,(PVOID)NtSys.pSyscallInstAddress))