#include <windows.h>
#include <stdio.h>
#include "dsyscalls.h"

// from dsyscalls.c
BOOL FetchNtSyscall(IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys);

extern VOID SetSSn(DWORD wSystemCall);
extern RunSyscall();