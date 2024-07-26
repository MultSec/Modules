//
// header: header.h
//

#include <windows.h>
#include <stdio.h>
#include <winternl.h>

#define INITIAL_HASH	3731  // added to randomize the hash
#define INITIAL_SEED	7
#define HASHA(API) (HashStringLoseLoseA((PCHAR) API))
#define HASHW(API) (HashStringLoseLoseW((PWCHAR) API))

DWORD HashStringLoseLoseA(_In_ PCHAR String);
DWORD HashStringLoseLoseW(_In_ PWCHAR String);

typedef LPVOID (WINAPI* fnMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);