#include <windows.h>
#include <stdio.h>

#include "MinHook.h"

// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa
typedef int (WINAPI* fnMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

// used as a unhooked MessageBoxA in `MyMessageBoxA`
// and used by `MH_CreateHook`
fnMessageBoxA g_pMessageBoxA = NULL;


// the function that will run instead MessageBoxA when hooked
INT WINAPI MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {

	printf("[+] Original Parameters : \n");
	printf("\t - lpText	: %s\n", lpText);
	printf("\t - lpCaption	: %s\n", lpCaption);

	return g_pMessageBoxA(hWnd, "Maldev Academy Is The Best", "Hooked MsgBox", uType);
}


//	MINHOOK HOOKING ROUTINE:
BOOL InstallHook() {
	
	DWORD		dwMinHookErr = NULL;

	if ((dwMinHookErr = MH_Initialize()) != MH_OK) {
		printf("[!] MH_Initialize Failed With Error : %d \n", dwMinHookErr);
		return FALSE;
	}

	if ((dwMinHookErr = MH_CreateHook(&MessageBoxA, &MyMessageBoxA, &g_pMessageBoxA)) != MH_OK) {
		printf("[!] MH_CreateHook Failed With Error : %d \n", dwMinHookErr);
		return FALSE;
	}

	if ((dwMinHookErr = MH_EnableHook(&MessageBoxA)) != MH_OK) {
		printf("[!] MH_EnableHook Failed With Error : %d \n", dwMinHookErr);
		return -1;
	}

	return TRUE;
}

//	MINHOOK UNHOOKING ROUTINE:
BOOL Unhook() {
	
	DWORD		dwMinHookErr = NULL;

	if ((dwMinHookErr = MH_DisableHook(&MessageBoxA)) != MH_OK) {
		printf("[!] MH_DisableHook Failed With Error : %d \n", dwMinHookErr);
		return -1;
	}

	if ((dwMinHookErr = MH_Uninitialize()) != MH_OK) {
		printf("[!] MH_Uninitialize Failed With Error : %d \n", dwMinHookErr);
		return -1;
	}
}



int main() {
	// will run
	MessageBoxA(NULL, "What Do You Think About MaldevAcademy ?", "Original MsgBox", MB_OK | MB_ICONQUESTION);

    //  hooking
	printf("[i] Installing The Hook ... ");
	if (!InstallHook()) {
		return -1;
	}
	printf("[+] DONE \n");

	
    //  wont run - hooked
	MessageBoxA(NULL, "MaldevAcademy Is Trash", "Original MsgBox", MB_OK | MB_ICONWARNING);


    //  unhooking
	printf("\n[i] Removing The Hook ... ");
	if (!Unhook()) {
		return -1;
	}
	printf("[+] DONE \n");


    //  will run - hook disabled
	MessageBoxA(NULL, "Normal MsgBox Again", "Original MsgBox", MB_OK | MB_ICONINFORMATION);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}




