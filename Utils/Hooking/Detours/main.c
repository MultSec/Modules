#include <windows.h>
#include <stdio.h>

#include "detours.h" // from the detours library

// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa
typedef int (WINAPI* fnMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

// used as a unhooked MessageBoxA in `MyMessageBoxA`
// and used by `DetourAttach` & `DetourDetach`
fnMessageBoxA g_pMessageBoxA = MessageBoxA;


// the function that will run instead MessageBoxA when hooked
INT WINAPI MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {

	printf("[+] Original Parameters : \n");
	printf("\t - lpText	: %s\n", lpText);
	printf("\t - lpCaption	: %s\n", lpCaption);

	return g_pMessageBoxA(hWnd, "Malware Development Is Cool", "Hooked MsgBox", uType);
}



//	DETOURS UNHOOKING ROUTINE:

BOOL Unhook() {

	DWORD	dwDetoursErr = NULL;

	if ((dwDetoursErr = DetourTransactionBegin()) != NO_ERROR) {
		printf("[!] DetourTransactionBegin Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}
	if ((dwDetoursErr = DetourUpdateThread(GetCurrentThread())) != NO_ERROR) {
		printf("[!] DetourUpdateThread Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}
	if ((dwDetoursErr = DetourDetach((PVOID)&g_pMessageBoxA, MyMessageBoxA)) != NO_ERROR) {
		printf("[!] DetourDetach Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}

	// actual hook removal happen after `DetourTransactionCommit`
	if ((dwDetoursErr = DetourTransactionCommit()) != NO_ERROR) {
		printf("[!] DetourTransactionCommit Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}

	return TRUE;
}


//	DETOURS HOOKING ROUTINE:

BOOL InstallHook() {
	
	DWORD	dwDetoursErr = NULL;

	if ((dwDetoursErr = DetourTransactionBegin()) != NO_ERROR) {
		printf("[!] DetourTransactionBegin Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}
	if ((dwDetoursErr = DetourUpdateThread(GetCurrentThread())) != NO_ERROR) {
		printf("[!] DetourUpdateThread Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}
	if ((dwDetoursErr = DetourAttach((PVOID)&g_pMessageBoxA, MyMessageBoxA)) != NO_ERROR) {
		printf("[!] DetourAttach Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}

	// actual hook installing happen after `DetourTransactionCommit`
	if ((dwDetoursErr = DetourTransactionCommit()) != NO_ERROR) {
		printf("[!] DetourTransactionCommit Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}

	return TRUE;
}



int main() {


	// will run
	MessageBoxA(NULL, "What Do You Think About Malware Development ?", "Original MsgBox", MB_OK | MB_ICONQUESTION);

//------------------------------------------------------------------
//  hooking
	
	printf("[i] Installing The Hook ... ");
	if (!InstallHook()) {
		return -1;
	}
	printf("[+] DONE \n");
	

//------------------------------------------------------------------	
//  wont run - hooked
	
	MessageBoxA(NULL, "Malware Development Is Bad", "Original MsgBox", MB_OK | MB_ICONWARNING);

//------------------------------------------------------------------
//  unhooking
	
	printf("[i] Removing The Hook ... ");
	if (!Unhook()) {
		return -1;
	}
	printf("[+] DONE \n");

//------------------------------------------------------------------
//  will run - hook disabled
	
	MessageBoxA(NULL, "Normal MsgBox Again", "Original MsgBox", MB_OK | MB_ICONINFORMATION);


	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}


