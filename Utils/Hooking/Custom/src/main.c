#include <windows.h>
#include <stdio.h>

// if compiling as 64-bit
#ifdef _M_X64
#define TRAMPOLINE_SIZE			13
#endif // _M_X64

// if compiling as 32-bit
#ifdef _M_IX86
#define TRAMPOLINE_SIZE			7
#endif // _M_IX86

typedef unsigned long long uint64_t;
typedef unsigned int       uint32_t;
typedef unsigned char      uint8_t;

typedef struct _HookSt {
	PVOID	pFunctionToHook;						// address of the function to hook
	PVOID	pFunctionToRun;							// address of the function to run instead
	BYTE	pOriginalBytes[TRAMPOLINE_SIZE];		// buffer to keep some original bytes (needed for cleanup)
	DWORD	dwOldProtection;						// holds the old memory protection of the "function to hook" address (needed for cleanup)
}HookSt, *PHookSt;


BOOL InitializeHookStruct(IN PVOID pFunctionToHook, IN PVOID pFunctionToRun, OUT PHookSt Hook) {
	// checking if null
	if (pFunctionToHook == NULL || pFunctionToRun == NULL || Hook == NULL)
		return FALSE;
	
	// filling up the struct
	Hook->pFunctionToHook	= pFunctionToHook;
	Hook->pFunctionToRun	= pFunctionToRun;

	// save original bytes of the same size that we will overwrite (that is TRAMPOLINE_SIZE)
	// this is done to be able to do cleanups when done
	memcpy(Hook->pOriginalBytes, pFunctionToHook, TRAMPOLINE_SIZE);

	// changing the protection to RWX so that we can modify the bytes 
	// we are saving the old protection to the struct (to re-place it at cleanup)
	if (!VirtualProtect(pFunctionToHook, TRAMPOLINE_SIZE, PAGE_EXECUTE_READWRITE, &Hook->dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL InstallHook (IN PHookSt Hook) {
	// checking if null
	if (Hook == NULL || Hook->dwOldProtection == NULL || Hook->pFunctionToHook == NULL || Hook->pFunctionToRun == NULL || Hook->pOriginalBytes == NULL)
		return FALSE;

#ifdef _M_X64

	// 64-bit trampoline
	uint8_t		uTrampoline [] = {
			0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, pFunctionToRun
			0x41, 0xFF, 0xE2                                            // jmp r10
	};

	// patching the shellcode with the address to jump to (pFunctionToRun)
	uint64_t uPatch = (uint64_t)(Hook->pFunctionToRun);
	// copying the address of the function to jump to, to the offset '2' in uTrampoline
	memcpy(&uTrampoline[2], &uPatch, sizeof(uPatch));

#endif // _M_X64


#ifdef _M_IX86

	// 32-bit trampoline
	uint8_t		uTrampoline[] = {
	   0xB8, 0x00, 0x00, 0x00, 0x00,     // mov eax, pFunctionToRun
	   0xFF, 0xE0                        // jmp eax
	};
	
	// patching the shellcode with the address to jump to (pFunctionToRun)
	uint32_t uPatch = (uint32_t)(Hook->pFunctionToRun);
	// copying the address of the function to jump to, to the offset '1' in uTrampoline
	memcpy(&uTrampoline[1], &uPatch, sizeof(uPatch));
#endif // _M_IX86

	
	// placing the trampoline function - installing the hook
	memcpy(Hook->pFunctionToHook, uTrampoline, sizeof(uTrampoline));

	return TRUE;
}

BOOL RemoveHook (IN PHookSt Hook) {
	// checking if null
	if (Hook == NULL || Hook->dwOldProtection == NULL || Hook->pFunctionToHook == NULL || Hook->pOriginalBytes == NULL)
		return FALSE;

	DWORD	dwOldProtection		= NULL;

	// copying the original bytes over
	memcpy(Hook->pFunctionToHook, Hook->pOriginalBytes, TRAMPOLINE_SIZE);
	// cleaning up our buffer
	memset(Hook->pOriginalBytes, '\0', TRAMPOLINE_SIZE);
	// setting the old memory protection back to what it was before hooking 
	if (!VirtualProtect(Hook->pFunctionToHook, TRAMPOLINE_SIZE, Hook->dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// setting all to null
	Hook->pFunctionToHook	= NULL;
	Hook->pFunctionToRun	= NULL;
	Hook->dwOldProtection	= NULL;

	return TRUE;
}

// the function that will run instead MessageBoxA when hooked
INT WINAPI MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	printf("[+] Original Parameters : \n");
	printf("\t - lpText	: %s\n", lpText);
	printf("\t - lpCaption	: %s\n", lpCaption);

	return MessageBoxW(hWnd, L"Malware Development Is Cool", L"Hooked MsgBox", uType);
}

int main() {
	// Initializing the structure (needed before installing/removing the hook)
	HookSt st = { 0 };

	if (!InitializeHookStruct(&MessageBoxA, &MyMessageBoxA, &st)) {
		return -1;
	}

	// will run
	MessageBoxA(NULL, "What Do You Think About Malware Development ?", "Original MsgBox", MB_OK | MB_ICONQUESTION);

	//  hooking
	printf("[i] Installing The Hook ... ");
	if (!InstallHook(&st)) {
		return -1;
	}
	printf("[+] DONE \n");
	
	//  wont run - hooked
	MessageBoxA(NULL, "Malware Development Is Bad", "Original MsgBox", MB_OK | MB_ICONWARNING);

	//  unhooking
	printf("[i] Removing The Hook ... ");
	if (!RemoveHook(&st)) {
		return -1;
	}
	printf("[+] DONE \n");

	//  will run - hook disabled
	MessageBoxA(NULL, "Normal MsgBox Again", "Original MsgBox", MB_OK | MB_ICONINFORMATION);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}