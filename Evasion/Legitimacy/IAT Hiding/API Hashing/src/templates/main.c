int main() {
	
	// Load User32.dll to the current process so that GetModuleHandleH will work
	if (LoadLibraryA("USER32.DLL") == NULL) {
		printf("[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
		return 0;
	}

	// Getting the handle of user32.dll using GetModuleHandleH 
	HMODULE hUser32Module = GetModuleHandleH( [["USER32.DLL"]] );
	if (hUser32Module == NULL){
		printf("[!] Couldn't Get Handle To User32.dll \n");
		return -1;
	}

	// Getting the address of MessageBoxA function using GetProcAddressH
	fnMessageBoxA pMessageBoxA = (fnMessageBoxA)GetProcAddressH(hUser32Module, [["MessageBoxA"]]);
	if (pMessageBoxA == NULL) {
		printf("[!] Couldn't Find Address Of Specified Function \n");
		return -1;
	}

	// Calling MessageBoxA
	pMessageBoxA(NULL, "Building Malware With Maldev", "Wow", MB_OK | MB_ICONEXCLAMATION);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}