#include <windows.h>
#include <stdio.h>

int main() {
    HRSRC       hRsrc = NULL;
    HGLOBAL     hGlobal = NULL;
    PVOID       pPayloadAddress = NULL;
    SIZE_T      sPayloadSize = 0;

    // Get the location to the data stored in .rsrc by its id *PAYLOAD* (more info here: https://stackoverflow.com/questions/2963634/understanding-makeintresourcew-definition)
    hRsrc = FindResourceW(NULL, ((LPWSTR)((ULONG_PTR)((WORD)(101)))), ((LPWSTR)((ULONG_PTR)((WORD)(10)))));
    if (hRsrc == NULL) {
        // in case of function failure 
        printf("[!] FindResourceW Failed With Error : %d \n", GetLastError());
        return -1;
    }

    // Get HGLOBAL, or the handle of the specified resource data since it's required to call LockResource later
    hGlobal = LoadResource(NULL, hRsrc);
    if (hGlobal == NULL) {
        // in case of function failure 
        printf("[!] LoadResource Failed With Error : %d \n", GetLastError());
        return -1;
    }

    // Get the address of our payload in .rsrc section
    pPayloadAddress = LockResource(hGlobal);
    if (pPayloadAddress == NULL) {
        // in case of function failure 
        printf("[!] LockResource Failed With Error : %d \n", GetLastError());
        return -1;
    }

    // Get the size of our payload in .rsrc section
    sPayloadSize = SizeofResource(NULL, hRsrc);
    if (sPayloadSize == 0) {
        // in case of function failure 
        printf("[!] SizeofResource Failed With Error : %d \n", GetLastError());
        return -1;
    }

    // Printing pointer and size to the screen
    printf("[i] pPayloadAddress var : 0x%p \n", pPayloadAddress);
    printf("[i] sPayloadSize var : %ld \n", sPayloadSize);

    // Printing the base address of our buffer (pTmpBuffer)
    printf("[#] Press <Enter> To Quit ...");
    getchar();
    return 0;
}
