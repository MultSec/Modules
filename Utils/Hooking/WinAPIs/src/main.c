#include <windows.h>
#include <stdio.h>

#define MONITOR_TIME   20000 // monitor mouse clicks for 20 seconds

/*
    - SetWindowsHookExW: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexw
    - CallNextHookEx: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-callnexthookex
    - UnhookWindowsHookEx: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-unhookwindowshookex
    
    - GetMessageW: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getmessagew
    - DefWindowProcW: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-defwindowprocw 
*/

// global hook handle variable
HHOOK g_hMouseHook      = NULL;

// the callback function that will be executed whenever the user clicked a mouse button
LRESULT HookCallback(int nCode, WPARAM wParam, LPARAM lParam){

    if (wParam == WM_LBUTTONDOWN){
        printf("[ # ] Left Mouse Click \n");
    }
    
    if (wParam == WM_RBUTTONDOWN) {
        printf("[ # ] Right Mouse Click \n");
    }
    
    if (wParam == WM_MBUTTONDOWN) {
        printf("[ # ] Middle Mouse Click \n");
    }
    
    // moving to the next hook in the hook chain
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

BOOL MouseClicksLogger(){
    MSG         Msg         = { 0 };

    // installing hook 
    g_hMouseHook = SetWindowsHookExW(
        WH_MOUSE_LL,
        (HOOKPROC)HookCallback,
        NULL,  
        NULL
    );
    if (!g_hMouseHook) {
        printf("[!] SetWindowsHookExW Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // process unhandled events
    while (GetMessageW(&Msg, NULL, NULL, NULL)) {
        DefWindowProcW(Msg.hwnd, Msg.message, Msg.wParam, Msg.lParam);
    }

    /* 
    This is another way to process unhandled events  

    while (GetMessageW(&Msg, NULL, NULL, NULL)) {
        TranslateMessage(&Msg);
        DispatchMessageW(&Msg);
    }
    */
    
    return TRUE;
}

int main() {
    HANDLE  hThread         = NULL;
    DWORD   dwThreadId      = NULL;

    hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)MouseClicksLogger, NULL, NULL, &dwThreadId);
    if (hThread) {
        printf("\t\t<<>> Thread %d Is Created To Monitor Mouse Clicks For %d Seconds <<>>\n\n", dwThreadId, (MONITOR_TIME / 1000));
        WaitForSingleObject(hThread, MONITOR_TIME);
    }


    if (g_hMouseHook && !UnhookWindowsHookEx(g_hMouseHook)) {
        printf("[!] UnhookWindowsHookEx Failed With Error : %d \n", GetLastError());
    }

    return 0;
}