#include <windows.h>
#include <stdio.h>

#define TIME_DELAY 13000 //13 seconds
#define MIN_CLICKS_NUM 5

// Global hook handle variable
HHOOK g_hMouseHook      = NULL;
// Global mouse clicks counter
DWORD g_dwMouseClicks   = NULL;

// The callback function that will be executed whenever the user clicked a mouse button
LRESULT CALLBACK HookEvent(int nCode, WPARAM wParam, LPARAM lParam){

    // WM_RBUTTONDOWN :         "Right Mouse Click"
    // WM_LBUTTONDOWN :         "Left Mouse Click"
    // WM_MBUTTONDOWN :         "Middle Mouse Click"

    if (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN || wParam == WM_MBUTTONDOWN) {
        printf("[+] Mouse Click Recorded\n");
        g_dwMouseClicks++;
    }

    return CallNextHookEx(g_hMouseHook, nCode, wParam, lParam);
}

BOOL MouseClicksLogger(){
    
    MSG         Msg         = { 0 };

    // Installing hook 
    g_hMouseHook = SetWindowsHookExW(
        WH_MOUSE_LL,
        (HOOKPROC)HookEvent,
        NULL,
        NULL
    );
    if (!g_hMouseHook) {
        printf("[!] SetWindowsHookExW Failed With Error : %d\n", GetLastError());
    }

    // Process unhandled events
    while (GetMessageW(&Msg, NULL, NULL, NULL)) {
        DefWindowProcW(Msg.hwnd, Msg.message, Msg.wParam, Msg.lParam);
    }
    
    return TRUE;
}

//Check for Mouse Movement
int checkMouseClicks() {
	HANDLE  hThread         = NULL;
    DWORD   dwThreadId      = NULL;

    // running the hooking function in a seperate thread for 'TIME_DELAY' ms
    hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)MouseClicksLogger, NULL, NULL, &dwThreadId);
    if (hThread) {
        printf("[i] Created thread to monitor mouse clicks\n");
        // If this sleep is fast forwarded then the mouse clicks
        // remains the same and therefore detects a sandbox env
        Sleep(TIME_DELAY);
    }

    // unhooking
    if (g_hMouseHook && !UnhookWindowsHookEx(g_hMouseHook)) {
        printf("[!] UnhookWindowsHookEx Failed With Error : %d\n", GetLastError());
    }

    // the test
    printf("[i] Monitored User's Mouse Clicks : %d ...\n", g_dwMouseClicks);

	return (g_dwMouseClicks < MIN_CLICKS_NUM);
}

int main() {
	if (checkMouseClicks()) {
		printf("[!] Possible sandbox, mouse didn't click in the span of %d ms\n", TIME_DELAY);
	} else {
		printf("[i] Mouse clicked in the span of %d ms\n", TIME_DELAY);
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}

