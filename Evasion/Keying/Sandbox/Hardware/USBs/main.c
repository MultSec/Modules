#include <windows.h>
#include <stdio.h>

#define MIN_USB 2 // 2 USBs previously mounted

int checkDiskSize() {
    HKEY    hKey            = NULL;
    DWORD   dwUsbNumber     = NULL;
    DWORD   dwRegErr        = NULL;


    if ((dwRegErr = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Enum\\USBSTOR", NULL, KEY_READ, &hKey)) != ERROR_SUCCESS) {
        printf("\n\t[!] RegOpenKeyExA Failed With Error : %d | 0x%0.8X \n", dwRegErr, dwRegErr);
    }

    if ((dwRegErr = RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &dwUsbNumber, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) != ERROR_SUCCESS) {
        printf("\n\t[!] RegQueryInfoKeyA Failed With Error : %d | 0x%0.8X \n", dwRegErr, dwRegErr);
    }

    return (dwUsbNumber <= MIN_USB);
}

int main() {
	if (checkDiskSize()) {
		printf("[!] Possible sandbox, history of mounted USBs less or equal than %d\n", MIN_USB);
	} else {
		printf("[i] History of mounted USBs more than %d\n", MIN_USB);
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}