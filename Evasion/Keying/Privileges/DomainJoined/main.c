#include <windows.h>
#include <stdio.h>
#include <lm.h>

//Check if domain joined
int isPartofDomain() {
    NET_API_STATUS nas;
    NETSETUP_JOIN_STATUS status;
    LPWSTR buf = NULL;
    nas = NetGetJoinInformation(NULL, &buf, &status);

    return ((nas == NERR_Success) && (status == NetSetupDomain));
}

int main() {
	if (!isPartofDomain()) {
		printf("[!] Comupter not part of domain\n");
	} else {
		printf("[i] Comupter part of domain\n");
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}

