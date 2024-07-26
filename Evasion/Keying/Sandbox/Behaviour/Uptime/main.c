#include <windows.h>
#include <stdio.h>

#define MIN_UPTIME 300000 // 5 min; 5*60=300s; 5*60*1000=300000 ms

//Check for Computer Uptime Greater than 5 min
int checkUptime() {
    // System uptime
    // We are using GetTickCount64
    // Retrieves the number of milliseconds that have elapsed since the system was started.
    // https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64
    return (GetTickCount() < (MIN_UPTIME));
}

int main() {
	if (checkUptime()) {
		printf("[!] Possible sandbox, uptime didn't less than %d ms\n", MIN_UPTIME);
	} else {
		printf("[i] Uptime more than %d ms\n", MIN_UPTIME);
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}