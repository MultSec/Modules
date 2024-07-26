#include <windows.h>
#include <stdio.h>

#define TIMEZONE_UL "Eastern Standard Time" // Define your predefined time zone here

// Check the TimeZone
int checkTime() {
    // Get Timezone
    TIME_ZONE_INFORMATION timeZone;
    DWORD ret = GetTimeZoneInformation(&timeZone);

    // Check if the current time zone is different from the predefined one
    return (strcmp(timeZone.StandardName, TIMEZONE_UL) != 0);
}

int main() {
    if (checkTime()) {
        printf("[!] Out of scope, timezone is different\n");
    } else {
        printf("[i] In scope\n");
    }

    printf("[#] Press <Enter> To Quit ...");
    getchar();

    return 0;
}
