#include <windows.h>
#include <stdio.h>

#define MIN_STORAGE 100 // 100GB

int checkDiskSize() {
    // Disk size
    // We are using GetDiskFreeSpaceExA
    // Retrieves information about the amount of space that is available on a disk volume,
    // which is the total amount of space, the total amount of free space, and the total
    // amount of free space available to the user that is associated with the calling thread.
    // https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdiskfreespaceexa

    ULARGE_INTEGER iFreeBytesAvailableToCaller, iTotalNumberOfBytes, iTotalNumberOfFreeBytes;

	// Retrieve information for disk C:
    GetDiskFreeSpaceExA("C:\\", &iFreeBytesAvailableToCaller, &iTotalNumberOfBytes, &iTotalNumberOfFreeBytes);

    return ((iTotalNumberOfBytes.QuadPart / 1073741824) <= MIN_STORAGE);
}

int main() {
	if (checkDiskSize()) {
		printf("[!] Possible sandbox, amount of available storage less or equal than %d GB\n", MIN_STORAGE);
	} else {
		printf("[i] Amount of available storage more than %d GB\n", MIN_STORAGE);
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}