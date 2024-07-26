#include <windows.h>
#include <stdio.h>
#include <stdint.h>

typedef struct {
	uint32_t EAX;
	uint32_t EBX;
	uint32_t ECX;
	uint32_t EDX;
} _cpuid_buffer_t;

int checkKnownHypervisors() {
    _cpuid_buffer_t cpuInfo = { 0 };
    __cpuid(&cpuInfo, 1);

    if (!(cpuInfo.ECX & (1 << 31))) // check bit 31 of register ECX, which is “hypervisor present bit”
		return 0;                   // if not present return

    // we know hypervisor is present we can query the vendor id.
	__cpuid(&cpuInfo, 0x40000000);

    // construct string for our vendor name
    char presentVendor[13];
	memcpy(presentVendor + 0, &cpuInfo.EBX, 4);
	memcpy(presentVendor + 4, &cpuInfo.ECX, 4);
	memcpy(presentVendor + 8, &cpuInfo.EDX, 4);
	presentVendor[12] = '\0';

	// check against known vendor names
	const char* vendors[] = {
		"KVMKVMKVM\0\0\0", // KVM 
		"Microsoft Hv",    // Microsoft Hyper-V or Windows Virtual PC */
		"VMwareVMware",    // VMware 
		"XenVMMXenVMM",    // Xen 
		"prl hyperv  ",    // Parallels
		"VBoxVBoxVBox"     // VirtualBox 
	};

    for (int i = 0; i < sizeof(vendors); ++i) {
        if (!memcmp(vendors[i], presentVendor, 13)) {
            printf("\tFound known hypervisor: %s\n", presentVendor);
            return 1;
        }
    }

    return 0;
}

int main() {
	if (checkKnownHypervisors()) {
		printf("[!] Possible sandbox, found VM cpu hypervisor info\n");
	} else {
		printf("[i] No VM files found\n");
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}