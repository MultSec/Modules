PCHAR BruteForce(DWORD dwHashedIpv4, BYTE bMinStart) {
	CHAR IPv4Addr[16]; // Maximum length of an IPv4 address is 15 characters plus 1 for null terminator

	// For each octet
	for (int i = bMinStart; i < 256; ++i) { 
        for (int j = bMinStart; j < 256; ++j) { 
            for (int k = bMinStart; k < 256; ++k) { 
				for (int l = bMinStart; l < 256; ++l) { 
					// Get IPv4 Addr
					sprintf(IPv4Addr, "%d.%d.%d.%d", i, j, k, l);
					printf("\r[i] Trying: %s    ", IPv4Addr);
    				fflush(stdout);

					// Hash the resulting IPv4 Addr and compare with the hardcoded
					if (dwHashedIpv4 == HASHA(IPv4Addr))
						return strdup(IPv4Addr);
				}
			}
		}
	}

	return NULL;
}

int main() {
	DWORD 	dwHashedIpv4 	= [["72.71.160.87"]];
	PCHAR 	pIPv4Addr		= NULL;
	BYTE 	bMinStart		= 71;

	printf("[i] Hashed IPv4 Address: %lu\n", dwHashedIpv4);

	printf("[#] Press <Enter> To Crack it ... ");
	getchar();

	pIPv4Addr = BruteForce(dwHashedIpv4, bMinStart);
	if(pIPv4Addr == NULL) {
		printf("[!] Couldn't Get IPv4 Address\n");
		return -1;
	}

	printf("[+] Cracked IPv4 Address: %s\n", pIPv4Addr);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	free(pIPv4Addr);

	return 0;
}