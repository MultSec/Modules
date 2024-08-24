#include <windows.h>
#include <stdio.h>
#include <winternl.h>

#define INITIAL_HASH	{{INITIAL_HASH}}  // added to randomize the hash
#define INITIAL_SEED	{{INITIAL_SEED}}
#define HASHA(API) ({{HASH_TYPE}}A((PCHAR) API))
#define HASHW(API) ({{HASH_TYPE}}W((PWCHAR) API))

DWORD {{HASH_TYPE}}A(_In_ PCHAR String);
DWORD {{HASH_TYPE}}W(_In_ PWCHAR String);