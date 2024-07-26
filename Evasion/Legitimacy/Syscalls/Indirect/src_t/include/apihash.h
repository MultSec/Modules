#include <windows.h>

#define INITIAL_HASH	{{INITIAL_HASH}}  // added to randomize the hash
#define INITIAL_SEED	{{INITIAL_SEED}}
#define HASHA(API) (HashString{{HASH_FUNC}}A((PCHAR) API))
#define HASHW(API) (HashString{{HASH_FUNC}}W((PWCHAR) API))

DWORD HashString{{HASH_FUNC}}A(_In_ PCHAR String);
DWORD HashString{{HASH_FUNC}}W(_In_ PWCHAR String);