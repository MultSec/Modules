# Concept

Usage of Detours to Hook Functions

>:warning: This project is broken, the error is the following:
> ```bash
>$ make
>[*] Compile x64 executable...
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/detours.obj):(.text$mn+0x19): undefined reference to `?detour_find_jmp_bounds@@YAXPEAEPEAPEAU_DETOUR_TRAMPOLINE@@1@Z'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/detours.obj):(.text$mn+0x1e): undefined reference to `?detour_find_jmp_bounds@@YAXPEAEPEAPEAU_DETOUR_TRAMPOLINE@@1@Z'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/detours.obj):(.text$mn+0x238): undefined reference to `??3@YAXPEAX_K@Z'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/detours.obj):(.text$mn+0x42c): undefined reference to `?detour_does_code_end_function@@YAHPEAE@Z'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/detours.obj):(.text$mn+0x44b): undefined reference to `?detour_is_code_filler@@YAKPEAE@Z'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/detours.obj):(.text$mn+0x580): undefined reference to `?detour_gen_jmp_indirect@@YAPEAEPEAEPEAPEAE@Z'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/detours.obj):(.text$mn+0x597): undefined reference to `?detour_gen_brk@@YAPEAEPEAE0@Z'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/detours.obj):(.text$mn+0x19): undefined reference to `?detour_skip_jmp@@YAPEAEPEAEPEAPEAX@Z'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/detours.obj):(.text$mn+0xe7): undefined reference to `??3@YAXPEAX_K@Z'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/detours.obj):(.text$mn+0xb2): undefined reference to `??3@YAXPEAX_K@Z'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/detours.obj):(.text$mn+0x119): undefined reference to `??3@YAXPEAX_K@Z'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/detours.obj):(.text$mn+0xf): undefined reference to `__security_cookie'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/detours.obj):(.text$mn+0x108): undefined reference to `?detour_gen_jmp_indirect@@YAPEAEPEAEPEAPEAE@Z'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/detours.obj):(.text$mn+0x126): undefined reference to `?detour_gen_jmp_immediate@@YAPEAEPEAE0@Z'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/detours.obj):(.text$mn+0x142): undefined reference to `?detour_gen_brk@@YAPEAEPEAE0@Z'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/detours.obj):(.text$mn+0x3bb): undefined reference to `??3@YAXPEAX_K@Z'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/detours.obj):(.text$mn+0x437): undefined reference to `??3@YAXPEAX_K@Z'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/detours.obj):(.text$mn+0x48b): undefined reference to `__security_check_cookie'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/detours.obj):(.text$mn+0x76): undefined reference to `??3@YAXPEAX_K@Z'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/detours.obj):(.xdata[$unwind$DetourTransactionCommitEx]+0x8): undefined reference to `__GSHandlerCheck'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/disasm.obj):(.text$mn+0x1e): undefined reference to `__security_cookie'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/disasm.obj):(.text$mn+0x6d): undefined reference to `__security_check_cookie'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/disasm.obj):(.xdata[$unwind$DetourCopyInstruction]+0x8): undefined reference to `__GSHandlerCheck'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/modules.obj):(.text$mn+0x14): undefined reference to `__security_cookie'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/modules.obj):(.text$mn+0x149): undefined reference to `?StringCchCopyA@@YAJPEAD_KPEBD@Z'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/modules.obj):(.text$mn+0x174): undefined reference to `?StringCchCatA@@YAJPEAD_KPEBD@Z'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/modules.obj):(.text$mn+0x19d): undefined reference to `?StringCchCatA@@YAJPEAD_KPEBD@Z'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/modules.obj):(.text$mn+0x20e): undefined reference to `__security_check_cookie'
>/usr/lib/gcc/x86_64-w64-mingw32/13.1.0/../../../../x86_64-w64-mingw32/bin/ld: lib/detoursx64.lib(obj.X64/modules.obj):(.xdata[$unwind$DetourFindFunction]+0x8): undefined reference to `__GSHandlerCheck'
>collect2: error: ld returned 1 exit status
>make: *** [makefile:20: x64] Error 1
>```

# Compiling

```bash
$ make
```