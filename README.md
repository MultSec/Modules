# Contents
```bash
$ tree . -d -I "scripts|lib|include|src|src_t|out|bin" .
.
├── Enumeration
│   ├── Process
│   │   ├── CreateToolhelp32Snapshot
│   │   ├── EnumProcesses
│   │   ├── NtQueryInformationFile
│   │   ├── NtQuerySystemInformation
│   │   └── WTSEnumerate
│   └── Thread
│       ├── CreateToolhelp32Snapshot
│       │   ├── Local
│       │   └── Remote
│       └── NtQuerySystemInformation
│           ├── Local
│           └── Remote
├── Evasion
│   ├── Keying
│   │   ├── Privileges
│   │   │   ├── Admin
│   │   │   └── DomainJoined
│   │   ├── Sandbox
│   │   │   ├── Behaviour
│   │   │   │   ├── BigHeap
│   │   │   │   ├── BigTask
│   │   │   │   ├── DoubleTry
│   │   │   │   ├── FileName
│   │   │   │   │   ├── Change
│   │   │   │   │   └── DigestName
│   │   │   │   ├── FLSErr
│   │   │   │   ├── Mouse
│   │   │   │   │   ├── Clicks
│   │   │   │   │   └── Movement
│   │   │   │   ├── NUMAErr
│   │   │   │   ├── TimeForward
│   │   │   │   └── Uptime
│   │   │   ├── Debugging
│   │   │   │   ├── IsDebuggerPresent1
│   │   │   │   ├── IsDebuggerPresent2
│   │   │   │   └── IsDebuggerPresent3
│   │   │   ├── Hardware
│   │   │   │   ├── CPU
│   │   │   │   ├── RAM
│   │   │   │   ├── Screen
│   │   │   │   │   ├── Height
│   │   │   │   │   └── Width
│   │   │   │   ├── Storage
│   │   │   │   └── USBs
│   │   │   └── VM
│   │   │       ├── CheckFYL2XP1
│   │   │       ├── CheckVendors
│   │   │       ├── CPUCycles
│   │   │       ├── FilesPath
│   │   │       └── InvalidMSR
│   │   └── Time
│   │       ├── KillDate
│   │       └── TimeZone
│   └── Legitimacy
│       ├── FileBloating
│       │   ├── Appending
│       │   └── Metadata
│       ├── IAT Hiding
│       │   ├── API Hashing
│       │   └── Custom
│       │       ├── GetModuleHandle
│       │       ├── GetProcAddress
│       │       └── GetProcAddressEx
│       ├── Metadata
│       ├── PPID Spoofing
│       ├── Signature
│       │   └── Self
│       ├── Syscalls
│       │   ├── Direct
│       │   ├── HellsGate
│       │   ├── Indirect
│       │   └── SysWhisper
│       ├── UnHooking
│       │   ├── BlockDLLPolicy
│       │   ├── Disk
│       │   │   ├── Map
│       │   │   └── Read
│       │   ├── KnownDLLs
│       │   ├── SuspendedProcess
│       │   └── WebServer
│       └── WordStuffing
├── Execution
│   ├── Fibers
│   ├── Proc
│   │   ├── EarLy Bird APC
│   │   │   ├── Debug
│   │   │   └── Suspended
│   │   ├── FPInline
│   │   └── FPointer
│   └── Thread
│       ├── APC
│       │   ├── Alertable
│       │   │   ├── MsgWaitForMultipleObjectsEx
│       │   │   ├── SignalObjectAndWait
│       │   │   ├── SleepEx
│       │   │   ├── WaitForMultipleObjectsEx
│       │   │   └── WaitForSingleObjectEx
│       │   └── Suspended
│       ├── Callback
│       │   ├── CertEnumSystemStore
│       │   ├── CertEnumSystemStoreLocation
│       │   ├── CopyFile2
│       │   ├── CopyFileEx
│       │   ├── CreateThreadPoolWait
│       │   ├── CreateTimerQueueTimer
│       │   ├── CryptEnumOIDInfo
│       │   ├── EnumCalendarInfo
│       │   ├── EnumCalendarInfoEx
│       │   ├── EnumChildWindows
│       │   ├── EnumDesktopW
│       │   ├── EnumDesktopWindows
│       │   ├── EnumDirTreeW
│       │   ├── EnumDisplayMonitors
│       │   ├── EnumerateLoadedModules
│       │   ├── EnumFontFamiliesExW
│       │   ├── EnumFontFamiliesW
│       │   ├── EnumFontsW
│       │   ├── EnumLanguageGroupLocalesW
│       │   ├── EnumObjects
│       │   ├── EnumPageFilesW
│       │   ├── EnumPwrSchemes
│       │   ├── EnumResourceTypesExW
│       │   ├── EnumResourceTypesW
│       │   ├── EnumSystemLocalesEx
│       │   ├── EnumThreadWindows
│       │   ├── EnumTimeFormatsEx
│       │   ├── EnumUILanguagesW
│       │   ├── EnumWindows
│       │   ├── EnumWindowStationsW
│       │   ├── FiberContextEdit
│       │   ├── FlsAlloc
│       │   ├── ImageGetDigestStream
│       │   ├── ImmEnumInputContext
│       │   ├── SetTimer
│       │   ├── SetupCommitFileQueueW
│       │   ├── SymEnumProcesses
│       │   └── VerifierEnumerateResource
│       ├── CreateThread
│       │   ├── Local
│       │   └── Remote
│       └── ThreadHijack
│           ├── Local
│           └── Remote
│               ├── CreateSuspendedProcess
│               └── GetRemoteThreadhandle
├── Payload
│   ├── Allocation
│   │   ├── Chunking
│   │   ├── Mapping
│   │   │   ├── Local
│   │   │   └── Remote
│   │   ├── MemoryHunting
│   │   ├── Stomping
│   │   │   ├── Function
│   │   │   │   ├── Local
│   │   │   │   └── Remote
│   │   │   └── Module
│   │   └── VirtuallAlloc
│   │       ├── Local
│   │       └── Remote
│   ├── Encryption
│   │   ├── AES
│   │   ├── BFDecryption
│   │   ├── CTAES
│   │   ├── RC4
│   │   └── XOR
│   ├── Obfuscation
│   │   ├── IPv4Fuscation
│   │   ├── IPv6Fuscation
│   │   ├── JigSaw
│   │   ├── LFSR
│   │   ├── MACFuscation
│   │   ├── Un1k0d3r
│   │   ├── Un1k0d3r++
│   │   └── UUIDFuscation
│   └── Placement
│       ├── Staged
│       │   └── WebServer
│       └── Stageless
│           ├── data
│           ├── rdata
│           ├── rsrc
│           └── text
└── Utils
    ├── Digests
    │   ├── Djb2
    │   ├── JenkinsOneAtATime32Bit
    │   ├── LoseLose
    │   ├── Rotr32
    │   └── SHA256
    ├── Execution Control
    │   ├── Events
    │   ├── Mutex
    │   └── Semaphore
    ├── Hooking
    │   ├── Custom
    │   ├── Detours
    │   ├── HardwareBreakpoints
    │   ├── HardwareBreakpointsEx
    │   ├── Minhook
    │   └── WinAPIs
    ├── Network
    │   ├── Coms
    │   │   ├── IPv4BruteF
    │   │   └── POSTRequest
    │   └── Shell
    │       └── Simple_Reverse
    ├── ParsePE
    └── Time
        └── GetTime
            ├── GetSystemTimeAsFileTime
            └── SharedUserData
.
├── Enumeration
│   ├── Process
│   │   ├── CreateToolhelp32Snapshot
│   │   ├── EnumProcesses
│   │   ├── NtQueryInformationFile
│   │   ├── NtQuerySystemInformation
│   │   └── WTSEnumerate
│   └── Thread
│       ├── CreateToolhelp32Snapshot
│       │   ├── Local
│       │   └── Remote
│       └── NtQuerySystemInformation
│           ├── Local
│           └── Remote
├── Evasion
│   ├── Keying
│   │   ├── Privileges
│   │   │   ├── Admin
│   │   │   └── DomainJoined
│   │   ├── Sandbox
│   │   │   ├── Behaviour
│   │   │   │   ├── BigHeap
│   │   │   │   ├── BigTask
│   │   │   │   ├── DoubleTry
│   │   │   │   ├── FileName
│   │   │   │   │   ├── Change
│   │   │   │   │   └── DigestName
│   │   │   │   ├── FLSErr
│   │   │   │   ├── Mouse
│   │   │   │   │   ├── Clicks
│   │   │   │   │   └── Movement
│   │   │   │   ├── NUMAErr
│   │   │   │   ├── TimeForward
│   │   │   │   └── Uptime
│   │   │   ├── Debugging
│   │   │   │   ├── IsDebuggerPresent1
│   │   │   │   ├── IsDebuggerPresent2
│   │   │   │   └── IsDebuggerPresent3
│   │   │   ├── Hardware
│   │   │   │   ├── CPU
│   │   │   │   ├── RAM
│   │   │   │   ├── Screen
│   │   │   │   │   ├── Height
│   │   │   │   │   └── Width
│   │   │   │   ├── Storage
│   │   │   │   └── USBs
│   │   │   └── VM
│   │   │       ├── CheckFYL2XP1
│   │   │       ├── CheckVendors
│   │   │       ├── CPUCycles
│   │   │       ├── FilesPath
│   │   │       └── InvalidMSR
│   │   └── Time
│   │       ├── KillDate
│   │       └── TimeZone
│   └── Legitimacy
│       ├── FileBloating
│       │   ├── Appending
│       │   └── Metadata
│       ├── IAT Hiding
│       │   ├── API Hashing
│       │   └── Custom
│       │       ├── GetModuleHandle
│       │       ├── GetProcAddress
│       │       └── GetProcAddressEx
│       ├── Metadata
│       ├── PPID Spoofing
│       ├── Signature
│       │   └── Self
│       ├── Syscalls
│       │   ├── Direct
│       │   ├── HellsGate
│       │   ├── Indirect
│       │   └── SysWhisper
│       ├── UnHooking
│       │   ├── BlockDLLPolicy
│       │   ├── Disk
│       │   │   ├── Map
│       │   │   └── Read
│       │   ├── KnownDLLs
│       │   ├── SuspendedProcess
│       │   └── WebServer
│       └── WordStuffing
├── Execution
│   ├── Fibers
│   ├── Proc
│   │   ├── EarLy Bird APC
│   │   │   ├── Debug
│   │   │   └── Suspended
│   │   ├── FPInline
│   │   └── FPointer
│   └── Thread
│       ├── APC
│       │   ├── Alertable
│       │   │   ├── MsgWaitForMultipleObjectsEx
│       │   │   ├── SignalObjectAndWait
│       │   │   ├── SleepEx
│       │   │   ├── WaitForMultipleObjectsEx
│       │   │   └── WaitForSingleObjectEx
│       │   └── Suspended
│       ├── Callback
│       │   ├── CertEnumSystemStore
│       │   ├── CertEnumSystemStoreLocation
│       │   ├── CopyFile2
│       │   ├── CopyFileEx
│       │   ├── CreateThreadPoolWait
│       │   ├── CreateTimerQueueTimer
│       │   ├── CryptEnumOIDInfo
│       │   ├── EnumCalendarInfo
│       │   ├── EnumCalendarInfoEx
│       │   ├── EnumChildWindows
│       │   ├── EnumDesktopW
│       │   ├── EnumDesktopWindows
│       │   ├── EnumDirTreeW
│       │   ├── EnumDisplayMonitors
│       │   ├── EnumerateLoadedModules
│       │   ├── EnumFontFamiliesExW
│       │   ├── EnumFontFamiliesW
│       │   ├── EnumFontsW
│       │   ├── EnumLanguageGroupLocalesW
│       │   ├── EnumObjects
│       │   ├── EnumPageFilesW
│       │   ├── EnumPwrSchemes
│       │   ├── EnumResourceTypesExW
│       │   ├── EnumResourceTypesW
│       │   ├── EnumSystemLocalesEx
│       │   ├── EnumThreadWindows
│       │   ├── EnumTimeFormatsEx
│       │   ├── EnumUILanguagesW
│       │   ├── EnumWindows
│       │   ├── EnumWindowStationsW
│       │   ├── FiberContextEdit
│       │   ├── FlsAlloc
│       │   ├── ImageGetDigestStream
│       │   ├── ImmEnumInputContext
│       │   ├── SetTimer
│       │   ├── SetupCommitFileQueueW
│       │   ├── SymEnumProcesses
│       │   └── VerifierEnumerateResource
│       ├── CreateThread
│       │   ├── Local
│       │   └── Remote
│       └── ThreadHijack
│           ├── Local
│           └── Remote
│               ├── CreateSuspendedProcess
│               └── GetRemoteThreadhandle
├── Payload
│   ├── Allocation
│   │   ├── Chunking
│   │   ├── Mapping
│   │   │   ├── Local
│   │   │   └── Remote
│   │   ├── MemoryHunting
│   │   ├── Stomping
│   │   │   ├── Function
│   │   │   │   ├── Local
│   │   │   │   └── Remote
│   │   │   └── Module
│   │   └── VirtuallAlloc
│   │       ├── Local
│   │       └── Remote
│   ├── Encryption
│   │   ├── AES
│   │   ├── BFDecryption
│   │   ├── CTAES
│   │   ├── RC4
│   │   └── XOR
│   ├── Obfuscation
│   │   ├── IPv4Fuscation
│   │   ├── IPv6Fuscation
│   │   ├── JigSaw
│   │   ├── LFSR
│   │   ├── MACFuscation
│   │   ├── Un1k0d3r
│   │   ├── Un1k0d3r++
│   │   └── UUIDFuscation
│   └── Placement
│       ├── Staged
│       │   └── WebServer
│       └── Stageless
│           ├── data
│           ├── rdata
│           ├── rsrc
│           └── text
└── Utils
    ├── Digests
    │   ├── Djb2
    │   ├── JenkinsOneAtATime32Bit
    │   ├── LoseLose
    │   ├── Rotr32
    │   └── SHA256
    ├── Execution Control
    │   ├── Events
    │   ├── Mutex
    │   └── Semaphore
    ├── Hooking
    │   ├── Custom
    │   ├── Detours
    │   ├── HardwareBreakpoints
    │   ├── HardwareBreakpointsEx
    │   ├── Minhook
    │   └── WinAPIs
    ├── Network
    │   ├── Coms
    │   │   ├── IPv4BruteF
    │   │   └── POSTRequest
    │   └── Shell
    │       └── Simple_Reverse
    ├── ParsePE
    └── Time
        └── GetTime
            ├── GetSystemTimeAsFileTime
            └── SharedUserData

430 directories
$
```
