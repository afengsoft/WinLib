#include "WinLibPs.h"
//C++ Standard Library
#include <functional>
#include <algorithm>
//Other
#include "WinLibStr.h"
#include "WinLibOs.h"
#include "wow64/wow64ext.h"

#pragma comment(lib, "Psapi.lib")

namespace WinLib
{
#ifdef __cplusplus
	extern "C" {
#endif

		// NTSTATUS
		typedef LONG NTSTATUS;
#define NT_SUCCESS(Status)								((NTSTATUS)(Status) >= 0)
#define STATUS_UNSUCCESSFUL								((NTSTATUS)0xC0000001L)
#define STATUS_INFO_LENGTH_MISMATCH						((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_TOO_SMALL							((NTSTATUS)0xC0000023L)

#define POINTER32(Type) ULONG
#define POINTER64(Type) ULONG64

		typedef struct _STRING {
			USHORT Length;
			USHORT MaximumLength;
			PCHAR  Buffer;
		} STRING, *PSTRING;

		typedef struct _UNICODE_STRING {
			USHORT Length;
			USHORT MaximumLength;
			PWSTR  Buffer;
		} UNICODE_STRING, *PUNICODE_STRING;

		typedef STRING ANSI_STRING;
		typedef PSTRING PANSI_STRING;
		typedef STRING OEM_STRING;
		typedef PSTRING POEM_STRING;
		typedef CONST STRING* PCOEM_STRING;
		typedef const UNICODE_STRING *PCUNICODE_STRING;

		typedef struct _IO_STATUS_BLOCK
		{
			union
			{
				NTSTATUS Status;
				PVOID Pointer;
			};
			ULONG_PTR Information;
		} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
		typedef struct _CLIENT_ID
		{
			HANDLE UniqueProcess;
			HANDLE UniqueThread;
		} CLIENT_ID, *PCLIENT_ID;

		typedef struct _CLIENT_ID32
		{
			DWORD UniqueProcess;
			DWORD UniqueThread;
		} CLIENT_ID32, *PCLIENT_ID32;

		typedef struct _CLIENT_ID64
		{
			DWORD64 UniqueProcess;
			DWORD64 UniqueThread;
		} CLIENT_ID64, *PCLIENT_ID64;

		typedef struct _CURDIR
		{
			UNICODE_STRING DosPath;
			HANDLE Handle;
		} CURDIR, *PCURDIR;

		typedef struct _STRING32
		{
			USHORT Length;
			USHORT MaximumLength;
			ULONG Buffer;
		} STRING32, *PSTRING32;
		typedef struct _STRING64
		{
			USHORT Length;
			USHORT MaximumLength;
			ULONGLONG Buffer;
		} STRING64, *PSTRING64;
		typedef struct _UNICODE_STRING32
		{
			USHORT  Length;
			USHORT  MaximumLength;
			ULONG Buffer;
		} UNICODE_STRING32, *PUNICODE_STRING32;
		typedef struct _UNICODE_STRING64
		{
			USHORT  Length;
			USHORT  MaximumLength;
			ULONGLONG Buffer;
		} UNICODE_STRING64, *PUNICODE_STRING64;

		typedef enum _SYSTEM_INFORMATION_CLASS
		{
			SystemBasicInformation,                // 0        Y        N
			SystemProcessorInformation,            // 1        Y        N
			SystemPerformanceInformation,          // 2        Y        N
			SystemTimeOfDayInformation,            // 3        Y        N
			SystemNotImplemented1,                 // 4        Y        N
			SystemProcessesAndThreadsInformation,  // 5        Y        N
			SystemCallCounts,                      // 6        Y        N
			SystemConfigurationInformation,        // 7        Y        N
			SystemProcessorTimes,                  // 8        Y        N
			SystemGlobalFlag,                      // 9        Y        Y
			SystemNotImplemented2,                 // 10       Y        N
			SystemModuleInformation,               // 11       Y        N
			SystemLockInformation,               // 12       Y        N
			SystemNotImplemented3,               // 13       Y        N
			SystemNotImplemented4,               // 14       Y        N
			SystemNotImplemented5,               // 15       Y        N
			SystemHandleInformation,             // 16       Y        N
			SystemObjectInformation,             // 17       Y        N
			SystemPagefileInformation,           // 18       Y        N
			SystemInstructionEmulationCounts,    // 19       Y        N
			SystemInvalidInfoClass1,             // 20
			SystemCacheInformation,              // 21       Y        Y
			SystemPoolTagInformation,            // 22       Y        N
			SystemProcessorStatistics,           // 23       Y        N
			SystemDpcInformation,                // 24       Y        Y
			SystemNotImplemented6,               // 25       Y        N
			SystemLoadImage,                     // 26       N        Y
			SystemUnloadImage,                   // 27       N        Y
			SystemTimeAdjustment,                // 28       Y        Y
			SystemNotImplemented7,               // 29       Y        N
			SystemNotImplemented8,               // 30       Y        N
			SystemNotImplemented9,               // 31       Y        N
			SystemCrashDumpInformation,          // 32       Y        N
			SystemExceptionInformation,          // 33       Y        N
			SystemCrashDumpStateInformation,     // 34       Y        Y/N
			SystemKernelDebuggerInformation,     // 35       Y        N
			SystemContextSwitchInformation,      // 36       Y        N
			SystemRegistryQuotaInformation,      // 37       Y        Y
			SystemLoadAndCallImage,              // 38       N        Y
			SystemPrioritySeparation,            // 39       N        Y
			SystemNotImplemented10,              // 40       Y        N
			SystemNotImplemented11,              // 41       Y        N
			SystemInvalidInfoClass2,             // 42
			SystemInvalidInfoClass3,             // 43
			SystemTimeZoneInformation,           // 44       Y        N
			SystemLookasideInformation,          // 45       Y        N
			SystemSetTimeSlipEvent,              // 46       N        Y
			SystemCreateSession,                 // 47       N        Y
			SystemDeleteSession,                 // 48       N        Y
			SystemInvalidInfoClass4,             // 49
			SystemRangeStartInformation,         // 50       Y        N
			SystemVerifierInformation,           // 51       Y        Y
			SystemAddVerifier,                   // 52       N        Y
			SystemSessionProcessesInformation    // 53       Y        N
		} SYSTEM_INFORMATION_CLASS;

		typedef LONG KPRIORITY;

		typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
			USHORT UniqueProcessId;
			USHORT CreatorBackTraceIndex;
			UCHAR ObjectTypeIndex;
			UCHAR HandleAttributes;
			USHORT HandleValue;
			PVOID Object;
			ULONG GrantedAccess;
		} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

		typedef struct _SYSTEM_HANDLE_INFORMATION {
			ULONG NumberOfHandles;
			SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
		} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

		typedef enum _THREADINFOCLASS {
			ThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
			ThreadTimes, // q: KERNEL_USER_TIMES
			ThreadPriority, // s: KPRIORITY
			ThreadBasePriority, // s: LONG
			ThreadAffinityMask, // s: KAFFINITY
			ThreadImpersonationToken, // s: HANDLE
			ThreadDescriptorTableEntry,
			ThreadEnableAlignmentFaultFixup, // s: BOOLEAN
			ThreadEventPair,
			ThreadQuerySetWin32StartAddress, // q: PVOID
			ThreadZeroTlsCell, // 10
			ThreadPerformanceCount, // q: LARGE_INTEGER
			ThreadAmILastThread, // q: ULONG
			ThreadIdealProcessor, // s: ULONG
			ThreadPriorityBoost, // qs: ULONG
			ThreadSetTlsArrayAddress,
			ThreadIsIoPending, // q: ULONG
			ThreadHideFromDebugger, // s: void
			ThreadBreakOnTermination, // qs: ULONG
			ThreadSwitchLegacyState,
			ThreadIsTerminated, // 20, q: ULONG
			ThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
			ThreadIoPriority, // qs: ULONG
			ThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION
			ThreadPagePriority, // q: ULONG
			ThreadActualBasePriority,
			ThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
			ThreadCSwitchMon,
			ThreadCSwitchPmu,
			ThreadWow64Context, // q: WOW64_CONTEXT
			ThreadGroupInformation, // 30, q: GROUP_AFFINITY
			ThreadUmsInformation,
			ThreadCounterProfiling,
			ThreadIdealProcessorEx, // q: PROCESSOR_NUMBER
			ThreadCpuAccountingInformation, // since WIN8
			ThreadSuspendCount, // since WINBLUE
			MaxThreadInfoClass
		} THREADINFOCLASS;

		typedef enum _PROCESSINFOCLASS
		{
			ProcessBasicInformation, // 0, q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
			ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
			ProcessIoCounters, // q: IO_COUNTERS
			ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX
			ProcessTimes, // q: KERNEL_USER_TIMES
			ProcessBasePriority, // s: KPRIORITY
			ProcessRaisePriority, // s: ULONG
			ProcessDebugPort, // q: HANDLE
			ProcessExceptionPort, // s: HANDLE
			ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
			ProcessLdtInformation, // 10
			ProcessLdtSize,
			ProcessDefaultHardErrorMode, // qs: ULONG
			ProcessIoPortHandlers, // (kernel-mode only)
			ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
			ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
			ProcessUserModeIOPL,
			ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
			ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
			ProcessWx86Information,
			ProcessHandleCount, // 20, q: ULONG, PROCESS_HANDLE_INFORMATION
			ProcessAffinityMask, // s: KAFFINITY
			ProcessPriorityBoost, // qs: ULONG
			ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
			ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
			ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
			ProcessWow64Information, // q: ULONG_PTR
			ProcessImageFileName, // q: UNICODE_STRING
			ProcessLUIDDeviceMapsEnabled, // q: ULONG
			ProcessBreakOnTermination, // qs: ULONG
			ProcessDebugObjectHandle, // 30, q: HANDLE
			ProcessDebugFlags, // qs: ULONG
			ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
			ProcessIoPriority, // qs: ULONG
			ProcessExecuteFlags, // qs: ULONG
			ProcessResourceManagement,
			ProcessCookie, // q: ULONG
			ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
			ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
			ProcessPagePriority, // q: ULONG
			ProcessInstrumentationCallback, // 40
			ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
			ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
			ProcessImageFileNameWin32, // q: UNICODE_STRING
			ProcessImageFileMapping, // q: HANDLE (input)
			ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
			ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
			ProcessGroupInformation, // q: USHORT[]
			ProcessTokenVirtualizationEnabled, // s: ULONG
			ProcessConsoleHostProcess, // q: ULONG_PTR
			ProcessWindowInformation, // 50, q: PROCESS_WINDOW_INFORMATION
			ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
			ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
			ProcessDynamicFunctionTableInformation,
			ProcessHandleCheckingMode,
			ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
			ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
			ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
			ProcessHandleTable, // since WINBLUE
			ProcessCheckStackExtentsMode,
			ProcessCommandLineInformation, // 60, q: UNICODE_STRING
			ProcessProtectionInformation, // q: PS_PROTECTION
			MaxProcessInfoClass
		} PROCESSINFOCLASS, *PPROCESSINFOCLASS;

		typedef	struct _CURDIR32
		{
			UNICODE_STRING32	DosPath;
			ULONG	ConsoleHandle;
		}CURDIR32, *PCURDIR32;
		typedef	struct _CURDIR64
		{
			UNICODE_STRING64	DosPath;
			PVOID64	ConsoleHandle;
		}CURDIR64, *PCURDIR64;

		typedef struct _RTL_DRIVE_LETTER_CURDIR
		{
			USHORT Flags;
			USHORT Length;
			ULONG TimeStamp;
			STRING DosPath;
		} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;
		typedef struct _RTL_DRIVE_LETTER_CURDIR32
		{
			USHORT Flags;
			USHORT Length;
			ULONG TimeStamp;
			STRING32 DosPath;
		} RTL_DRIVE_LETTER_CURDIR32, *PRTL_DRIVE_LETTER_CURDIR32;
		typedef struct _RTL_DRIVE_LETTER_CURDIR64
		{
			USHORT Flags;
			USHORT Length;
			ULONG TimeStamp;
			STRING64 DosPath;
		} RTL_DRIVE_LETTER_CURDIR64, *PRTL_DRIVE_LETTER_CURDIR64;

#define RTL_MAX_DRIVE_LETTERS 32
		typedef struct _RTL_USER_PROCESS_PARAMETERS
		{
			ULONG MaximumLength;
			ULONG Length;
			ULONG Flags;
			ULONG DebugFlags;
			HANDLE ConsoleHandle;
			ULONG ConsoleFlags;
			HANDLE StandardInput;
			HANDLE StandardOutput;
			HANDLE StandardError;
			CURDIR CurrentDirectory;
			UNICODE_STRING DllPath;
			UNICODE_STRING ImagePathName;
			UNICODE_STRING CommandLine;
			PVOID Environment;
			ULONG StartingX;
			ULONG StartingY;
			ULONG CountX;
			ULONG CountY;
			ULONG CountCharsX;
			ULONG CountCharsY;
			ULONG FillAttribute;
			ULONG WindowFlags;
			ULONG ShowWindowFlags;
			UNICODE_STRING WindowTitle;
			UNICODE_STRING DesktopInfo;
			UNICODE_STRING ShellInfo;
			UNICODE_STRING RuntimeData;
			RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];
			ULONG EnvironmentSize;
			ULONG EnvironmentVersion;
			PVOID PackageDependencyData;
			ULONG ProcessGroupId;
		} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

		typedef struct _RTL_USER_PROCESS_PARAMETERS32
		{
			ULONG MaximumLength;
			ULONG Length;
			ULONG Flags;
			ULONG DebugFlags;
			POINTER32(HANDLE) ConsoleHandle;
			ULONG ConsoleFlags;
			POINTER32(HANDLE) StandardInput;
			POINTER32(HANDLE) StandardOutput;
			POINTER32(HANDLE) StandardError;
			CURDIR32 CurrentDirectory;
			UNICODE_STRING32 DllPath;
			UNICODE_STRING32 ImagePathName;
			UNICODE_STRING32 CommandLine;
			POINTER32(PVOID) Environment;
			ULONG StartingX;
			ULONG StartingY;
			ULONG CountX;
			ULONG CountY;
			ULONG CountCharsX;
			ULONG CountCharsY;
			ULONG FillAttribute;
			ULONG WindowFlags;
			ULONG ShowWindowFlags;
			UNICODE_STRING32 WindowTitle;
			UNICODE_STRING32 DesktopInfo;
			UNICODE_STRING32 ShellInfo;
			UNICODE_STRING32 RuntimeData;
			RTL_DRIVE_LETTER_CURDIR32 CurrentDirectories[RTL_MAX_DRIVE_LETTERS];
			ULONG EnvironmentSize;
			ULONG EnvironmentVersion;
			POINTER32(PVOID) PackageDependencyData;
			ULONG ProcessGroupId;
		} RTL_USER_PROCESS_PARAMETERS32, *PRTL_USER_PROCESS_PARAMETERS32;

		typedef struct _RTL_USER_PROCESS_PARAMETERS64
		{
			ULONG MaximumLength;
			ULONG Length;
			ULONG Flags;
			ULONG DebugFlags;
			POINTER64(HANDLE) ConsoleHandle;
			ULONG ConsoleFlags;
			POINTER64(HANDLE) StandardInput;
			POINTER64(HANDLE) StandardOutput;
			POINTER64(HANDLE) StandardError;
			CURDIR64 CurrentDirectory;
			UNICODE_STRING64 DllPath;
			UNICODE_STRING64 ImagePathName;
			UNICODE_STRING64 CommandLine;
			POINTER64(PVOID) Environment;
			ULONG StartingX;
			ULONG StartingY;
			ULONG CountX;
			ULONG CountY;
			ULONG CountCharsX;
			ULONG CountCharsY;
			ULONG FillAttribute;
			ULONG WindowFlags;
			ULONG ShowWindowFlags;
			UNICODE_STRING64 WindowTitle;
			UNICODE_STRING64 DesktopInfo;
			UNICODE_STRING64 ShellInfo;
			UNICODE_STRING64 RuntimeData;
			RTL_DRIVE_LETTER_CURDIR64 CurrentDirectories[RTL_MAX_DRIVE_LETTERS];
			ULONG EnvironmentSize;
			ULONG EnvironmentVersion;
			POINTER64(PVOID) PackageDependencyData;
			ULONG ProcessGroupId;
		} RTL_USER_PROCESS_PARAMETERS64, *PRTL_USER_PROCESS_PARAMETERS64;

		typedef struct _PEB_LDR_DATA
		{
			DWORD Length;
			UCHAR Initialized;
			PVOID SsHandle;
			LIST_ENTRY InLoadOrderModuleList;
			LIST_ENTRY InMemoryOrderModuleList;
			LIST_ENTRY InInitializationOrderModuleList;
			PVOID EntryInProgress;
		}PEB_LDR_DATA, *PPEB_LDR_DATA;

		typedef struct _PEB_LDR_DATA32
		{
			DWORD Length;
			UCHAR Initialized;
			ULONG SsHandle;
			LIST_ENTRY32 InLoadOrderModuleList;
			LIST_ENTRY32 InMemoryOrderModuleList;
			LIST_ENTRY32 InInitializationOrderModuleList;
			ULONG EntryInProgress;
		}PEB_LDR_DATA32, *PPEB_LDR_DATA32;

		typedef struct _PEB_LDR_DATA64
		{
			DWORD Length;
			UCHAR Initialized;
			PVOID64 SsHandle;
			LIST_ENTRY64 InLoadOrderModuleList;
			LIST_ENTRY64 InMemoryOrderModuleList;
			LIST_ENTRY64 InInitializationOrderModuleList;
			PVOID64 EntryInProgress;
		}PEB_LDR_DATA64, *PPEB_LDR_DATA64;

		typedef struct _PEB
		{
			UCHAR InheritedAddressSpace;
			UCHAR ReadImageFileExecOptions;
			UCHAR BeingDebugged;
			UCHAR SpareBool;
			PVOID Mutant;
			PVOID ImageBaseAddress;
			PPEB_LDR_DATA Ldr;
			PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
		}PEB, *PPEB;

		typedef struct _PEB32
		{
			UCHAR InheritedAddressSpace;
			UCHAR ReadImageFileExecOptions;
			UCHAR BeingDebugged;
			UCHAR SpareBool;
			POINTER32(PVOID64) Mutant;
			POINTER32(PVOID64) ImageBaseAddress;
			POINTER32(PPEB_LDR_DATA) Ldr;
			POINTER32(PRTL_USER_PROCESS_PARAMETERS64) ProcessParameters;
		}PEB32, *PPEB32;

		typedef struct _PEB64
		{
			UCHAR InheritedAddressSpace;
			UCHAR ReadImageFileExecOptions;
			UCHAR BeingDebugged;
			UCHAR SpareBool;
			POINTER64(PVOID64) Mutant;
			POINTER64(PVOID64) ImageBaseAddress;
			POINTER64(PPEB_LDR_DATA) Ldr;
			POINTER64(PRTL_USER_PROCESS_PARAMETERS64) ProcessParameters;
		}PEB64, *PPEB64;

		typedef struct _LDR_DATA_TABLE_ENTRY32
		{
			LIST_ENTRY32 InLoadOrderLinks;
			LIST_ENTRY32 InMemoryOrderLinks;
			LIST_ENTRY32 InInitializationOrderLinks;
			ULONG DllBase;
			ULONG EntryPoint;
			DWORD SizeOfImage;
			UNICODE_STRING32 FullDllName;
			UNICODE_STRING32 BaseDllName;
			DWORD Flags;
			WORD LoadCount;
			WORD TlsIndex;
			LIST_ENTRY32 HashLinks;
			DWORD TimeDateStamp;
			ULONG LoadedImports;
			ULONG EntryPointActivationContext;
			ULONG PatchInformation;
		}LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

		typedef struct _LDR_DATA_TABLE_ENTRY64
		{
			LIST_ENTRY64 InLoadOrderLinks;
			LIST_ENTRY64 InMemoryOrderLinks;
			LIST_ENTRY64 InInitializationOrderLinks;
			PVOID64 DllBase;
			PVOID64 EntryPoint;
			DWORD SizeOfImage;
			UNICODE_STRING64 FullDllName;
			UNICODE_STRING64 BaseDllName;
			DWORD Flags;
			WORD LoadCount;
			WORD TlsIndex;
			LIST_ENTRY64 HashLinks;
			DWORD TimeDateStamp;
			PVOID64 LoadedImports;
			PVOID64 EntryPointActivationContext;
			PVOID64 PatchInformation;
		}LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

		typedef struct _TEB
		{
			NT_TIB NtTib;
			PVOID EnvironmentPointer;
			CLIENT_ID ClientId;
			PVOID ActiveRpcHandle;
			PVOID ThreadLocalStoragePointer;
			PPEB ProcessEnvironmentBlock;
			ULONG LastErrorValue;
			// [TODO] more...
		} TEB, *PTEB;

		typedef struct _THREAD_BASIC_INFORMATION
		{
			NTSTATUS ExitStatus;
			PTEB TebBaseAddress;
			CLIENT_ID ClientId;
			ULONG_PTR AffinityMask;
			KPRIORITY Priority;
			LONG BasePriority;
		} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

		typedef struct _THREAD_BASIC_INFORMATION32
		{
			NTSTATUS ExitStatus;
			ULONG TebBaseAddress;
			CLIENT_ID32 ClientId;
			ULONG AffinityMask;
			KPRIORITY Priority;
			LONG BasePriority;
		} THREAD_BASIC_INFORMATION32, *PTHREAD_BASIC_INFORMATION32;

		typedef struct _THREAD_BASIC_INFORMATION64
		{
			ULONG ExitStatus;
			ULONG64 TebBaseAddress;
			CLIENT_ID64 ClientId;
			ULONG64 AffinityMask;
			KPRIORITY Priority;
			LONG BasePriority;
		} THREAD_BASIC_INFORMATION64, *PTHREAD_BASIC_INFORMATION64;


		// NtReadVirtualMemory
		typedef NTSTATUS(WINAPI *__NtReadVirtualMemory)(
			IN HANDLE ProcessHandle,
			IN PVOID BaseAddress,
			IN OUT PVOID Buffer,
			IN SIZE_T NumberOfBytesToRead,
			OUT SIZE_T* NumberOfBytesReaded
			);

		// NtWow64ReadVirtualMemory64
		typedef NTSTATUS(WINAPI *__NtWow64ReadVirtualMemory64)(
			IN HANDLE ProcessHandle,
			IN PVOID64 BaseAddress,
			IN OUT PVOID Buffer,
			IN UINT64 NumberOfBytesToRead,
			OUT PUINT64 NumberOfBytesReaded
			);

		// NTWow64WriteVirtualMemory64
		typedef NTSTATUS(NTAPI *__NtWow64WriteVirtualMemory64)(
			IN  HANDLE   ProcessHandle,
			IN  PVOID64  BaseAddress,
			OUT PVOID    BufferData,
			IN  ULONG64  BufferLength,
			OUT PULONG64 ReturnLength OPTIONAL);

		// NtWriteVirtualMemory
		typedef NTSTATUS(NTAPI *__NtWriteVirtualMemory)(
			IN HANDLE    ProcessHandle,
			IN PVOID     BaseAddress,
			IN PVOID     Buffer,
			IN SIZE_T     NumberOfBytesToWrite,
			OUT SIZE_T*   NumberOfBytesWritten OPTIONAL);

		// NtSuspendProcess
		typedef NTSTATUS(NTAPI *__NtSuspendProcess)(
			__in HANDLE ProcessHandle
			);

		// NtQuerySystemInformation
		typedef NTSTATUS(NTAPI *__NtQuerySystemInformation)(
			IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
			IN OUT PVOID SystemInformation,
			IN ULONG SystemInformationLength,
			OUT PULONG ReturnLength OPTIONAL
			);

		// NtQueryInformationThread
		typedef NTSTATUS(NTAPI *__NtQueryInformationThread)(
			IN   HANDLE   ThreadHandle,
			IN   THREADINFOCLASS   ThreadInformationClass,
			OUT  PVOID   ThreadInformation,
			IN   ULONG   ThreadInformationLength,
			OUT  PULONG   ReturnLength   OPTIONAL
			);

		// NtWow64QueryInformationProcess64
		typedef NTSTATUS(NTAPI *__NtWow64QueryInformationProcess64)(
			IN HANDLE ProcessHandle,
			IN PROCESSINFOCLASS InformationClass,
			OUT PVOID ProcessInformation,
			IN ULONG ProcessInformationLength,
			OUT PULONG ReturnLength OPTIONAL
			);

		// NtQueryInformationProcess
		typedef NTSTATUS(NTAPI *__NtQueryInformationProcess)(
			IN HANDLE ProcessHandle,
			IN PROCESSINFOCLASS InformationClass,
			OUT PVOID ProcessInformation,
			IN ULONG ProcessInformationLength,
			OUT PULONG ReturnLength OPTIONAL
			);

		// NtResumeProcess
		typedef NTSTATUS(NTAPI *__NtResumeProcess)(
			__in HANDLE ProcessHandle
			);

		// Wow64SuspendThread
		typedef DWORD(WINAPI *__Wow64SuspendThread)(
			__in HANDLE hThread
			);

		// RtlCreateUserThread
		typedef NTSTATUS(NTAPI *__RtlCreateUserThread)(
			IN HANDLE Process,
			IN PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
			IN BOOLEAN CreateSuspended,
			IN ULONG ZeroBits OPTIONAL,
			IN SIZE_T MaximumStackSize OPTIONAL,
			IN SIZE_T CommittedStackSize OPTIONAL,
			IN PVOID StartAddress,
			IN PVOID Parameter OPTIONAL,
			OUT PHANDLE Thread OPTIONAL,
			OUT PCLIENT_ID ClientId OPTIONAL
			);



#ifdef __cplusplus
	} // extern "C"
#endif

#ifndef IN_RANGE
#define IN_RANGE(Locate,Start,Size) (((ULONGLONG)Locate>=(ULONGLONG)Start) && ((ULONGLONG)Locate<=((ULONGLONG)Start+Size)))
#endif

	typedef std::function<bool(PROCESSENTRY32 &entry)> ProcessCallback;

	bool ReadUnicodeString32(HANDLE phd, std::wstring& wstr, PUNICODE_STRING32 ustr, __NtReadVirtualMemory read_routine)
	{
		SIZE_T readlen;
		wstr.assign(ustr->Length / 2, 0);
		NTSTATUS status = read_routine(phd, (PVOID)ustr->Buffer, (PVOID)wstr.c_str(), ustr->Length, &readlen);
		if (!NT_SUCCESS(status)) {
			wstr.clear();
			return false;
		}
		return true;
	}

#ifdef _M_IX86
	bool ReadUnicodeString64(HANDLE phd, std::wstring& wstr, PUNICODE_STRING64 ustr, __NtWow64ReadVirtualMemory64 read_routine)
#else
	bool ReadUnicodeString64(HANDLE phd, std::wstring& wstr, PUNICODE_STRING64 ustr, __NtReadVirtualMemory read_routine)
#endif
	{
		ULONG64 readlen;
		wstr.assign(ustr->Length / 2, 0);
		NTSTATUS status = read_routine(phd, (PVOID64)ustr->Buffer, (PVOID)wstr.c_str(), ustr->Length, &readlen);
		if (!NT_SUCCESS(status)) {
			return false;
		}
		return true;
	}

	bool WriteUnicodeString32(HANDLE phd, const std::wstring& wstr, PUNICODE_STRING32 ustr, __NtWriteVirtualMemory write_routine)
	{
		SIZE_T readlen;
		NTSTATUS status = write_routine(phd, (PVOID)ustr->Buffer, (PVOID)wstr.c_str(), wstr.size() * sizeof(WCHAR), &readlen);
		if (!NT_SUCCESS(status)) {
			return false;
		}
		return true;
	}

#ifdef _M_IX86
	bool WriteUnicodeString64(HANDLE phd, const std::wstring& wstr, PUNICODE_STRING64 ustr, __NtWow64WriteVirtualMemory64 write_routine)
#else
	bool WriteUnicodeString64(HANDLE phd, const std::wstring& wstr, PUNICODE_STRING64 ustr, __NtWriteVirtualMemory write_routine)
#endif
	{
		ULONG64 readlen;
		NTSTATUS status = write_routine(phd, (PVOID64)ustr->Buffer, (PVOID)wstr.c_str(), wstr.size() * sizeof(WCHAR), &readlen);
		if (!NT_SUCCESS(status)) {
			return false;
		}
		return true;
	}

	FORCEINLINE PVOID GetReadRoutine32()
	{
		HMODULE ntdll = GetModuleHandle(_T("ntdll.dll"));
		return GetProcAddress(ntdll, "NtReadVirtualMemory");
	}

	FORCEINLINE PVOID GetReadRoutine64()
	{
		HMODULE ntdll = GetModuleHandle(_T("ntdll.dll"));
#ifdef _M_IX86
		return GetProcAddress(ntdll, "NtWow64ReadVirtualMemory64");
#else
		return GetProcAddress(ntdll, "NtReadVirtualMemory");
#endif
	}

	FORCEINLINE PVOID GetWriteRoutine32()
	{
		HMODULE ntdll = GetModuleHandle(_T("ntdll.dll"));
		return GetProcAddress(ntdll, "NtWriteVirtualMemory");
	}

	FORCEINLINE PVOID GetWriteRoutine64()
	{
		HMODULE ntdll = GetModuleHandle(_T("ntdll.dll"));
#ifdef _M_IX86
		return GetProcAddress(ntdll, "NtWow64WriteVirtualMemory64");
#else
		return GetProcAddress(ntdll, "NtWriteVirtualMemory");
#endif
	}

	/*++
	Description:
		check process is deleted
	Arguments:
		pid - process id
	Return:
		bool
	--*/
	bool PsIsDeleted(DWORD Pid)
	{
		bool result = false;
		HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, Pid);
		if (process)
		{
			if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0)	//signal
				result = true;
			CloseHandle(process);
		}
		else
		{
			if (GetLastError() == ERROR_INVALID_PARAMETER)	//87 PID²»´æÔÚ
				result = true;
		}
		return result;
	}

	/*++
	Description:
		get process basic information
	Arguments:
		phd - process handle
		pbi32 - PROCESS_BASIC_INFORMATION
	Return:
		bool
	--*/
	bool PsGetPbi32(HANDLE Process, PROCESS_BASIC_INFORMATION32& Pbi32)
	{
		typedef struct _PROCESS_BASIC_INFORMATION {
			NTSTATUS ExitStatus;
			PPEB PebBaseAddress;
			ULONG_PTR AffinityMask;
			KPRIORITY BasePriority;
			ULONG_PTR UniqueProcessId;
			ULONG_PTR InheritedFromUniqueProcessId;
		} PROCESS_BASIC_INFORMATION;

		NTSTATUS ntStatus;
		ULONG RetLen;
		PROCESS_BASIC_INFORMATION Pbi;
		HMODULE hNtdll = GetModuleHandle(_T("ntdll.dll"));
		auto pfnNtQueryInformationProcess = (__NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
		if (!pfnNtQueryInformationProcess)
			return false;
		ntStatus = pfnNtQueryInformationProcess(Process, ProcessBasicInformation, &Pbi, sizeof(PROCESS_BASIC_INFORMATION), &RetLen);
		if (!NT_SUCCESS(ntStatus))
			return false;
		Pbi32.ExitStatus = Pbi.ExitStatus;
		Pbi32.PebBaseAddress = (ULONG)Pbi.PebBaseAddress;
		Pbi32.AffinityMask = (ULONG)Pbi.AffinityMask;
		Pbi32.BasePriority = Pbi.BasePriority;
		Pbi32.UniqueProcessId = (ULONG)Pbi.UniqueProcessId;
		Pbi32.InheritedFromUniqueProcessId = (ULONG)Pbi.InheritedFromUniqueProcessId;
		return true;
	}

	/*++
	Description:
		get process basic information
	Arguments:
		phd - process handle
		pbi64 - PROCESS_BASIC_INFORMATION64
	Return:
		bool
	--*/
	bool PsGetPbi64(__in HANDLE phd, __out PROCESS_BASIC_INFORMATION64 &pbi64)
	{
		NTSTATUS status;
		ULONG retlen;
		HMODULE ntdll = GetModuleHandle(_T("ntdll.dll"));
#ifdef _M_IX86
		auto pNtQueryInformationProcess = (__NtWow64QueryInformationProcess64)GetProcAddress(ntdll, "NtWow64QueryInformationProcess64");
#else
		auto pNtQueryInformationProcess = (__NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
#endif
		if (!pNtQueryInformationProcess)
			return false;
		status = pNtQueryInformationProcess(phd, ProcessBasicInformation, &pbi64, sizeof(PROCESS_BASIC_INFORMATION64), &retlen);
		if (!NT_SUCCESS(status)) {
			return false;
		}
		return true;
	}


	/*++
	Description:
		get process PEB
	Arguments:
		phd - process handle
	Return:
		PEB
	--*/
	PVOID PsGetPebAddress32(__in HANDLE phd)
	{
		NTSTATUS status;
		ULONG retlen;
		PVOID peb = NULL;
		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
		auto pNtQueryInformationProcess = (__NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
#ifdef _M_IX86
		PROCESS_BASIC_INFORMATION32 pbi32 = { 0 };
		status = pNtQueryInformationProcess(phd, ProcessBasicInformation, &pbi32, sizeof(PROCESS_BASIC_INFORMATION32), &retlen);
		if (!NT_SUCCESS(status)) {
			return NULL;
		}
		peb = (PVOID)pbi32.PebBaseAddress;
#else
		status = pNtQueryInformationProcess(phd, ProcessWow64Information, &peb, sizeof(PVOID), &retlen);
		if (!NT_SUCCESS(status)) {
			return NULL;
		}
#endif
		return peb;
	}

	/*++
	Description:
		get process PEB
	Arguments:
		phd - process handle
	Return:
		PEB
	--*/
	PVOID64 PsGetPebAddress64(__in HANDLE phd)
	{
		PROCESS_BASIC_INFORMATION64 pbi64 = { 0 };
		if (PsGetPbi64(phd, pbi64))
			return (PVOID64)pbi64.PebBaseAddress;
		return NULL;
	}

	/*++
	Description:
		get 32bit process base information
	Arguments:
		pid - process id
		info - base information
	Return:
		bool
	--*/
	bool PsGetProcessInfo32(__in DWORD pid, __out PROCESS_BASE_INFO &info)
	{
		auto read_routine = (__NtReadVirtualMemory)GetReadRoutine32();
		if (!read_routine) return false;

		NTSTATUS status = STATUS_SUCCESS;
		HANDLE phd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (!phd) {
			return false;
		}
		do {
			PVOID peb_addr = PsGetPebAddress32(phd);
			if (!peb_addr) break;

			PEB32 peb;
			SIZE_T readlen;
			status = read_routine(phd, peb_addr, &peb, sizeof(peb), &readlen);
			if (!NT_SUCCESS(status)) break;

			RTL_USER_PROCESS_PARAMETERS32 params;
			status = read_routine(phd, (PVOID)peb.ProcessParameters, &params, sizeof(params), &readlen);
			if (!NT_SUCCESS(status)) break;

			if (!ReadUnicodeString32(phd, info.ImagePathName, &params.ImagePathName, read_routine)) break;
			if (!ReadUnicodeString32(phd, info.CommandLine, &params.CommandLine, read_routine)) break;
			if (!ReadUnicodeString32(phd, info.WindowTitle, &params.WindowTitle, read_routine)) break;
			if (!ReadUnicodeString32(phd, info.CurrentDirectory, &params.CurrentDirectory.DosPath, read_routine)) break;
		} while (0);

		CloseHandle(phd);
		if (!NT_SUCCESS(status)) {
			return false;
		}
		return true;
	}

	/*++
	Description:
		get 64bit process base information
	Arguments:
		pid - process id
		info - base information
	Return:
		bool
	--*/
	bool PsGetProcessInfo64(__in DWORD pid, __out PROCESS_BASE_INFO &info)
	{
#ifdef _M_IX86
		auto read_routine = (__NtWow64ReadVirtualMemory64)GetReadRoutine64();
#else
		auto read_routine = (__NtReadVirtualMemory)GetReadRoutine64();
#endif
		if (!read_routine) return false;

		NTSTATUS status = STATUS_SUCCESS;
		HANDLE phd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (!phd) {
			return false;
		}
		do {
			PVOID64 peb_addr = PsGetPebAddress64(phd);
			if (!peb_addr) break;

			PEB64 peb;
			ULONG64 readlen;
			status = read_routine(phd, peb_addr, &peb, sizeof(peb), &readlen);
			if (!NT_SUCCESS(status)) break;

			RTL_USER_PROCESS_PARAMETERS64 params;
			status = read_routine(phd, (PVOID64)peb.ProcessParameters, &params, sizeof(params), &readlen);
			if (!NT_SUCCESS(status)) break;

			if (!ReadUnicodeString64(phd, info.ImagePathName, &params.ImagePathName, read_routine)) break;
			if (!ReadUnicodeString64(phd, info.CommandLine, &params.CommandLine, read_routine)) break;
			if (!ReadUnicodeString64(phd, info.WindowTitle, &params.WindowTitle, read_routine)) break;
			if (!ReadUnicodeString64(phd, info.CurrentDirectory, &params.CurrentDirectory.DosPath, read_routine)) break;
		} while (0);

		CloseHandle(phd);
		if (!NT_SUCCESS(status)) {
			return false;
		}
		return true;
	}

	/*++
	Description:
		get 32bit module list information
	Arguments:
		pid - process id
		infos - module list information
	Return:
		bool
	--*/
	bool PsGetModulesInfo32(__in DWORD pid, __out std::vector<MODULE_BASE_INFO32> &infos)
	{
		auto read_routine = (__NtReadVirtualMemory)GetReadRoutine32();
		if (!read_routine) return false;

		NTSTATUS status = STATUS_SUCCESS;
		HANDLE phd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (!phd) {
			return false;
		}
		do {
			PVOID peb_addr = PsGetPebAddress32(phd);
			if (!peb_addr) break;

			PEB32 peb;
			SIZE_T readlen;
			status = read_routine(phd, peb_addr, &peb, sizeof(peb), &readlen);
			if (!NT_SUCCESS(status)) break;

			PEB_LDR_DATA32 ldr;
			LIST_ENTRY32 node, *last = NULL;
			status = read_routine(phd, (PVOID)peb.Ldr, &ldr, sizeof(ldr), &readlen);
			if (!NT_SUCCESS(status)) break;

			node = ldr.InLoadOrderModuleList;
			last = (LIST_ENTRY32*)((ULONG32)peb.Ldr + FIELD_OFFSET(PEB_LDR_DATA32, InLoadOrderModuleList));

			while ((LIST_ENTRY32*)node.Flink != last) {
				LDR_DATA_TABLE_ENTRY32 entry;
				status = read_routine(phd, (PVOID)(ULONG32)node.Flink, &entry, sizeof(entry), &readlen);
				if (!NT_SUCCESS(status)) break;

				if (entry.EntryPoint != NULL && !IN_RANGE(entry.EntryPoint, entry.DllBase, entry.SizeOfImage)) {
					break;
				}
				MODULE_BASE_INFO32 info;
				info.DllBase = entry.DllBase;
				info.EntryPoint = entry.EntryPoint;
				info.SizeOfImage = entry.SizeOfImage;
				info.Flags = entry.Flags;
				info.LoadCount = entry.LoadCount;
				info.TimeDateStamp = entry.TimeDateStamp;
				ReadUnicodeString32(phd, info.FullDllName, &entry.FullDllName, read_routine);
				ReadUnicodeString32(phd, info.BaseDllName, &entry.BaseDllName, read_routine);
				node = entry.InLoadOrderLinks;
				infos.push_back(info);
			}
		} while (0);

		CloseHandle(phd);
		if (!NT_SUCCESS(status)) {
			return false;
		}
		return true;
	}

	/*++
	Description:
		get 64bit module list information
	Arguments:
		pid - process id
		infos - module list information
	Return:
		bool
	--*/
	bool PsGetModulesInfo64(__in DWORD pid, __out std::vector<MODULE_BASE_INFO64> &infos)
	{
#ifdef _M_IX86
		auto read_routine = (__NtWow64ReadVirtualMemory64)GetReadRoutine64();
#else
		auto read_routine = (__NtReadVirtualMemory)GetReadRoutine64();
#endif
		if (!read_routine) return false;

		NTSTATUS status = STATUS_SUCCESS;
		HANDLE phd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (!phd) {
			return false;
		}
		do {
			PVOID64 peb_addr = PsGetPebAddress64(phd);
			if (!peb_addr) break;

			PEB64 peb;
			ULONG64 readlen;
			status = read_routine(phd, peb_addr, &peb, sizeof(peb), &readlen);
			if (!NT_SUCCESS(status)) break;

			PEB_LDR_DATA64 ldr;
			LIST_ENTRY64 node, *last = NULL;
			status = read_routine(phd, (PVOID)peb.Ldr, &ldr, sizeof(ldr), &readlen);
			if (!NT_SUCCESS(status)) break;

			node = ldr.InLoadOrderModuleList;
			last = (LIST_ENTRY64*)((ULONG64)peb.Ldr + FIELD_OFFSET(PEB_LDR_DATA64, InLoadOrderModuleList));

			while ((LIST_ENTRY64*)node.Flink != last) {
				LDR_DATA_TABLE_ENTRY64 entry;
				status = read_routine(phd, (PVOID64)(ULONG64)node.Flink, &entry, sizeof(entry), &readlen);
				if (!NT_SUCCESS(status)) break;

				if (entry.EntryPoint != NULL && !IN_RANGE(entry.EntryPoint, entry.DllBase, entry.SizeOfImage)) {
					break;
				}
				MODULE_BASE_INFO64 info;
				info.DllBase = (ULONG64)entry.DllBase;
				info.EntryPoint = (ULONG64)entry.EntryPoint;
				info.SizeOfImage = entry.SizeOfImage;
				info.Flags = entry.Flags;
				info.LoadCount = entry.LoadCount;
				info.TimeDateStamp = entry.TimeDateStamp;
				ReadUnicodeString64(phd, info.FullDllName, &entry.FullDllName, read_routine);
				ReadUnicodeString64(phd, info.BaseDllName, &entry.BaseDllName, read_routine);
				node = entry.InLoadOrderLinks;
				infos.push_back(info);
			}
		} while (0);

		CloseHandle(phd);
		if (!NT_SUCCESS(status)) {
			return false;
		}
		return true;
	}


	bool PsGetThreadEntryAddress32(DWORD Tid, ULONG& EntryAddress)
	{
		bool result = false;
		if (!Tid)
			return false;
		HANDLE hThread = NULL;
		DWORD RetLen;
		NTSTATUS ntStatus;
		do
		{
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, Tid);
			if (!hThread)
				break;
			if (PsIsWow64())
			{
				PVOID64 Wow64ThreadEntry = NULL;
				auto pfnNtQueryInformationThread64 = (__NtQueryInformationThread)GetProcAddress64(
					GetModuleHandle64(L"ntdll.dll"), "NtQueryInformationThread");
				if (!pfnNtQueryInformationThread64)
					break;
				ntStatus = (NTSTATUS)X64Call((DWORD64)pfnNtQueryInformationThread64, 5,
					(DWORD64)hThread,
					(DWORD64)ThreadQuerySetWin32StartAddress,
					(DWORD64)&Wow64ThreadEntry,
					(DWORD64)sizeof(PVOID64),
					(DWORD64)&RetLen);
				if (!NT_SUCCESS(ntStatus))
					break;
				if (Wow64ThreadEntry)
				{
					EntryAddress = (ULONG)Wow64ThreadEntry;
					result = true;
				}
			}
			else
			{
				PVOID ThreadEntry = NULL;
				auto pfnNtQueryInformationThread = (__NtQueryInformationThread)GetProcAddress(
					GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
				if (!pfnNtQueryInformationThread)
					break;
				ntStatus = pfnNtQueryInformationThread(
					hThread,
					ThreadQuerySetWin32StartAddress,
					&ThreadEntry,
					sizeof(PVOID),
					&RetLen);
				if (!NT_SUCCESS(ntStatus))
					break;
				if (ThreadEntry)
				{
					EntryAddress = (ULONG)ThreadEntry;
					result = true;
				}
			}
		} while (0);
		if (hThread)
			CloseHandle(hThread);
		return result;
	}

	bool PsGetThreadEntryAddress64(DWORD Tid, ULONG64& EntryAddress)
	{
		bool result = false;
		if (!Tid)
			return false;
		HANDLE hThread = NULL;
		DWORD RetLen;
		NTSTATUS ntStatus;
		do
		{
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, Tid);
			if (!hThread)
				break;
#ifdef _M_IX86
			PVOID64 ThreadEntry64 = NULL;
			auto pfnNtQueryInformationThread64 = (__NtQueryInformationThread)GetProcAddress64(
				GetModuleHandle64(L"ntdll.dll"), "NtQueryInformationThread");
			if (!pfnNtQueryInformationThread64)
				break;
			ntStatus = (NTSTATUS)X64Call((DWORD64)pfnNtQueryInformationThread64, 5,
				(DWORD64)hThread,
				(DWORD64)ThreadQuerySetWin32StartAddress,
				(DWORD64)&ThreadEntry64,
				(DWORD64)sizeof(PVOID64),
				(DWORD64)&RetLen);
			if (!NT_SUCCESS(ntStatus))
				break;
			if (ThreadEntry64)
			{
				EntryAddress = (ULONG64)ThreadEntry64;
				result = true;
			}
#else
			PVOID ThreadEntry = NULL;
			auto pfnNtQueryInformationThread = (__NtQueryInformationThread)GetProcAddress(
				GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
			if (!pfnNtQueryInformationThread)
				break;
			ntStatus = pfnNtQueryInformationThread(
				hThread,
				ThreadQuerySetWin32StartAddress,
				&ThreadEntry,
				sizeof(PVOID),
				&RetLen);
			if (!NT_SUCCESS(ntStatus))
				break;
			if (ThreadEntry)
			{
				EntryAddress = (ULONG64)ThreadEntry;
				result = true;
			}
#endif
		} while (0);
		if (hThread)
			CloseHandle(hThread);
		return result;
	}

	DWORD PsNormalSuspendThread(DWORD Tid)
	{
		DWORD result = -1;
		HANDLE Thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, Tid);
		if (Thread)
		{
			result = SuspendThread(Thread);
			CloseHandle(Thread);
		}
		return result;
	}

	DWORD PsSuspendWow64Thread(DWORD Tid)
	{
		DWORD result = -1;
		typedef DWORD(WINAPI* WOW64SUSPENDTHREAD)(HANDLE hThread);
		WOW64SUSPENDTHREAD pfnWow64SuspendThread = (WOW64SUSPENDTHREAD)GetProcAddress(
			GetModuleHandleA("kernel32.dll"), "Wow64SuspendThread");
		if (pfnWow64SuspendThread)
		{
			HANDLE Thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, Tid);
			if (Thread)
			{
				result = pfnWow64SuspendThread(Thread);
				CloseHandle(Thread);
			}
		}
		return result;
	}

	/*++
	Description:
		check process is running under wow64 by process handle.
		default process is current.
	Arguments:
		phd - process handle
	Return:
		bool
	--*/
	bool PsIsWow64(HANDLE Process)
	{
		typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
		LPFN_ISWOW64PROCESS fnIsWow64Process = NULL;
		BOOL bIsWow64 = FALSE;
		fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");
		if (NULL != fnIsWow64Process)
		{
			if (!fnIsWow64Process(Process, &bIsWow64))
			{
				// handle error
			}
		}
		return bIsWow64 == TRUE;
	}

	/*++
	Description:
		check process is running under wow64 by process id.
		default process is current.
	Arguments:
		pid - process id
	Return:
		bool
	--*/
	bool PsIsWow64(DWORD Pid)
	{
		bool result = false;
		HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Pid);
		if (process)
		{
			result = PsIsWow64(process);
			CloseHandle(process);
		}
		return result;
	}

	/*++
	Description:
		check process is x64 by process id.
	Arguments:
		pid - process id
	Return:
		bool
	--*/
	bool PsIsX64(DWORD Pid)
	{
		return OsIs64() && !PsIsWow64(Pid);
	}

	/*++
	Description:
		check thread is x64 by thread id
	Arguments:
		tid - thread id
	Return:
		bool
	--*/
	bool PsThreadIsX64(DWORD Tid)
	{
		return PsIsX64(PsGetPidByTid(Tid));
	}

	/*++
	Description:
		check process is existed by pid
	Arguments:
		pid - process id
	Return:
		bool
	--*/
	bool PsIsExisted(DWORD Pid)
	{
		bool Result = false;
		std::vector<DWORD> Pids;
		if (PsEnumProcessId(Pids))
		{
			if (find(begin(Pids), end(Pids), Pid) != end(Pids))
				Result = true;
		}
		if (!Result)
		{
			if (!PsIsDeleted(Pid))
				Result = true;
		}
		return Result;
	}

	/*++
	Description:
		enum process, if callback return false then enum aborted
	Arguments:
		proc_cb - process callback
	Return:
		bool
	--*/
	bool PsEnumProcess(__in ProcessCallback process_cb)
	{
		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snap == INVALID_HANDLE_VALUE) {
			return false;
		}
		PROCESSENTRY32 entry;
		entry.dwSize = sizeof(entry);
		if (!Process32First(snap, &entry)) {
			CloseHandle(snap);
			return false;
		}
		do {
			if (!process_cb(entry))
				break;
		} while (Process32Next(snap, &entry));
		CloseHandle(snap);
		return true;
	}


	/*++
	Description:
		check process is existed by name
	Arguments:
		wild - process name wildcard
	Return:
		bool
	--*/
	bool PsIsNameExisted(const tstring &wild)
	{
		if (wild.empty()) return false;
		bool exsited = false;
		PsEnumProcess([&](PROCESSENTRY32& entry)->bool {
			if (StrCompare(entry.szExeFile, wild)) {
				exsited = true;
				return false;
			}
			return true;
		});
		return exsited;
	}

	/*++
	Description:
		get process full path
	Arguments:
		pid - process id
	Return:
		process path
	--*/
	tstring PsGetProcessPath(DWORD pid)
	{
		if (pid == 0) return _T("System Idle Process");
		if (pid == 4) return _T("System");

		TCHAR path[MAX_PATH + 1] = { 0 };
		HANDLE phd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (phd != NULL)
		{
			if (GetModuleFileNameEx(phd, NULL, path, MAX_PATH) != 0) {
				CloseHandle(phd);
				return path;
			}
			else
			{
				if (GetProcessImageFileName(phd, path, MAX_PATH) != 0) {
					return StrNtToDosPath(path);
				}
			}
		}
		return _T("");
	}

	bool PsFindProcessByName(const tstring& ProcessName, std::vector<DWORD>& Pids)
	{
		Pids.clear();
		if (ProcessName.empty()) {
			return false;
		}
		HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (Snap == INVALID_HANDLE_VALUE) {
			return false;
		}
		PROCESSENTRY32 Entry;
		Entry.dwSize = sizeof(Entry);
		if (Process32First(Snap, &Entry))
		{
			do {
				if (WinLib::StrCompare(Entry.szExeFile, ProcessName))
					Pids.push_back(Entry.th32ProcessID);
			} while (Process32Next(Snap, &Entry));
		}
		CloseHandle(Snap);
		return !Pids.empty();
	}

	/*++
	Description:
		get module path
	Arguments:
		name - module name
		base - module base address
	Return:
		module path
	--*/
	tstring PsGetModulePath(const tstring &ModuleName, HMODULE base)
	{
		HMODULE mod;
		if (base != NULL) mod = base;
		else mod = GetModuleHandle(ModuleName.c_str());
		if (mod != NULL) {
			TCHAR path[MAX_PATH] = { 0 };
			if (GetModuleFileName(mod, path, MAX_PATH - 1) &&
				GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
				return path;
			}
		}
		return _T("");
	}


	/*++
	Routine Description:
		PsGetPidByWindow
	Arguments:
		ClassName - ClassName
		TitleName - TitleName
	Return Value:
		Pid
	--*/
	DWORD PsGetPidByWindow(const tstring& ClassName, const tstring& TitleName)
	{
		DWORD Pid = 0;
		HWND Wnd = FindWindow(ClassName.c_str(), TitleName.c_str());
		if (Wnd != NULL) {
			GetWindowThreadProcessId(Wnd, &Pid);
		}
		return Pid;
	}

	/*++
	Description:
		get process id by thread id
	Arguments:
		tid - thread id
	Return:
		process pid
	--*/
	DWORD PsGetPidByTid(DWORD tid)
	{
		DWORD retlen = 0;
		DWORD pid = 0;
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		HANDLE thd = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
		if (!thd) {
			return -1;
		}
#ifdef _M_IX86
		if (PsIsWow64()) {
			THREAD_BASIC_INFORMATION64 tbi64;
			auto pNtQueryInformationThread64 = GetProcAddress64(GetModuleHandle64(L"ntdll.dll"), "NtQueryInformationThread");
			if (!pNtQueryInformationThread64)
				return 0;
			status = (NTSTATUS)X64Call((DWORD64)pNtQueryInformationThread64, 5,
				(DWORD64)thd,
				(DWORD64)ThreadBasicInformation,
				(DWORD64)&tbi64,
				(DWORD64)sizeof(tbi64),
				(DWORD64)&retlen);
			if (NT_SUCCESS(status)) {
				pid = (DWORD)tbi64.ClientId.UniqueProcess;
			}
			CloseHandle(thd);
			return pid;
		}
#endif

#ifdef _M_IX86
		THREAD_BASIC_INFORMATION32 tbi;
#else
		THREAD_BASIC_INFORMATION64 tbi;
#endif
		auto pNtQueryInformationThread = (__NtQueryInformationThread)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread");
		if (!pNtQueryInformationThread) return -1;
		status = pNtQueryInformationThread(
			thd,
			ThreadBasicInformation,
			&tbi,
			sizeof(tbi),
			&retlen);
		if (NT_SUCCESS(status)) {
			pid = (DWORD)tbi.ClientId.UniqueProcess;
		}
		CloseHandle(thd);
		return pid;
	}

	/*++
	Description:
		get process parent pid
	Arguments:
		pid - process id
	Return:
		process pid
	--*/
	DWORD PsGetParentPid(DWORD Pid)
	{
		DWORD ParentId = 0;
		HANDLE Process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Pid);
		if (!Process)
			return 0;
		if (PsIsX64(Pid)) {
			PROCESS_BASIC_INFORMATION64 Pbi64;
			if (PsGetPbi64(Process, Pbi64))
				ParentId = (DWORD)Pbi64.InheritedFromUniqueProcessId;
		}
		else {
			PROCESS_BASIC_INFORMATION32 Pbi32;
			if (PsGetPbi32(Process, Pbi32))
				ParentId = (DWORD)Pbi32.InheritedFromUniqueProcessId;
		}
		CloseHandle(Process);
		return ParentId;
	}

	/*++
	Description:
		get process child pid list
	Arguments:
		pid - process id
		ChildPids - child processes
	Return:
		bool
	--*/
	bool PsGetChildPids(DWORD pid, std::vector<DWORD>& ChildPids)
	{
		std::vector<DWORD> childs;
		PsEnumProcess([&](PROCESSENTRY32W &entry)->bool {
			if (pid != 0 && pid == entry.th32ParentProcessID) {
				childs.push_back(entry.th32ProcessID);
			}
			return true;
		});
		return true;
	}

	/*++
	Description:
		get process descendant pid list
	Arguments:
		pid - process id
		descendants - descendant processes
	Return:
		bool
	--*/
	bool PsGetDescendantPids(__in DWORD pid, std::vector<DWORD>& descendants)
	{

		std::vector<DWORD> childs;
		PsGetChildPids(pid, childs);
		if (childs.empty()) return true;
		std::for_each(std::begin(childs), std::end(childs), [&](DWORD id) {
			//child can't includes parent
			if (id == pid) return;
			std::vector<DWORD> trees;
			PsGetDescendantPids(id, trees);
			if (!trees.empty())
				descendants.insert(descendants.end(), trees.begin(), trees.end());
			descendants.push_back(id);
		});
		return true;
	}

	/*++
	Description:
		enum process thread id
	Arguments:
		Pid - Pid
		Tids - thread id list
	Return:
		bool
	--*/
	bool PsEnumThreadId(DWORD Pid, std::vector<DWORD>& Tids)
	{
		Tids.clear();
		HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (Snap == INVALID_HANDLE_VALUE) {
			return false;
		}
		THREADENTRY32 Entry;
		Entry.dwSize = sizeof(Entry);
		if (Thread32First(Snap, &Entry)) {
			do {
				if (Entry.th32OwnerProcessID == Pid)
					Tids.push_back(Entry.th32ThreadID);
			} while (Thread32Next(Snap, &Entry));
		}
		CloseHandle(Snap);
		return !Tids.empty();
	}
	/*++
	Description:
		enum process id
	Arguments:
		Pids - process id list
	Return:
		bool
	--*/
	bool PsEnumProcessId(std::vector<DWORD>& Pids)
	{
		Pids.clear();
		HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (Snap == INVALID_HANDLE_VALUE) {
			return false;
		}
		PROCESSENTRY32 Entry;
		Entry.dwSize = sizeof(Entry);
		if (Process32First(Snap, &Entry)) {
			do {
				Pids.push_back(Entry.th32ProcessID);
			} while (Process32Next(Snap, &Entry));
		}
		CloseHandle(Snap);
		return !Pids.empty();
	}

	/*++
	Description:
		enum process id
	Arguments:
		Pids - process id list
	Return:
		bool
	--*/
	bool PsEnumProcessId2(std::set<DWORD>& Pids)
	{
		Pids.clear();
		HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (Snap == INVALID_HANDLE_VALUE) {
			return false;
		}
		PROCESSENTRY32 Entry;
		Entry.dwSize = sizeof(Entry);
		if (Process32First(Snap, &Entry)) {
			do {
				Pids.insert(Entry.th32ProcessID);
			} while (Process32Next(Snap, &Entry));
		}
		CloseHandle(Snap);
		return !Pids.empty();
	}

	bool PsEnumProcessNames(std::map<DWORD, tstring>& ProcNames)
	{
		ProcNames.clear();
		HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (Snap == INVALID_HANDLE_VALUE) {
			return false;
		}

		PROCESSENTRY32 Entry;
		Entry.dwSize = sizeof(Entry);
		if (Process32First(Snap, &Entry)) {
			do {
				ProcNames.insert(std::pair<DWORD, tstring>(Entry.th32ProcessID, Entry.szExeFile));
			} while (Process32Next(Snap, &Entry));
		}
		return true;
	}

	/*++
	Description:
		force enum process id
	Arguments:
		Pids - process id list
	Return:
		bool
	--*/
	bool PsForceEnumProcessId(std::vector<DWORD>& Pids)
	{
		bool result = true;
		for (DWORD i = 8; i < 65536; i += 4)
		{
			if (!PsIsDeleted(i))
				Pids.push_back(i);
		}
		return !Pids.empty();
	}


	/*++
	Routine Description:
		enum module info
	Arguments:
		pid - process id
		Modules - module info list
	Return Value:
		bool
	--*/
	bool PsEnumModule(DWORD Pid, std::vector<MODULEENTRY32>& Modules)
	{
		Modules.clear();
		HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, Pid);
		if (Snap == INVALID_HANDLE_VALUE) {
			return false;
		}
		MODULEENTRY32 Entry;
		Entry.dwSize = sizeof(Entry);
		if (Module32First(Snap, &Entry)) {
			do {
				Modules.push_back(Entry);
			} while (Module32Next(Snap, &Entry));
		}
		CloseHandle(Snap);
		return !Modules.empty();
	}

	/*++
	Description:
		suspend process
	Arguments:
		pid - process id
	Return:
		bool
	--*/
	bool PsSuspendProcess(__in DWORD pid)
	{
		bool result = false;
		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
		__NtSuspendProcess pNtSuspendProcess = (__NtSuspendProcess)GetProcAddress(ntdll, "NtSuspendProcess");
		if (pNtSuspendProcess) {
			HANDLE phd = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
			if (phd) {
				if (NT_SUCCESS(pNtSuspendProcess(phd)))
					result = true;
				CloseHandle(phd);
			}
		}
		return result;
	}

	/*++
	Description:
		suspend thread
	Arguments:
		tid - thread id
	Return:
		previous suspend count
	--*/
	DWORD PsSuspendThread(__in DWORD tid)
	{
#ifdef _AMD64_
		if (!PsThreadIsX64(tid))
			return PsSuspendWow64Thread(tid);
#endif
		return PsNormalSuspendThread(tid);
	}

	/*++
	Description:
		resume thread
	Arguments:
		tid - thread id
	Return:
		previous suspend count
	--*/
	DWORD PsResumeThread(__in DWORD tid)
	{
		DWORD result = -1;
		HANDLE thd = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
		if (thd) {
			result = ResumeThread(thd);
			CloseHandle(thd);
		}
		return result;
	}

	bool PsSuspendProcessByName(const tstring& Name)
	{
		std::vector<DWORD> Pids;
		if (!WinLib::PsFindProcessByName(Name, Pids)) {
			return false;
		}
		for (auto iter2 = Pids.begin(); iter2 != Pids.end(); iter2++) {
			WinLib::PsSuspendProcess(*iter2);
		}
		return true;
	}

	bool PsResumeProcessByName(const tstring& Name)
	{
		std::vector<DWORD> Pids;
		if (!WinLib::PsFindProcessByName(Name, Pids)) {
			return false;
		}
		for (auto iter2 = Pids.begin(); iter2 != Pids.end(); iter2++) {
			WinLib::PsResumeProcess(*iter2);
		}
		return true;
	}

	/*++
	Description:
		resume process
	Arguments:
		pid - process id
	Return:
		bool
	--*/
	bool PsResumeProcess(__in DWORD pid)
	{
		bool result = false;
		HMODULE ntdll = GetModuleHandle(_T("ntdll.dll"));
		__NtResumeProcess pNtResumeProcess = (__NtResumeProcess)GetProcAddress(ntdll, "NtResumeProcess");
		if (pNtResumeProcess) {
			HANDLE phd = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
			if (phd) {
				if (NT_SUCCESS(pNtResumeProcess(phd)))
					result = true;
				CloseHandle(phd);
			}
		}
		return result;
	}

	/*++
	Description:
		create process, WinExec analogous
	Arguments:
		craete pid
	Return:
		bool
	--*/
	bool PsCreateProcess(__in const tstring &Cmdline, DWORD& Pid, __in UINT cmdshow /*= SW_SHOW*/)
	{
		PROCESS_INFORMATION pi = { 0 };
		STARTUPINFO si = { 0 };
		si.dwFlags = STARTF_USESHOWWINDOW;
		si.wShowWindow = (WORD)cmdshow;
		si.cb = sizeof(STARTUPINFO);
		if (!CreateProcess(NULL, (LPTSTR)Cmdline.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
			return false;
		}
		Pid = pi.dwProcessId;
		if (pi.hProcess) {
			CloseHandle(pi.hProcess);
		}
		if (pi.hThread) {
			CloseHandle(pi.hThread);
		}
		return true;
	}

	/*++
	Description:
		create process, WinExec analogous
	Arguments:
		cmdline - process path or command line
		cmdshow - show type
		proc_info - process information
	Return:
		bool
	--*/
	bool PsCreateProcess(__in const tstring &Cmdline, __in LPCTSTR CurrentDirectory, __in UINT cmdshow /*= SW_SHOW*/, __out PROCESS_INFORMATION *proc_info /*= NULL*/)
	{
		PROCESS_INFORMATION pi = { 0 };
		STARTUPINFO si = { 0 };
		si.dwFlags = STARTF_USESHOWWINDOW;
		si.wShowWindow = (WORD)cmdshow;
		si.cb = sizeof(STARTUPINFO);
		if (!proc_info)
			proc_info = &pi;
		if (!CreateProcess(NULL, (LPTSTR)Cmdline.c_str(), NULL, NULL, FALSE, 0, NULL, CurrentDirectory, &si, proc_info))
			return false;
		if (pi.hProcess)
			CloseHandle(pi.hProcess);
		if (pi.hThread)
			CloseHandle(pi.hThread);
		return true;
	}

	bool PsCreateProcessByShell(const tstring& FilePath, DWORD& ProcessId, __in LPCTSTR lpParameters, __in LPCTSTR lpDirectory, __in UINT cmdshow)
	{
		SHELLEXECUTEINFO sei;
		ZeroMemory(&sei, sizeof(SHELLEXECUTEINFO));
		sei.cbSize = sizeof(SHELLEXECUTEINFO);
		sei.lpFile = FilePath.c_str();
		sei.lpParameters = lpParameters;
		sei.lpDirectory = lpDirectory;
		sei.nShow = cmdshow;
		sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
		sei.lpVerb = _T("open");
		if (ShellExecuteEx(&sei))
		{
			HANDLE hProcess = sei.hProcess;
			if (WinLib::OsIs64() && !WinLib::PsIsWow64(hProcess))
			{
				PROCESS_BASIC_INFORMATION64 Pbi64;
				if (WinLib::PsGetPbi64(hProcess, Pbi64)) {
					ProcessId = (DWORD)Pbi64.UniqueProcessId;
				}
			}
			else
			{
				PROCESS_BASIC_INFORMATION32 Pbi32;
				if (WinLib::PsGetPbi32(hProcess, Pbi32)) {
					ProcessId = (DWORD)Pbi32.UniqueProcessId;
				}
			}
			return true;
		}
		return false;
	}

	bool PsCreateProcessByOther(tstring Cmdline, DWORD OtherPid, DWORD& NewPid, DWORD dwCreationFlags)
	{
		bool ret = false;
		CHAR* pBuf = NULL;
		HANDLE hProcess = NULL;

		do
		{
			hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, OtherPid);
			if (!hProcess) {
				break;
			}

			STARTUPINFOEX si = { 0 };
			si.StartupInfo.cb = sizeof(si);
			SIZE_T lpsize = 0;
			if (!::InitializeProcThreadAttributeList(NULL, 1, 0, &lpsize)
				&& ::GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			{
				break;
			}

			CHAR* pBuf = new (std::nothrow) char[lpsize];
			if (!pBuf) {
				break;
			}

			LPPROC_THREAD_ATTRIBUTE_LIST AttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)pBuf;
			if (!::InitializeProcThreadAttributeList(AttributeList, 1, 0, &lpsize)) {
				break;
			}

			if (::UpdateProcThreadAttribute(AttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hProcess, sizeof(HANDLE), NULL, NULL))
			{
				si.lpAttributeList = AttributeList;
				PROCESS_INFORMATION pi = { 0 };
				if (::CreateProcessAsUser(NULL, 0, (LPWSTR)Cmdline.c_str(), 0, 0, 0, dwCreationFlags | EXTENDED_STARTUPINFO_PRESENT, 0, 0, (LPSTARTUPINFO)&si, &pi))
				{
					ret = true;
					NewPid = pi.dwProcessId;
					::CloseHandle(pi.hProcess);
					::CloseHandle(pi.hThread);
				}
			}
			::DeleteProcThreadAttributeList(AttributeList);
		} while (false);

		if (pBuf) {
			delete[] pBuf;
		}
		if (hProcess) {
			::CloseHandle(hProcess);
		}
		return ret;
	}

	/*++
	Description:
		kill process
	Arguments:
		pid - process id
	Return:
		bool
	--*/
	bool PsTerminate(DWORD Pid)
	{
		bool result = false;
		HANDLE Process = OpenProcess(PROCESS_TERMINATE, FALSE, Pid);
		if (Process) {
			if (TerminateProcess(Process, 0))
				result = true;
			CloseHandle(Process);
		}
		return result;
	}

	bool PsTerminateProcessByName(const tstring& Name)
	{
		std::vector<DWORD> Pids;
		if (!WinLib::PsFindProcessByName(Name, Pids)) {
			return false;
		}
		for (auto iter2 = Pids.begin(); iter2 != Pids.end(); iter2++) {
			WinLib::PsTerminate(*iter2);
		}
		return true;
	}


	/*++
	Description:
		get process base information
		32bit->32bit OK.
		32bit->64bit OK.
		64bit->32bit OK.
		64bit->64bit OK.
	Arguments:
		pid - process id
		info - base information
	Return:
		bool
	--*/
	bool PsGetProcessInfo(DWORD Pid, PROCESS_BASE_INFO& Info)
	{
		if (PsIsX64(Pid))
			return PsGetProcessInfo64(Pid, Info);
		else
			return PsGetProcessInfo32(Pid, Info);
	}

	/*++
	Description:
		create remote thread for 32-bits process
	Arguments:
		phd - process handle
		routine - thread procedure
		param - thread parameter
		flags - create flags
	Return:
		thread handle
	--*/
	HANDLE PsCreateRemoteThread32(__in HANDLE phd, __in ULONG32 routine, __in ULONG32 param, __in DWORD flags)
	{
		HANDLE thd = NULL;
		BOOLEAN suspended = flags & CREATE_SUSPENDED;

		DWORD MajorVer = 0, MinorVer = 0, BuildNumber = 0;
		OsVersionNumber(MajorVer, MinorVer, BuildNumber);
		if (MajorVer >= 6) {
			auto pRtlCreateUserThread = (__RtlCreateUserThread)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "RtlCreateUserThread");
			if (pRtlCreateUserThread == NULL) return NULL;
			NTSTATUS status = pRtlCreateUserThread(phd, NULL, suspended, 0, 0, 0, (PVOID)routine, (PVOID)param, &thd, NULL);
			if (!NT_SUCCESS(status)) {
				return NULL;
			}
		}
		else {
			thd = CreateRemoteThread(phd, NULL, 0, (LPTHREAD_START_ROUTINE)routine, (PVOID)param, flags, NULL);
			if (thd == NULL) {
				return NULL;
			}
		}
		return thd;
	}

	/*++
	Description:
		create remote thread for 64-bits process
	Arguments:
		phd - process handle
		routine - thread procedure
		param - thread parameter
		flags - create flags
	Return:
		thread handle
	--*/
	HANDLE PsCreateRemoteThread64(__in HANDLE phd, __in ULONG64 routine, __in ULONG64 param, __in DWORD flags)
	{
		NTSTATUS status;
		DWORD64 thd = NULL;
		BOOLEAN suspended = flags & CREATE_SUSPENDED;
#ifdef _AMD64_
		auto pRtlCreateUserThread = (__RtlCreateUserThread)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserThread");
		if (!pRtlCreateUserThread) return NULL;
		status = pRtlCreateUserThread(phd, NULL, suspended, (ULONG)0, (SIZE_T)0, (SIZE_T)0, (PVOID)routine, (PVOID)param, (PHANDLE)&thd, NULL);
#else
		auto pRtlCreateUserThread = GetProcAddress64(GetModuleHandle64(L"ntdll.dll"), "RtlCreateUserThread");
		if (!pRtlCreateUserThread) return NULL;
		status = (NTSTATUS)X64Call(pRtlCreateUserThread, 10,
			(DWORD64)phd,
			(DWORD64)NULL,
			(DWORD64)suspended,
			(DWORD64)0,
			(DWORD64)0,
			(DWORD64)0,
			(DWORD64)routine,
			(DWORD64)param,
			(DWORD64)&thd,
			(DWORD64)NULL);
#endif
		if (!NT_SUCCESS(status)) {
			return NULL;
		}
		return (HANDLE)thd;
	}

	/*++
	Description:
		create remote thread for 64-bits process
	Arguments:
		phd - process handle
		routine - thread procedure
		param - thread parameter
		flags - create flags
	Return:
		thread handle
	--*/
	HANDLE PsCreateRemoteThread64(__in DWORD pid, __in ULONG64 routine, __in ULONG64 param, __in DWORD flags)
	{
		HANDLE thd = NULL;
		HANDLE phd = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
		if (!phd) {
			return NULL;
		}
		thd = PsCreateRemoteThread64(phd, (ULONG64)routine, (ULONG64)param, flags);
		CloseHandle(phd);
		return thd;
	}

	/*++
	Description:
		create remote thread for 32-bits process
	Arguments:
		phd - process handle
		routine - thread procedure
		param - thread parameter
		flags - create flags
	Return:
		thread handle
	--*/
	HANDLE PsCreateRemoteThread32(__in DWORD pid, __in ULONG routine, __in ULONG param, __in DWORD flags)
	{
		HANDLE thd = NULL;
		HANDLE phd = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
		if (!phd) {
			return NULL;
		}
		thd = PsCreateRemoteThread32(phd, (ULONG32)routine, (ULONG32)param, flags);
		CloseHandle(phd);
		return thd;
	}

	/*++
	Description:
		enable privilege
	Arguments:
		PrivName - privilege name
		IsEnable - enable or disable
	Return:
		bool
	--*/
	bool PsSetPrivilege(const tstring& PrivName, bool IsEnable)
	{
		bool Result = false;
		if (PrivName.empty()) {
			return false;
		}

		do {
			HANDLE Token = NULL;
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token)) {
				break;
			}

			LUID DebugNameValue;
			if (!LookupPrivilegeValue(NULL, PrivName.c_str(), &DebugNameValue)) {
				CloseHandle(Token);
				break;
			}

			TOKEN_PRIVILEGES Tp;
			Tp.PrivilegeCount = 1;
			Tp.Privileges[0].Luid = DebugNameValue;
			if (IsEnable)
				Tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			else
				Tp.Privileges[0].Attributes = 0;
			if (!AdjustTokenPrivileges(Token, FALSE, &Tp, sizeof(Tp), NULL, NULL) ||
				GetLastError() != ERROR_SUCCESS)
			{
				CloseHandle(Token);
				break;
			}
			Result = true;
		} while (0);

		return Result;
	}


	/*++
	Description:
		read process (32-bit) memory, whichever arch(32/64) the caller is
	Arguments:
		map_buff - file path
		fd - file size
		hmap - file handle
		hmap - mapped handle
	Return:
		bool
	--*/
	bool PsReadProcessMemory32(__in DWORD pid, __in ULONG addr, __inout PVOID buff, __in ULONG size, __out PULONG readlen)
	{
		NTSTATUS result;
		HANDLE phd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (!phd) {
			return false;
		}
		HMODULE ntdll = GetModuleHandle(_T("ntdll.dll"));
		__NtReadVirtualMemory pNtReadVirtualMemory = (__NtReadVirtualMemory)GetProcAddress(ntdll, "NtReadVirtualMemory");
		result = pNtReadVirtualMemory(phd, (PVOID)addr, buff, (SIZE_T)size, (SIZE_T*)readlen);
		CloseHandle(phd);
		return NT_SUCCESS(result);
	}

	/*++
	Description:
		read process (64-bit) memory, whichever arch(32/64) the caller is
	Arguments:
		map_buff - file path
		fd - file size
		hmap - file handle
		hmap - mapped handle
	Return:
		bool
	--*/
	bool PsReadProcessMemory64(__in DWORD pid, __in ULONG64 addr, __inout PVOID buff, __in ULONG size, __out PULONG64 readlen)
	{
		NTSTATUS result;
		HANDLE phd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (!phd) {
			return false;
		}
		HMODULE ntdll = GetModuleHandle(_T("ntdll.dll"));
#ifdef _AMD64_
		__NtReadVirtualMemory pNtReadVirtualMemory = (__NtReadVirtualMemory)
			GetProcAddress(ntdll, "NtReadVirtualMemory");
#else
		__NtWow64ReadVirtualMemory64 pNtReadVirtualMemory = (__NtWow64ReadVirtualMemory64)
			GetProcAddress(ntdll, "NtWow64ReadVirtualMemory64");
#endif
		if (!pNtReadVirtualMemory) {
			CloseHandle(phd);
			return false;
		}
		result = pNtReadVirtualMemory(phd, (PVOID64)addr, buff, (SIZE_T)size, readlen);
		CloseHandle(phd);
		return NT_SUCCESS(result);
	}

	/*++
	Description:
		read process (64-bit) memory, whichever arch(32/64) the caller is
	Arguments:
		map_buff - file path
		fd - file size
		hmap - file handle
		hmap - mapped handle
	Return:
		bool
	--*/
	bool PsGetProcessMemoryInfo(__in DWORD pid, __inout PROCESS_MEMORY_COUNTERS_EX& mm_info)
	{
		bool result = false;
		HANDLE phd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (!phd) {
			return FALSE;
		}
		if (GetProcessMemoryInfo(phd, (PPROCESS_MEMORY_COUNTERS)&mm_info, sizeof(mm_info))) {
			result = true;
		}
		CloseHandle(phd);
		return result;
	}

	bool PsGetProcessHandles(DWORD Pid, std::vector<HANDLE>& Handles, USHORT ObjectTypeIndex)
	{
		auto NtQuerySystemInformationPtr = (__NtQuerySystemInformation)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtQuerySystemInformation");
		if (NtQuerySystemInformationPtr == NULL) {
			return false;
		}

		bool ret = false;
		PSYSTEM_HANDLE_INFORMATION pInfo = NULL;
		ULONG BufferSize = 0;
		while (true)
		{
			BufferSize += 0x10000;
			pInfo = (PSYSTEM_HANDLE_INFORMATION)new(std::nothrow) UCHAR[BufferSize];
			if (!pInfo) {
				break;
			}

			NTSTATUS Status = NtQuerySystemInformationPtr(SystemHandleInformation, pInfo, BufferSize, &BufferSize);
			if (NT_SUCCESS(Status))
			{
				for (ULONG i = 0; i < pInfo->NumberOfHandles; i++)
				{
					auto& Block = pInfo->Handles[i];
					if (Pid != (DWORD)Block.UniqueProcessId) {
						continue;
					}

					if (ObjectTypeIndex != Block.ObjectTypeIndex)
					{
						continue;
					}

					Handles.push_back((HANDLE)Block.HandleValue);
				}
				ret = true;
				break;
			}
			else if (Status == STATUS_INFO_LENGTH_MISMATCH)
			{
				delete pInfo;
			}
			else
			{
				break;
			}
		}

		if (pInfo) {
			delete pInfo;
		}
		return ret;
	}

	tstring PsGetModuleFileName(HMODULE module)
	{
		TCHAR TmpFilename[MAX_PATH + 1] = { 0 };
		if (!GetModuleFileName(module, TmpFilename, MAX_PATH)) {
			return _T("");
		}
		return TmpFilename;
	}

	bool PsSetProcessCommandLine32(DWORD pid, const std::wstring& CommandLine)
	{
		auto read_routine = (__NtReadVirtualMemory)GetReadRoutine32();
		if (!read_routine) return false;

		auto write_routine = (__NtWriteVirtualMemory)GetWriteRoutine32();
		if (!write_routine) return false;

		NTSTATUS status = STATUS_SUCCESS;
		HANDLE phd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
		if (!phd) {
			return false;
		}
		do {
			PVOID peb_addr = WinLib::PsGetPebAddress32(phd);
			if (!peb_addr) break;

			PEB32 peb;
			SIZE_T readlen;
			status = read_routine(phd, peb_addr, &peb, sizeof(peb), &readlen);
			if (!NT_SUCCESS(status)) break;

			RTL_USER_PROCESS_PARAMETERS32 params;
			status = read_routine(phd, (PVOID)peb.ProcessParameters, &params, sizeof(params), &readlen);
			if (!NT_SUCCESS(status)) break;

			if (!WriteUnicodeString32(phd, CommandLine, &params.CommandLine, write_routine)) break;
		} while (0);

		CloseHandle(phd);
		if (!NT_SUCCESS(status)) {
			return false;
		}
		return true;
	}

	bool PsSetProcessCommandLine64(DWORD pid, const std::wstring& CommandLine)
	{
#ifdef _M_IX86
		auto read_routine = (__NtWow64ReadVirtualMemory64)GetReadRoutine64();
#else
		auto read_routine = (__NtReadVirtualMemory)GetReadRoutine64();
#endif

#ifdef _M_IX86
		auto write_routine = (__NtWow64WriteVirtualMemory64)GetWriteRoutine64();
#else
		auto write_routine = (__NtWriteVirtualMemory)GetWriteRoutine64();
#endif
		if (!read_routine || !write_routine) return false;

		NTSTATUS status = STATUS_SUCCESS;
		HANDLE phd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
		if (!phd) {
			return false;
		}
		do {
			PVOID64 peb_addr = WinLib::PsGetPebAddress64(phd);
			if (!peb_addr) break;

			PEB64 peb;
			ULONG64 readlen;
			status = read_routine(phd, peb_addr, &peb, sizeof(peb), &readlen);
			if (!NT_SUCCESS(status)) break;

			RTL_USER_PROCESS_PARAMETERS64 params;
			status = read_routine(phd, (PVOID64)peb.ProcessParameters, &params, sizeof(params), &readlen);
			if (!NT_SUCCESS(status)) break;

			if (!WriteUnicodeString64(phd, CommandLine, &params.CommandLine, write_routine)) break;
		} while (0);

		::CloseHandle(phd);
		if (!NT_SUCCESS(status)) {
			return false;
		}
		return true;
	}

	bool PsSetProcessCommandLine(DWORD Pid, const std::wstring& CommandLine)
	{
		if (PsIsX64(Pid))
			return PsSetProcessCommandLine64(Pid, CommandLine);
		else
			return PsSetProcessCommandLine32(Pid, CommandLine);
	}

	bool PsSetProcessImagePathName32(DWORD pid, const std::wstring& ImagePathName)
	{
		auto read_routine = (__NtReadVirtualMemory)GetReadRoutine32();
		if (!read_routine) return false;

		auto write_routine = (__NtWriteVirtualMemory)GetWriteRoutine32();
		if (!write_routine) return false;

		NTSTATUS status = STATUS_SUCCESS;
		HANDLE phd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
		if (!phd) {
			return false;
		}
		do {
			PVOID peb_addr = WinLib::PsGetPebAddress32(phd);
			if (!peb_addr) break;

			PEB32 peb;
			SIZE_T readlen;
			status = read_routine(phd, peb_addr, &peb, sizeof(peb), &readlen);
			if (!NT_SUCCESS(status)) break;

			RTL_USER_PROCESS_PARAMETERS32 params;
			status = read_routine(phd, (PVOID)peb.ProcessParameters, &params, sizeof(params), &readlen);
			if (!NT_SUCCESS(status)) break;

			if (!WriteUnicodeString32(phd, ImagePathName, &params.ImagePathName, write_routine)) break;
		} while (0);

		CloseHandle(phd);
		if (!NT_SUCCESS(status)) {
			return false;
		}
		return true;
	}

	bool PsSetProcessImagePathName64(DWORD pid, const std::wstring& ImagePathName)
	{
#ifdef _M_IX86
		auto read_routine = (__NtWow64ReadVirtualMemory64)GetReadRoutine64();
#else
		auto read_routine = (__NtReadVirtualMemory)GetReadRoutine64();
#endif

#ifdef _M_IX86
		auto write_routine = (__NtWow64WriteVirtualMemory64)GetWriteRoutine64();
#else
		auto write_routine = (__NtWriteVirtualMemory)GetWriteRoutine64();
#endif
		if (!read_routine) return false;

		NTSTATUS status = STATUS_SUCCESS;
		HANDLE phd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
		if (!phd) {
			return false;
		}
		do {
			PVOID64 peb_addr = WinLib::PsGetPebAddress64(phd);
			if (!peb_addr) break;

			PEB64 peb;
			ULONG64 readlen;
			status = read_routine(phd, peb_addr, &peb, sizeof(peb), &readlen);
			if (!NT_SUCCESS(status)) break;

			RTL_USER_PROCESS_PARAMETERS64 params;
			status = read_routine(phd, (PVOID64)peb.ProcessParameters, &params, sizeof(params), &readlen);
			if (!NT_SUCCESS(status)) break;

			if (!WriteUnicodeString64(phd, ImagePathName, &params.ImagePathName, write_routine)) break;
		} while (0);

		::CloseHandle(phd);
		if (!NT_SUCCESS(status)) {
			return false;
		}
		return true;
	}

	bool PsSetProcessImagePathName(DWORD Pid, const std::wstring& CommandLine)
	{
		if (PsIsX64(Pid))
			return PsSetProcessImagePathName64(Pid, CommandLine);
		else
			return PsSetProcessImagePathName32(Pid, CommandLine);
	}

	bool PsGetProcessImageBaseAddress32(DWORD pid, ULONG& ImageBaseAddress)
	{
		auto read_routine = (__NtReadVirtualMemory)GetReadRoutine32();
		if (!read_routine) return false;

		auto write_routine = (__NtWriteVirtualMemory)GetWriteRoutine32();
		if (!write_routine) return false;

		NTSTATUS status = STATUS_SUCCESS;
		HANDLE phd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (!phd) {
			return false;
		}
		do {
			PVOID peb_addr = WinLib::PsGetPebAddress32(phd);
			if (!peb_addr) break;

			PEB32 peb;
			SIZE_T readlen;
			status = read_routine(phd, peb_addr, &peb, sizeof(peb), &readlen);
			if (!NT_SUCCESS(status)) break;

			ImageBaseAddress = peb.ImageBaseAddress;
		} while (0);

		CloseHandle(phd);
		if (!NT_SUCCESS(status)) {
			return false;
		}
		return true;
	}

	bool PsGetProcessImageBaseAddress64(DWORD pid, ULONG64& ImageBaseAddress)
	{
#ifdef _M_IX86
		auto read_routine = (__NtWow64ReadVirtualMemory64)GetReadRoutine64();
#else
		auto read_routine = (__NtReadVirtualMemory)GetReadRoutine64();
#endif
		if (!read_routine) return false;

		NTSTATUS status = STATUS_SUCCESS;
		HANDLE phd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (!phd) {
			return false;
		}
		do {
			PVOID64 peb_addr = WinLib::PsGetPebAddress64(phd);
			if (!peb_addr) break;

			PEB64 peb;
			ULONG64 readlen;
			status = read_routine(phd, peb_addr, &peb, sizeof(peb), &readlen);
			if (!NT_SUCCESS(status)) break;

			ImageBaseAddress = peb.ImageBaseAddress;

		} while (0);

		::CloseHandle(phd);
		if (!NT_SUCCESS(status)) {
			return false;
		}
		return true;
	}

	bool PsWriteProcessMemory32(__in DWORD pid, __in ULONG addr, __inout PVOID buff, __in ULONG size, __out SIZE_T* writelen)
	{
		auto write_routine = (__NtWriteVirtualMemory)GetWriteRoutine32();
		if (!write_routine) return false;

		NTSTATUS result;
		HANDLE phd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE, FALSE, pid);
		if (!phd) {
			return false;
		}

		result = write_routine(phd, (PVOID)addr, buff, size, (SIZE_T*)writelen);
		CloseHandle(phd);
		return NT_SUCCESS(result);
	}

	bool PsWriteProcessMemory64(__in DWORD pid, __in ULONG64 addr, __inout PVOID buff, __in ULONG size, __out PULONG64 readlen)
	{
#ifdef _M_IX86
		auto write_routine = (__NtWow64WriteVirtualMemory64)GetWriteRoutine64();
#else
		auto write_routine = (__NtWriteVirtualMemory)GetWriteRoutine64();
#endif
		if (!write_routine) return false;

		NTSTATUS result;
		HANDLE phd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE, FALSE, pid);
		if (!phd) {
			return false;
		}

		result = write_routine(phd, (PVOID64)addr, buff, (SIZE_T)size, readlen);
		CloseHandle(phd);
		return NT_SUCCESS(result);
	}
}