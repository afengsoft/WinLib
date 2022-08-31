/************************************************************************/
/*
/*				Programming Applications Library For Windows
/*				Light Version
/*
/************************************************************************/
#pragma once
#include <Windows.h>
#ifndef PSAPI_VERSION
#define PSAPI_VERSION 1
#endif
#include <Tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <map>
#include <set>
#include <string>
#include <tchar.h>

namespace WinLib
{
	typedef std::basic_string<TCHAR> tstring;

	typedef struct _PROCESS_BASE_INFO
	{
		tstring ImagePathName;
		tstring CommandLine;
		tstring WindowTitle;
		tstring CurrentDirectory;
	} PROCESS_BASE_INFO, *PPROCESS_BASE_INFO;

	typedef struct _MODULE_BASE_INFO32 {
		ULONG DllBase;
		ULONG EntryPoint;
		ULONG SizeOfImage;
		tstring FullDllName;
		tstring BaseDllName;
		DWORD Flags;
		WORD LoadCount;
		DWORD TimeDateStamp;
	} MODULE_BASE_INFO32, *PMODULE_BASE_INFO32;

	typedef struct _MODULE_BASE_INFO64 {
		ULONG64	DllBase;
		ULONG64 EntryPoint;
		ULONG SizeOfImage;
		tstring FullDllName;
		tstring BaseDllName;
		DWORD Flags;
		WORD LoadCount;
		DWORD TimeDateStamp;
	} MODULE_BASE_INFO64, *PMODULE_BASE_INFO64;

	typedef struct _PROCESS_BASIC_INFORMATION32 {
		NTSTATUS ExitStatus;
		ULONG PebBaseAddress;
		ULONG AffinityMask;
		LONG BasePriority;
		ULONG UniqueProcessId;
		ULONG InheritedFromUniqueProcessId;
	} PROCESS_BASIC_INFORMATION32;

	typedef struct _PROCESS_BASIC_INFORMATION64
	{
		NTSTATUS ExitStatus;
		ULONG Pad1;
		ULONG64 PebBaseAddress;
		ULONG64 AffinityMask;
		LONG BasePriority;
		ULONG Pad2;
		ULONG64 UniqueProcessId;
		ULONG64 InheritedFromUniqueProcessId;
	} PROCESS_BASIC_INFORMATION64, *PPROCESS_BASIC_INFORMATION64;

	bool			PsIsWow64(HANDLE Process = GetCurrentProcess());
	bool			PsIsWow64(DWORD Pid);
	bool			PsIsX64(DWORD Pid);
	bool			PsThreadIsX64(DWORD Tid);
	bool			PsIsExisted(DWORD Pid);
	bool			PsIsNameExisted(const tstring &Name);
	tstring			PsGetProcessPath(DWORD Pid = GetCurrentProcessId());
	bool			PsFindProcessByName(const tstring& ProcessName, std::vector<DWORD>& Pids);
	tstring			PsGetModulePath(const tstring& ModuleName, HMODULE ModuleBase = NULL);
	DWORD			PsGetPidByWindow(const tstring& ClassName, const tstring& TitleName);
	DWORD			PsGetPidByTid(DWORD Tid);
	DWORD			PsGetParentPid(DWORD Pid);
	bool			PsGetChildPids(DWORD Pid, std::vector<DWORD>& ChildPids);
	bool			PsGetDescendantPids(DWORD Pid, std::vector<DWORD>& descendants);
	bool			PsEnumThreadId(DWORD Pid, std::vector<DWORD>& Tids);
	bool			PsEnumProcessId(std::vector<DWORD>& Pids);
	bool			PsEnumProcessId2(std::set<DWORD>& Pids);
	bool			PsEnumProcessNames(std::map<DWORD, tstring>& ProcNames);
	bool			PsEnumModule(DWORD Pid, std::vector<MODULEENTRY32>& Modules);
	bool			PsSuspendProcess(DWORD Pid);
	DWORD			PsSuspendThread(DWORD Tid);
	bool			PsResumeProcess(DWORD Pid);
	DWORD			PsResumeThread(DWORD Tid);
	bool			PsSuspendProcessByName(const tstring& Name);
	bool			PsResumeProcessByName(const tstring& Name);
	bool			PsCreateProcess(const tstring &Cmdline, DWORD& Pid, UINT CmdShow = SW_SHOW);
	bool			PsCreateProcess(const tstring& CmdLine, LPCTSTR CurrentDirectory = NULL, UINT CmdShow = SW_SHOW, PROCESS_INFORMATION* ProcessInfo = NULL);
	bool			PsCreateProcessByShell(const tstring& FilePath, DWORD& ProcessId, __in LPCTSTR lpParameters = NULL, __in LPCTSTR lpDirectory = NULL, __in UINT cmdshow = SW_SHOW);
	bool			PsCreateProcessByOther(tstring Cmdline, DWORD OtherPid, DWORD& NewPid, DWORD dwCreationFlags = 0);
	bool			PsTerminate(DWORD Pid);
	bool			PsTerminateProcessByName(const tstring& Name);
	bool			PsIsDeleted(DWORD pid);
	bool			PsGetPbi32(HANDLE phd, PROCESS_BASIC_INFORMATION32 &pbi32);
	bool			PsGetPbi64(HANDLE phd, PROCESS_BASIC_INFORMATION64 &pbi64);
	PVOID			PsGetPebAddress32(HANDLE phd);
	PVOID64			PsGetPebAddress64(HANDLE phd);
	bool			PsGetProcessInfo(DWORD Pid, PROCESS_BASE_INFO& Info);
	bool			PsGetModulesInfo32(DWORD Pid, std::vector<MODULE_BASE_INFO32>& Infos);
	bool			PsGetModulesInfo64(DWORD Pid, std::vector<MODULE_BASE_INFO64>& Infos);
	bool			PsGetThreadEntryAddress32(DWORD Tid, ULONG& EntryAddress);
	bool			PsGetThreadEntryAddress64(DWORD Tid, ULONG64& EntryAddress);
	HANDLE			PsCreateRemoteThread32(DWORD Pid, ULONG StartAddress, ULONG Parameter, DWORD CreationFlags = 0);
	HANDLE			PsCreateRemoteThread64(DWORD Pid, ULONG64 StartAddress, ULONG64 Parameter, DWORD CreationFlags = 0);
	bool			PsSetPrivilege(const tstring& PrivName = SE_DEBUG_NAME, bool IsEnable = true);
	bool			PsReadProcessMemory32(DWORD Pid, ULONG Address, PVOID Buffer, ULONG Size, PULONG BytesRead);
	bool			PsReadProcessMemory64(DWORD Pid, ULONG64 Address, PVOID Buffer, ULONG Size, PULONG64 BytesRead);
	bool			PsWriteProcessMemory32(DWORD pid, ULONG addr, PVOID buff, ULONG size, SIZE_T* writelen);
	bool			PsWriteProcessMemory64(DWORD pid, ULONG64 addr, PVOID buff, ULONG size, PULONG64 readlen);
	bool			PsGetProcessMemoryInfo(DWORD Pid, PROCESS_MEMORY_COUNTERS_EX& MemoryInfo);
	bool			PsGetProcessHandles(DWORD Pid, std::vector<HANDLE>& Handles, USHORT ObjectTypeIndex);
	tstring			PsGetModuleFileName(HMODULE module = NULL);
	bool			PsSetProcessCommandLine(DWORD pid, const std::wstring& CommandLine);
	bool			PsSetProcessImagePathName(DWORD pid, const std::wstring& CommandLine);
	bool			PsGetProcessImageBaseAddress32(DWORD pid, ULONG& ImageBaseAddress);
	bool			PsGetProcessImageBaseAddress64(DWORD pid, ULONG64& ImageBaseAddress);
}