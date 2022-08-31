# WinLib
Windows Api Enclosing C++ Library
Windows Api 封装 C++ 库

#include "WinLibOs.h"
	bool			 OsIs64();
	bool			 OsVersionNumber(DWORD& MajorVer, DWORD& MinorVer, DWORD& BuildNumber);
	tstring		 OsPcName();
	tstring		 OsCurrentUserName();
	tstring		 OsSessionUserName(DWORD SessionId = WTS_CURRENT_SESSION);
	DWORD			 OsGetCPUCount();
	DWORD			 OsGetMemoryMb();
	void			 OsGetScreenResolution(int& Width, int& Height);
	bool			 OsIsVM();
	tstring		 OsDrive();
	tstring		 OsGetWindowsDirectory();
	bool			 OsEnumLogicalDriveName(std::vector<tstring>& LogicalDriveNames);
	bool			 OsDisableFileRedirection(PVOID& OldValue);
	bool			 OsEnableFileRedirection(PVOID& OldValue);
	DWORD			 OsGetUserSid(const tstring& UserName, PSID* Sid);
	bool			 OsGetUserStringSid(const tstring& UserName, tstring& StringSid);
  
#include "WinLibSe.h"
	bool			SeTakeFileOwnership(const tstring& UserName, const tstring& FilePath);
	bool			SeSetFileAllowAccess(const tstring& UserName, const tstring& FilePath, DWORD DesiredAccess = GENERIC_ALL, bool DelAllAccess = false);
	bool			SeSetFileDenyAccess(const tstring& UserName, const tstring& FilePath, DWORD DesiredAccess = GENERIC_ALL, bool DelAllAccess = false);

#include "WinLibMm.h"
  bool			MmReleaseResource(HMODULE hModule, WORD wResourceID, LPCTSTR lpType, const tstring& strFileName);
	bool			MmReleaseResource(HMODULE hModule, WORD wResourceID, LPCTSTR lpType, std::string& ResourceData);
	CHAR*			MmCreateFileMapping(const tstring& Name, DWORD Size, HANDLE& hFileMap, bool LowSecutity = true);
	CHAR* 		MmOpenFileMapping(const tstring& Name, HANDLE& hFileMap);
	bool 			MmForceWriteMemcpy(void* dst, void* src, int size);
  
#include "WinLibNet.h"
  bool 			NetGetAdapterInfos(std::vector<ADAPTER_INFO>& Adapters);
	ULONG 			NetGetHostByName(const std::string& Host);
	tstring 		NetIpToStr(UINT32 Ip);
	ULONG 			NetStrToIp(const tstring& IpStr);
	bool 			NetGetDnsQuery(const tstring Dns, std::map<ULONG, tstring>& DnsInfo);
	tstring 		NetGetMac();
	UINT32 			NetGetIp();
	tstring 		NetGetRouteIP();
	tstring 		NetGetRouterMac();
	bool 			NetStartSocket(WORD Version = MAKEWORD(2, 2));
	bool 			NetCleanSocket();
	bool 			NetGetaddrinfo(const std::string& Domain, std::vector<UINT32>& IpList);
	bool 			NetSendUdp(const char* pBuf, int iLen, UINT32 Ip, USHORT iPort);
  
#include "WinLibStr.h"
  std::string		StrToString(const std::wstring& Str);
	std::wstring	StrToWstring(const std::string& Str);
	std::wstring	StrUTF8ToWide(const std::string& Str);
	std::string		StrWideToUTF8(const std::wstring& Str);
	tstring			StrToLower(const tstring& Str);
	tstring			StrToUpper(const tstring& Str);
	UINT			StrToHex(const tstring& Str);
	UINT			StrToDecimal(const tstring& Str);
	UINT64			StrToDecimal64(const tstring& Str);
	UINT			StrToBinary(const tstring& Str);
	std::string		StrStreamToHexStr(const std::string& Stream);
	std::string		StrHexStrToStream(const std::string& inhexstr);
	bool			StrFind(const tstring& Str, const tstring& SubStr, bool CaseInsensitive = false);
	bool			StrFind(const tstring& Str1, const std::vector<tstring>& Str2, bool CaseInsensitive = false);
	bool			StrFindA(const std::string& Str, const std::string& SubStr, bool CaseInsensitive = false);
	bool			StrCompare(const tstring& Str1, const tstring& Str2, bool CaseInsensitive = false);
	bool			StrCompare(const tstring& Str1, const std::vector<tstring>& Str2, bool CaseInsensitive = false);
	bool			StrCompareA(const std::string& Str1, const std::string& Str2, bool CaseInsensitive = false);
	bool			StrSplit(tstring Str, const tstring& Sep, std::vector<tstring>& Vec);
	bool			StrSplitA(const std::string& Str, const std::string& Sep, std::vector<std::string>& Vec);
	bool			StrSplitLines(const tstring& Str, std::vector<tstring>& Lines);
	bool			StrSplitLinesA(const std::string& str, std::vector<std::string>& lines);
	tstring			StrReplace(const tstring& Source, const tstring& Pattern, const tstring& Replaced = _T(""));
	std::string		StrReplaceA(const std::string& source, const std::string& pattern, const std::string& replaced = "");
	tstring			StrPathToName(const tstring& Path);
	tstring			StrPathToDir(const tstring& Path);
	tstring			StrNameToExt(const tstring& Name);
	tstring			StrNameWithoutExt(const tstring& Name);
	UINT64			StrVersionToNumber(const tstring& VersionStr);
	tstring			StrNumberToVersion(LONGLONG version);
	tstring			StrErrorMsg(DWORD Error);
	DWORD			StrNtToDosError(LONG Status);
	tstring			StrFormat(const TCHAR* formats, ...);
	tstring			StrFormatVaList(const TCHAR* formats, va_list lst);
	std::string		StrFormatA(const char* formats, ...);
	std::string		StrFormatVaListA(const char* formats, va_list lst);
	bool			StrParseCmdline(const tstring& Cmdline, std::vector<tstring>& Argv);
	bool			StrJoinCmdline(const std::vector<tstring>& Argv, tstring& Cmdline);
	std::wstring	StrUnicodeToWstr(void* Ustr);
	std::string		StrUrlEncode(const std::string& Url);
	std::string		StrUrlDecode(const std::string& Url);
	tstring			StrRandString(int Count, const tstring& Charset);
	int				StrRandInteger(int min, int max);
	tstring			StrDosToNtPath(const tstring& DosPath);
	tstring			StrNtToDosPath(const tstring& NtPath);
  
#include "WinLibPs.h"
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
