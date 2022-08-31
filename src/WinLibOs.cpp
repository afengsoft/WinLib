#include "WinLibOs.h"
//Windows SDK
#include <Sddl.h>
//C++ Standard Library
#include <memory>
//Other
#include "WinLibStr.h"

#pragma comment(lib,"UserEnv.lib")
#pragma comment(lib,"Wtsapi32.lib")

namespace WinLib
{
/*++
Description:
	check os is x64/amd64.
Arguments:
	void
Return:
	true - x64/amd64
	false - non x64/amd64
--*/
bool OsIs64()
{
	SYSTEM_INFO si = {0};
	::GetNativeSystemInfo(&si);
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
		return true;
	}
	return false;
}

/*++
Description:
	get major version number of os, works from xp to win11.
	in compatible mode, still return real version.
Arguments:
	MajorVer
	MinorVer
	BuildNumber
Return:
	bool
--*/
bool OsVersionNumber(DWORD& MajorVer, DWORD& MinorVer, DWORD& BuildNumber)
{
	typedef VOID(NTAPI* __RtlGetNtVersionNumbers)(
		OUT PULONG MajorVer,
		OUT PULONG MinorVer,
		OUT PULONG BuildNumber
		);

	__RtlGetNtVersionNumbers pRtlGetNtVersionNumbers = 
		(__RtlGetNtVersionNumbers)::GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "RtlGetNtVersionNumbers");
	if (pRtlGetNtVersionNumbers) 
	{
		pRtlGetNtVersionNumbers(&MajorVer, &MinorVer, &BuildNumber);
		BuildNumber = BuildNumber ^ 0xF0000000;
		return true;
	}
	return false;
}

/*++
Routine Description:
	OsPcName
Arguments:
	void
Return Value:
	PcName
--*/
tstring OsPcName()
{
	DWORD size = 0;
	if (!::GetComputerNameEx(ComputerNameDnsHostname, NULL, &size) && GetLastError() == ERROR_MORE_DATA) 
	{
		tstring name;
		name.resize((size + 1) * sizeof(TCHAR));		
		if (::GetComputerNameEx(ComputerNameDnsHostname, (LPTSTR)name.c_str(), &size)) {
			return name;
		}
	}
	return _T("");
}

/*++
Description:
	get current user name
Arguments:
	void
Return:
	user name
--*/
tstring OsCurrentUserName()
{
	DWORD size = 0;
	if (!GetUserName(NULL, &size) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
		std::unique_ptr<TCHAR> name(new(std::nothrow) TCHAR[size + 1]);
		if (name)	{
			memset(name.get(), 0, size + 1);
			if (GetUserName(name.get(), &size))
				return name.get();
		}
	}
	return _T("");
}


/*++
Description:
	get session user name, WTS_CURRENT_SESSION is current
Arguments:
	session - session id
Return:
	session user name
--*/
tstring OsSessionUserName(__in DWORD id)
{
	LPTSTR temp_name = NULL;
	DWORD size = 0;
	tstring name;
	BOOL ret = WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, id, WTSUserName, &temp_name, &size);
	if (ret && temp_name != NULL) {
		name = temp_name;
		WTSFreeMemory(temp_name);
	}
	return name;
}

/*++
Routine Description:
	Count Of CPU
Arguments:
	void
Return Value:
	Count Of CPU
--*/
DWORD OsGetCPUCount()
{
	SYSTEM_INFO SystemInfo;
	::GetSystemInfo(&SystemInfo);
	return SystemInfo.dwNumberOfProcessors;
}

DWORD OsGetMemoryMb()
{
	MEMORYSTATUSEX statex;
	statex.dwLength = sizeof(statex);
	::GlobalMemoryStatusEx(&statex);
	return statex.ullTotalPhys / (1024 * 1024);
}

void OsGetScreenResolution(int& Width, int& Height)
{
	Width = ::GetSystemMetrics(SM_CXSCREEN);
	Height = ::GetSystemMetrics(SM_CYSCREEN);
}

/*++
Routine Description:
	get windows disk symbol
	like: 
	C:
Arguments:
	
Return Value:
	disk symbol
--*/
tstring OsDrive()
{
	TCHAR path[MAX_PATH + 1] = {0};
	ExpandEnvironmentStrings(_T("%SystemDrive%"), path, MAX_PATH);
	return path;
}

/*++
Description:
	get windows directory (WinDir/SystemRoot)
	like: 
	C:\Windows
Arguments:
	void
Return:
	directory
--*/
tstring OsGetWindowsDirectory()
{
	TCHAR windir[MAX_PATH + 1] = { 0 };
	::GetWindowsDirectory(windir, MAX_PATH);
	return windir;
}

/*++
Routine Description:
	Disable FileRedirection
Arguments:
	OldValue - OldValue
Return Value:
	bool 
--*/
bool OsDisableFileRedirection(PVOID& OldValue)
{
	typedef BOOL (WINAPI* DEF_Wow64DisableWow64FsRedirection)(PVOID* OldValue);
	HMODULE hKernel32 = GetModuleHandle(_T("kernel32.dll"));
	DEF_Wow64DisableWow64FsRedirection pfnWow64DisableWow64FsRedirection;
	if( (pfnWow64DisableWow64FsRedirection = (DEF_Wow64DisableWow64FsRedirection)
		GetProcAddress(hKernel32, "Wow64DisableWow64FsRedirection")) == NULL )
		return false;
	return pfnWow64DisableWow64FsRedirection(&OldValue)==TRUE;
}

/*++
Routine Description:
	Enable FileRedirection
Arguments:
	OldValue - OldValue
Return Value:
	bool 
--*/
bool OsEnableFileRedirection(PVOID& OldValue)
{
	typedef BOOL (WINAPI* DEF_Wow64RevertWow64FsRedirection)(PVOID OldValue);
	HMODULE hKernel32 = GetModuleHandle(_T("kernel32.dll"));
	DEF_Wow64RevertWow64FsRedirection pfnWow64RevertWow64FsRedirection;
	if( (pfnWow64RevertWow64FsRedirection = (DEF_Wow64RevertWow64FsRedirection)
		GetProcAddress(hKernel32, "Wow64RevertWow64FsRedirection")) == NULL )
		return false;
	return pfnWow64RevertWow64FsRedirection(OldValue)==TRUE;
}

/*++
Routine Description:
	get UserSid
Arguments:
	UserName - UserName
	StringSid - Sid
Return Value:
	failed - Other
	success - ERROR_SUCCESS
--*/
DWORD OsGetUserSid(const tstring& UserName, PSID* Sid)
{
	DWORD SidSize = 0, DomainSize = 0;
	LPTSTR Domain = NULL;
	SID_NAME_USE SidNameUse;
	DWORD Result = ERROR_SUCCESS;
	do
	{
		if (Sid == NULL)
		{
			Result = ERROR_INVALID_PARAMETER;
			break;
		}

		if (!LookupAccountName(NULL, UserName.c_str(), NULL, &SidSize, NULL, &DomainSize, NULL) && 
			GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			Result = GetLastError();
			break;
		}

		if (!(*Sid=(PSID)malloc(SidSize)) || !(Domain=(LPTSTR)malloc(DomainSize * sizeof(TCHAR))))
		{
			Result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}
	
		if (!LookupAccountName(NULL, UserName.c_str(), *Sid, &SidSize, Domain, &DomainSize, &SidNameUse))
		{
			Result = GetLastError();
			break;
		}
	} while (0);
	if (Domain)
		free(Domain);
	if (Result!=ERROR_SUCCESS && *Sid)
	{
		*Sid = NULL;
		free(Sid);
	}
	return Result;
}

/*++
Routine Description:
	get UserStringSid
	N.B.
	Administrator => S-1-5-21-3271787186-2771540736-500
Arguments:
	UserName - UserName
	StringSid - StringSid
Return Value:
	bool
--*/
bool OsGetUserStringSid(const tstring& UserName, tstring& StringSid)
{
	bool Result = false;
	PSID Sid = NULL;
	LPTSTR Str = NULL;
	if (OsGetUserSid(UserName, &Sid) == ERROR_SUCCESS)
	{
		if ((ConvertSidToStringSid(Sid, &Str)))
		{
			StringSid = Str;
			LocalFree(Str);
			Result = true;
		}
		free(Sid);
	}
	return Result;
}

bool OsEnumLogicalDriveName(std::vector<tstring>& LogicalDriveNames)
{
	TCHAR szTemp[MAX_PATH + 1] = { 0 };
	if (!::GetLogicalDriveStrings(MAX_PATH, szTemp)) {
		return false;
	}

	TCHAR szDrive[3] = TEXT(" :");
	TCHAR* p = szTemp;
	try
	{
		do {
			*szDrive = *p;
			LogicalDriveNames.push_back(szDrive);
			while (*p++);
		} while (*p);
	}
	catch (...) {
		return false;
	}
	return true;
}

/*++
Routine Description:
	OsIsVM
Arguments:
	void
Return Value:
	bool
--*/
bool OsIsVM()
{
	bool rc = true;
	__try
	{
#ifdef _M_X64
		rc = false;
#else
		__asm
		{
			push   edx
				push   ecx
				push   ebx
				mov    eax, 'VMXh'
				mov    ebx, 0  
				mov    ecx, 10 
				mov    edx, 'VX' 
				in     eax, dx 
				
				cmp    ebx, 'VMXh' 
				setz[rc]
				pop    ebx
				pop    ecx
				pop    edx
		}
#endif
	}
	__except (EXCEPTION_EXECUTE_HANDLER)  
	{
		rc = false;
	}
	return rc;
}

}
