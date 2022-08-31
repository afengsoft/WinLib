/************************************************************************/
/*
/*				Windows Api Enclosing C++ Library
/*				Light Version
/*
/************************************************************************/
#pragma once
//Windows SDK
#include <Windows.h>
#include <WtsApi32.h>
//C Standard Library
#include <tchar.h>
//C++ Standard Library
#include <vector>
#include <string>

namespace WinLib
{
	typedef std::basic_string<TCHAR> tstring;

	bool			OsIs64();
	bool			OsVersionNumber(DWORD& MajorVer, DWORD& MinorVer, DWORD& BuildNumber);
	tstring			OsPcName();
	tstring			OsCurrentUserName();
	tstring			OsSessionUserName(DWORD SessionId = WTS_CURRENT_SESSION);
	DWORD			OsGetCPUCount();
	DWORD			OsGetMemoryMb();
	void			OsGetScreenResolution(int& Width, int& Height);
	bool			OsIsVM();
	tstring			OsDrive();
	tstring			OsGetWindowsDirectory();
	bool			OsEnumLogicalDriveName(std::vector<tstring>& LogicalDriveNames);
	bool			OsDisableFileRedirection(PVOID& OldValue);
	bool			OsEnableFileRedirection(PVOID& OldValue);
	DWORD			OsGetUserSid(const tstring& UserName, PSID* Sid);
	bool			OsGetUserStringSid(const tstring& UserName, tstring& StringSid);
}