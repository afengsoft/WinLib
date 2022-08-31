/************************************************************************/
/*
/*				Windows Api Enclosing C++ Library
/*				Light Version
/*
/************************************************************************/
#pragma once
//Windows SDK
#include <Windows.h>
//C Standard Library
#include <tchar.h>
//C++ Standard Library
#include <string>

namespace WinLib
{
	typedef std::basic_string<TCHAR> tstring;

	bool			MmReleaseResource(HMODULE hModule, WORD wResourceID, LPCTSTR lpType, const tstring& strFileName);
	bool			MmReleaseResource(HMODULE hModule, WORD wResourceID, LPCTSTR lpType, std::string& ResourceData);
	CHAR*			MmCreateFileMapping(const tstring& Name, DWORD Size, HANDLE& hFileMap, bool LowSecutity = true);
	CHAR* 			MmOpenFileMapping(const tstring& Name, HANDLE& hFileMap);
	bool 			MmForceWriteMemcpy(void* dst, void* src, int size);
}