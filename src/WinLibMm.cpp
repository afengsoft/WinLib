#include "WinLibMm.h"

namespace WinLib
{
	bool MmReleaseResource(HMODULE hModule, WORD wResourceID, LPCTSTR lpType, const tstring& strFileName)
	{
		bool Result = false;
		if (strFileName.empty()) {
			return Result;
		}

		HRSRC hResInfo = ::FindResource(hModule, MAKEINTRESOURCE(wResourceID), lpType);
		if (hResInfo == NULL) {
			return Result;
		}

		HGLOBAL hRes = ::LoadResource(hModule, hResInfo);
		if (hRes == NULL) {
			return Result;
		}

		HANDLE hFile = ::CreateFile(
			strFileName.c_str(),
			GENERIC_WRITE,
			FILE_SHARE_READ,
			NULL,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);
		if (hFile == INVALID_HANDLE_VALUE) {
			return Result;
		}

		DWORD dwBytes = 0;
		DWORD dwResSize = ::SizeofResource(hModule, hResInfo);
		if (::WriteFile(hFile, hRes, dwResSize, &dwBytes, NULL))
		{
			if(dwResSize == dwBytes)
				Result = true;
		}
		::CloseHandle(hFile);
		::FreeResource(hRes);
		return Result;
	}

	bool MmReleaseResource(HMODULE hModule, WORD wResourceID, LPCTSTR lpType, std::string& ResourceData)
	{
		ResourceData.clear();
		HRSRC hResInfo = ::FindResource(hModule, MAKEINTRESOURCE(wResourceID), lpType);
		if (hResInfo == NULL) {
			return false;
		}

		HGLOBAL hRes = ::LoadResource(hModule, hResInfo);
		if (hRes == NULL) {
			return false;
		}

		DWORD BufSize = ::SizeofResource(hModule, hResInfo);
		ResourceData.append((const char*)hRes, BufSize);
		::FreeResource(hRes);
		return true;
	}

	CHAR* MmCreateFileMapping(const tstring& Name, DWORD Size, HANDLE& hFileMap, bool LowSecutity)
	{
		if (LowSecutity)
		{
			SECURITY_DESCRIPTOR secutityDese;
			::InitializeSecurityDescriptor(&secutityDese, SECURITY_DESCRIPTOR_REVISION);
			::SetSecurityDescriptorDacl(&secutityDese, TRUE, NULL, FALSE);
			SECURITY_ATTRIBUTES securityAttr;
			securityAttr.nLength = sizeof SECURITY_ATTRIBUTES;
			securityAttr.bInheritHandle = FALSE;
			securityAttr.lpSecurityDescriptor = &secutityDese;
			hFileMap = ::CreateFileMapping(INVALID_HANDLE_VALUE, &securityAttr, PAGE_READWRITE, 0, Size, Name.c_str());
		}
		else
		{
			hFileMap = ::CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, Size, Name.c_str());
		}

		if (hFileMap == NULL) {
			return NULL;
		}

		CHAR* Buff = (CHAR*)::MapViewOfFile(hFileMap, FILE_MAP_WRITE, 0, 0, 0);
		if (Buff == NULL) {
			::CloseHandle(hFileMap);
			return NULL;
		}
		return Buff;
	}

	CHAR* MmOpenFileMapping(const tstring& Name, HANDLE& hFileMap)
	{
		hFileMap = ::OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, Name.c_str());
		if (hFileMap == NULL) {
			return NULL;
		};

		CHAR* Buff = (CHAR*)::MapViewOfFile(hFileMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
		if (Buff == NULL) {
			::CloseHandle(hFileMap);
			return NULL;
		}
		return Buff;
	}

	bool MmForceWriteMemcpy(void* dst, void* src, int size)
	{
		bool retval = false;
		DWORD protect;
		if (::VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &protect)) 
		{
			::memcpy(dst, src, size);
			::VirtualProtect(dst, size, protect, &protect);
			retval = true;
		}
		return retval;
	}
}