/************************************************************************/
/*
/*				Windows Api Enclosing C++ Library
/*				Light Version
/*
/************************************************************************/
#pragma once
//Windows SDK
#include <Windows.h>
#include <Aclapi.h>
//C Standard Library
#include <tchar.h>
//C++ Standard Library
#include <string>

namespace WinLib
{
	typedef std::basic_string<TCHAR> tstring;
	
	bool			SeSetObjectAccess(const tstring& UserName, HANDLE Object, SE_OBJECT_TYPE ObjectType, ACCESS_MASK AccessMask, bool IsAdd, bool IsAccessAllow, bool ForbidInherit = false);
	bool			SeTakeObjectOwnership(const tstring& UserName, HANDLE Object, SE_OBJECT_TYPE ObjectType);
	bool			SeTakeFileOwnership(const tstring& UserName, const tstring& FilePath);
	bool			SeSetFileAllowAccess(const tstring& UserName, const tstring& FilePath, DWORD DesiredAccess = GENERIC_ALL, bool DelAllAccess = false);
	bool			SeSetFileDenyAccess(const tstring& UserName, const tstring& FilePath, DWORD DesiredAccess = GENERIC_ALL, bool DelAllAccess = false);
}