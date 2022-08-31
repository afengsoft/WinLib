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
#include <vector>
#include <string>

namespace WinLib
{
	typedef std::basic_string<TCHAR> tstring;

	struct FILE_RESOURCEINFO
	{
		tstring FileDescription;
		tstring FileVersion;
		tstring CompanyName;
		tstring InternalName;
		tstring OriginalFileName;
		tstring LegalCopyright;
		tstring ProductName;
		tstring ProductVersion;
	};

	bool			FsGetFileResourceInfo(const tstring& FilePath, FILE_RESOURCEINFO& ResourceInfo);
	DWORD			FsGetFileSize(const tstring& FilePath);
	DWORD64			FsGetFileSize64(const tstring& FilePath);
	bool			FsReadFileData(const tstring& FilePath, std::string& Data);
	bool			FsWriteFileData(const tstring& FilePath, std::string Data, DWORD64 FileOffset = 0);
	bool			FsAppendFileData(const tstring& FilePath, const std::string& Data);
	bool			FsCreateDirectory(const tstring& Dir);
	bool			FsDeleteDirectory(const tstring& Dir);
	bool			FsIsFile(const tstring& Path);
	bool			FsIsDirectory(const tstring& Path);
	bool			FsEnumDirectoryFiles(const tstring& Dir, std::vector<tstring>& Files);
	bool			FsEnumDirectory(const tstring& Dir, std::vector<tstring>& Dirs);
	CHAR*			FsMapFile(const tstring& FilePath, DWORD& FileSize, HANDLE& FileHandle, HANDLE& MapHandle);
	bool			FsUnMapFile(CHAR* MapAddr, HANDLE FileHandle, HANDLE MapHandle);
	bool			FsUpdataResource(const tstring& FilePath, const std::string& ResourceData, WORD wResourceID, LPCTSTR lpType);
	bool			FsGetFileTimeInfo(const tstring& FilePath, FILETIME& CreateTime, FILETIME& AccessTime, FILETIME& ModifyTime);
}