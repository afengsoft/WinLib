#include "WinLibFs.h"
//C++ Standard Library
#include <functional>
//Other
#include "WinLibStr.h"

#pragma comment(lib, "Version.lib")

namespace WinLib
{
#ifndef MAKELONGLONG
#define MAKELONGLONG(a, b) ((LONGLONG(DWORD(a) & 0xFFFFFFFF) << 32 ) | LONGLONG(DWORD(b) & 0xFFFFFFFF))
#endif

#ifndef LONGLONGHIGH
#define LONGLONGHIGH(a) DWORD((LONGLONG(a) & 0xFFFFFFFF00000000UI64) >> 32)
#endif

#ifndef LONGLONGLOW
#define LONGLONGLOW(a) DWORD(LONGLONG(a) & 0xFFFFFFFFUI64)
#endif

	typedef std::function<bool(__in TCHAR* path, __in TCHAR* name, __in void* param)> DirEnumCallback;

	/*++
	Description:
		get file size.
	Arguments:
		fpath - file path
	Return:
		file size
	--*/
	DWORD FsGetFileSize(const tstring& FilePath)
	{
		HANDLE hFile = ::CreateFile(FilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			return 0;
		}

		DWORD FileSizeLow = ::GetFileSize(hFile, NULL);
		if (FileSizeLow == INVALID_FILE_SIZE)
		{
			::CloseHandle(hFile);
			return 0;
		}
		::CloseHandle(hFile);
		return FileSizeLow;
	}

	/*++
	Description:
		get file size64.
	Arguments:
		fpath - file path
	Return:
		file size 64
	--*/
	DWORD64 FsGetFileSize64(const tstring& FilePath)
	{
		HANDLE hFile = ::CreateFile(FilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			return 0;
		}

		DWORD FileSizeHigh = 0;
		DWORD FileSizeLow = ::GetFileSize(hFile, &FileSizeHigh);
		if (FileSizeLow == INVALID_FILE_SIZE)
		{
			::CloseHandle(hFile);
			return 0;
		}
		::CloseHandle(hFile);
		return MAKELONGLONG(FileSizeHigh, FileSizeLow);
	}

	/*++
	Description:
		read file data.
	Arguments:
		fpath - file path
		fdata - file data
	Return:
		bool
	--*/
	bool FsReadFileData(const tstring& FilePath, std::string& Data)
	{
		HANDLE hFile = ::CreateFile(FilePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			return false;
		}

		bool Result = false;
		DWORD FileSize = ::GetFileSize(hFile, NULL);
		if (FileSize != INVALID_FILE_SIZE)
		{
			if (FileSize == 0) {
				Result = true;
			}
			else
			{
				char* Buffer = new(std::nothrow) char[FileSize];
				if (Buffer != NULL)
				{
					DWORD ReadLen = 0;
					if (::ReadFile(hFile, Buffer, FileSize, &ReadLen, NULL))
					{
						if (ReadLen == FileSize)
						{
							try
							{
								Data.assign(Buffer, FileSize);
								Result = true;
							}
							catch (...) {
							}
						}
					}
					delete[] Buffer;
				}
			}
		}
		::CloseHandle(hFile);
		return Result;
	}

	/*++
	Description:
		write file data
	Arguments:
		fpath - file path
		fdata - file data
	Return:
		bool
	--*/
	bool FsWriteFileData(const tstring& FilePath, std::string Data, DWORD64 FileOffset)
	{
		bool Result = false;
		HANDLE File = ::CreateFile(FilePath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (File != INVALID_HANDLE_VALUE)
		{
			DWORD WriteLen = 0;
			if (::WriteFile(File, Data.data(), (DWORD)Data.size(), &WriteLen, NULL)) {
				if (Data.size() == WriteLen) {
					Result = true;
				}
			}
			::CloseHandle(File);
		}
		return Result;
	}

	/*++
	Description:
		write file data in file end
	Arguments:
		fpath - file path
		fdata - file data
	Return:
		bool
	--*/
	bool FsAppendFileData(const tstring& FilePath, const std::string& Data)
	{
		bool Result = false;
		HANDLE File = ::CreateFile(FilePath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (File != INVALID_HANDLE_VALUE)
		{
			DWORD WriteLen;
			::SetFilePointer(File, 0, NULL, FILE_END);
			if (::WriteFile(File, Data.c_str(), (DWORD)Data.size(), &WriteLen, NULL)) {
				if (Data.size() == WriteLen) {
					Result = true;
				}
			}
			::CloseHandle(File);
		}
		return Result;
	}

	/*++
	Description:
		create directory, could be created recursively
	Arguments:
		dir - directory path
	Return:
		bool
	--*/
	bool FsCreateDirectory(const tstring& Dir)
	{
		if (FsIsDirectory(Dir)) {
			return true;
		}
		if (FsIsFile(Dir)) {
			return false;
		}
		if (::CreateDirectory(Dir.c_str(), NULL)) {
			return true;
		}

		std::vector<tstring> Subdirs;
		tstring SubDir = Dir;
		tstring Str;
		while (Str.compare(SubDir) != 0)
		{
			Str = SubDir;
			Subdirs.push_back(SubDir);
			SubDir = StrPathToDir(Str);
		}

		for (int i = (int)Subdirs.size() - 1; i >= 0; i--)
		{
			if (FsIsDirectory(Subdirs[i]) || FsIsFile(Subdirs[i])) {
				continue;
			}

			if (!::CreateDirectory(Subdirs[i].c_str(), NULL)) {
				return false;
			}
		}
		return true;
	}

	bool FsEnumDirectoryCallBack(__in const tstring& Dir, __inout DirEnumCallback Callback, __in void* param)
	{
		if (!FsIsFile(Dir) && !FsIsDirectory(Dir)) {
			return false;
		}

		tstring Path = Dir + _T("\\*.*");
		WIN32_FIND_DATA FindData;
		HANDLE hFind = FindFirstFile(Path.c_str(), &FindData);
		if (hFind == INVALID_HANDLE_VALUE) {
			return false;
		}

		while (::FindNextFile(hFind, &FindData))
		{
			if (StrCompare(FindData.cFileName, L".")
				|| StrCompare(FindData.cFileName, _T("..")))
			{
				continue;
			}

			tstring FullPath = Dir + _T("\\") + FindData.cFileName;
			if (!Callback((TCHAR*)FullPath.c_str(), FindData.cFileName, param)) {
				break;
			}
		}

		::FindClose(hFind);
		return true;
	}

	/*++
	Description:
		delete directory include sub files
	Arguments:
		Dir - directory path
	Return:
		bool
	--*/
	bool FsDeleteDirectory(__in const tstring& Dir)
	{
		if (!FsIsDirectory(Dir)) {
			return true;
		}

		bool ret = true;
		FsEnumDirectoryCallBack(Dir, [&ret](TCHAR* path, TCHAR* name, void* param)->bool
		{
			if (FsIsDirectory(path)) {
				ret = FsDeleteDirectory(path);
			}
			else {
				ret = (::DeleteFile(path) == TRUE);
			}
			return ret;
		}, nullptr);

		if (ret) {
			ret = (::RemoveDirectory(Dir.c_str()) == TRUE);
		}
		return ret;
	}

	/*++
	Description:
		Enum directory
	Arguments:
		Dir - directory
		Dirs
	Return:
		bool
	--*/
	bool FsEnumDirDirectory(const tstring& Dir, std::vector<tstring>& Dirs)
	{
		if (!FsIsDirectory(Dir)) {
			return false;
		}

		bool result = false;
		WIN32_FIND_DATA fd;
		tstring Path = Dir + _T("\\*.*");
		HANDLE hFind = ::FindFirstFile(Path.c_str(), &fd);
		if (hFind != INVALID_HANDLE_VALUE)
		{
			while (::FindNextFile(hFind, &fd))
			{
				if (tstring(fd.cFileName).compare(_T(".")) == 0
					|| tstring(fd.cFileName).compare(_T("..")) == 0)
				{
					continue;
				}
				else if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					Dirs.push_back(Dir + _T("\\") + fd.cFileName);
				}
			}
			::FindClose(hFind);
			result = true;
		}
		return result;
	}

	/*++
	Description:
		check path is a directory
	Arguments:
		fpath - path
	Return:
		bool
	--*/
	bool FsIsDirectory(const tstring& Path)
	{
		DWORD Attrs = ::GetFileAttributes(Path.c_str());
		if (Attrs != INVALID_FILE_ATTRIBUTES) {
			if (Attrs & FILE_ATTRIBUTE_DIRECTORY)
				return true;
		}
		return false;
	}

	/*++
	Description:
		check path is a file
	Arguments:
		fpath - path
	Return:
		bool
	--*/
	bool FsIsFile(const tstring& Path)
	{
		DWORD Attrs = ::GetFileAttributes(Path.c_str());
		if (Attrs != INVALID_FILE_ATTRIBUTES) {
			if (!(Attrs & FILE_ATTRIBUTE_DIRECTORY))
				return true;
		}
		return false;
	}

	tstring FsVerQueryValue(LPCVOID pBlock, const TCHAR* type)
	{
		struct LANGANDCODEPAGE {
			WORD language;
			WORD codepage;
		};
		UINT Size = 0;
		LANGANDCODEPAGE* Translation = NULL;
		if (!VerQueryValue(pBlock, _T("\\VarFileInfo\\Translation"), (LPVOID*)&Translation, &Size)) {
			return false;
		}

		TCHAR Str[128] = { 0 };
		_stprintf_s(Str, 128, _T("\\StringFileInfo\\%04X%04X\\%s"), Translation->language, Translation->codepage, type);

		LPVOID Buf = NULL;
		if (VerQueryValue(pBlock, Str, (LPVOID*)&Buf, &Size) && Buf) {
			return (TCHAR*)Buf;
		}
		return _T("");
	}

	bool FsGetFileResourceInfo(const tstring& FilePath, FILE_RESOURCEINFO& ResourceInfo)
	{
		bool bResult = false;
		char* pBlock = NULL;

		do
		{
			DWORD dwHandle = 0;
			DWORD dwDataSize = ::GetFileVersionInfoSize(FilePath.c_str(), &dwHandle);
			if (dwDataSize == 0) {
				break;
			}

			pBlock = new (std::nothrow) char[dwDataSize];
			if (NULL == pBlock) {
				break;
			}

			if (!::GetFileVersionInfo(FilePath.c_str(), dwHandle, dwDataSize, (void*)pBlock)) {
				break;
			}

			ResourceInfo.FileDescription = FsVerQueryValue(pBlock, _T("FileDescription"));
			ResourceInfo.FileVersion = FsVerQueryValue(pBlock, _T("FileVersion"));
			ResourceInfo.CompanyName = FsVerQueryValue(pBlock, _T("CompanyName"));
			ResourceInfo.InternalName = FsVerQueryValue(pBlock, _T("InternalName"));
			ResourceInfo.OriginalFileName = FsVerQueryValue(pBlock, _T("OriginalFileName"));
			ResourceInfo.LegalCopyright = FsVerQueryValue(pBlock, _T("LegalCopyright"));
			ResourceInfo.ProductName = FsVerQueryValue(pBlock, _T("ProductName"));
			ResourceInfo.ProductVersion = FsVerQueryValue(pBlock, _T("ProductVersion"));
		} while (false);

		if (pBlock)
		{
			delete[] pBlock;
			pBlock = NULL;
		}
		return bResult;
	}

	/*++
	Routine Description:
		FsEnumDirectoryFiles
	Arguments:
		Dir - Dir
		Files - Files
	Return Value:
		bool
	--*/
	bool FsEnumDirectoryFiles(const tstring& Dir, std::vector<tstring>& Files)
	{
		if (!FsIsDirectory(Dir)) {
			return false;
		}

		WIN32_FIND_DATA fd;
		tstring Path = Dir + _T("\\*.*");
		HANDLE hFind = ::FindFirstFile(Path.c_str(), &fd);
		if (hFind == INVALID_HANDLE_VALUE) {
			return false;
		}

		while (::FindNextFile(hFind, &fd))
		{
			if (tstring(fd.cFileName).compare(_T(".")) == 0
				|| tstring(fd.cFileName).compare(_T("..")) == 0)
			{
				continue;
			}
			else if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				continue;
			}
			Files.push_back(Dir + _T("\\") + fd.cFileName);
		}
		::FindClose(hFind);
		return true;
	}

	/*++
	Routine Description:
		FsEnumDirectory
	Arguments:
		Dir - Dir
		Dirs - Dirs
	Return Value:
		bool
	--*/
	bool FsEnumDirectory(const tstring& Dir, std::vector<tstring>& Dirs)
	{
		if (!FsIsDirectory(Dir)) {
			return false;
		}

		WIN32_FIND_DATA fd;
		tstring Path = Dir + _T("\\*.*");
		HANDLE hFind = ::FindFirstFile(Path.c_str(), &fd);
		if (hFind == INVALID_HANDLE_VALUE) {
			return false;
		}

		while (::FindNextFile(hFind, &fd))
		{
			if (tstring(fd.cFileName).compare(_T(".")) == 0
				|| tstring(fd.cFileName).compare(_T("..")) == 0)
			{
				continue;
			}
			else if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				Dirs.push_back(Dir + _T("\\") + fd.cFileName);
			}
		}
		::FindClose(hFind);
		return true;
	}

	bool FsGetFileTimeInfo(const tstring& FilePath, FILETIME& CreateTime, FILETIME& AccessTime, FILETIME& ModifyTime)
	{
		HANDLE hFile = ::CreateFile(FilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			return false;
		}

		if (::GetFileTime(hFile, &CreateTime, &AccessTime, &ModifyTime))
		{
			::CloseHandle(hFile);
			return true;
		}
		::CloseHandle(hFile);
		return false;
	}

	/*++
	Description:
		map file to section, if succeeded, caller should close handles(MmUnmapFile).
	Arguments:
		path - file path
		size - file size
		fd - file handle
		hmap - mapped handle
	Return:
		mapped buffer
	--*/
	CHAR* FsMapFile(const tstring& FilePath, DWORD& Size, HANDLE& hFile, HANDLE& hMap)
	{
		hFile = INVALID_HANDLE_VALUE;
		hMap = NULL;
		do {
			hFile = ::CreateFile(FilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
			if (hFile == INVALID_HANDLE_VALUE) {
				break;
			}
			Size = ::GetFileSize(hFile, NULL);
			if (Size == INVALID_FILE_SIZE) {
				break;
			}
			if (Size == 0) {
				break;
			}
			hMap = ::CreateFileMapping(hFile, NULL, PAGE_READONLY, NULL, NULL, NULL);
			if (hMap == NULL) {
				break;
			}
			PVOID MapBuff = ::MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
			if (MapBuff == NULL) {
				break;
			}
			return (CHAR*)MapBuff;
		} while (false);

		if (hMap != NULL)
		{
			::CloseHandle(hMap);
			hMap = NULL;
		}
		if (hFile != INVALID_HANDLE_VALUE)
		{
			::CloseHandle(hFile);
			hFile = INVALID_HANDLE_VALUE;
		}
		return NULL;
	}

	/*++
	Description:
		close map file
	Arguments:
		MapBuff - mapbuf
		hFile - file handle
		hMap - mapped handle
	Return:
		bool
	--*/
	bool FsUnMapFile(CHAR* MapBuff, HANDLE hFile, HANDLE hMap)
	{
		if (!MapBuff || hFile == INVALID_HANDLE_VALUE || !hMap) {
			return false;
		}
		if (!::UnmapViewOfFile(MapBuff)) {
			return false;
		}
		::CloseHandle(hMap);
		::CloseHandle(hFile);
		return true;
	}

	/*++
	Description:
		UpdataResource file
	Arguments:
		FilePath - file path
		ResourceData - New Resource Data
		wResourceID - Resource ID
		lpType - Resource Type
	Return:
		bool
	--*/
	bool FsUpdataResource(const tstring& FilePath, const std::string& ResourceData, WORD wResourceID, LPCTSTR lpType)
	{
		bool bRte = false;
		do
		{
			HANDLE  hResource = ::BeginUpdateResource(FilePath.c_str(), FALSE);
			if (!hResource) {
				break;
			}

			if (::UpdateResource(hResource, lpType, MAKEINTRESOURCE(wResourceID),
				MAKELCID(MAKELANGID(LANG_CHINESE, SUBLANG_CHINESE_SIMPLIFIED), SORT_DEFAULT),
				(LPVOID)ResourceData.c_str(), (DWORD)ResourceData.size()) == FALSE)
			{
				break;
			}

			if (::EndUpdateResource(hResource, FALSE) == FALSE) {
				DWORD dw = GetLastError();
				break;
			}
			bRte = true;
		} while (false);

		return bRte;
	}

}