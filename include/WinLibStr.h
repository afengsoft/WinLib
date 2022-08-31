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
#include <list>
#include <ctime>

#ifdef _UNICODE
#define STRTOTSTING(a) WinLib::StrToWstring(a)
#else
#define STRTOTSTING(a) (a)
#endif // _UNICODE

#ifdef _UNICODE
#define TSTRTOSTING(a) WinLib::StrToString(a)
#else
#define TSTRTOSTING(a) (a)
#endif // _UNICODE

namespace WinLib
{
	typedef std::basic_string<TCHAR> tstring;

	std::string		StrToString(const std::wstring& Str);
	std::wstring	StrToWstring(const std::string& Str);
	std::wstring	StrCodeToWide(unsigned int code, const std::string& Str);
	std::string		StrWideToCode(unsigned int code, const std::wstring& Str);
	std::wstring	StrUTF8ToWide(const std::string& Str);
	std::string		StrWideToUTF8(const std::wstring& Str);
	tstring			StrToLower(const tstring& Str);
	std::string		StrToLowerA(const std::string& wstr);
	tstring			StrToUpper(const tstring& Str);
	std::string		StrToUpperA(const std::string& str);
	UINT			StrToHex(const tstring& Str);
	UINT			StrToDecimal(const tstring& Str);
	UINT64			StrToDecimal64(const tstring& Str);
	UINT			StrToBinary(const tstring& Str);
	UINT64			StrToBinary64(const tstring& Str);
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
}