#ifndef _CRT_RAND_S
#define _CRT_RAND_S
#endif
#include "WinLibStr.h"

namespace WinLib
{

	//1 => '1' / A => 'A'
#ifndef HEX_TO_CHAR
#define HEX_TO_CHAR(x)	((unsigned char)(x) > 9 ? (unsigned char)(x) -10 + 'A': (unsigned char)(x) + '0')
#endif

//'1' => 1 / 'A' => A
#ifndef CHAR_TO_HEX
#define CHAR_TO_HEX(x)	(isdigit((unsigned char)(x)) ? (unsigned char)(x)-'0' : (unsigned char)(toupper(x))-'A'+10)
#endif

/*++
Description:
	check SubStr is sub string of Str
Arguments:
	Str - primary
	SubStr - sub
	CaseInsensitive - case insensitive
Return:
	bool
--*/
	bool StrFind(const tstring& Str, const tstring& SubStr, bool CaseInsensitive)
	{
		try {
			if (CaseInsensitive) {
				return StrToLower(Str).find(StrToLower(SubStr)) != tstring::npos;
			}
			return Str.find(SubStr) != tstring::npos;
		}
		catch (...) {
			return false;
		}
	}

	/*++
	Description:
		check SubStr is sub string of Str list
	Arguments:
		Str - primary
		SubStr - sub
		CaseInsensitive - case insensitive
	Return:
		bool
	--*/
	bool StrFind(const tstring& Str1, const std::vector<tstring>& Str2, bool CaseInsensitive)
	{
		for (auto iter = Str2.begin(); iter != Str2.end(); iter++)
		{
			if (WinLib::StrFind(Str1, *iter, CaseInsensitive)) {
				return true;
			}
		}
		return false;
	}

	bool StrFindA(const std::string& Str, const std::string& SubStr, bool CaseInsensitive)
	{
		try {
			if (CaseInsensitive) {
				return StrToLowerA(Str).find(StrToLowerA(SubStr)) != std::string::npos;
			}
			return Str.find(SubStr) != std::string::npos;
		}
		catch (...) {
			return false;
		}
	}

	/*++
	Description:
		string to upper
	Arguments:
		wstr - origin wstring
	Return:
		result upper string
	--*/
	tstring StrToUpper(const tstring& wstr)
	{
		try {
			tstring tmp(wstr);
			for (size_t i = 0; i < tmp.size(); i++) {
				tmp[i] = toupper(tmp[i]);
			}
			return std::move(tmp);
		}
		catch (...) {
			return _T("");
		}
	}

	std::string StrToUpperA(const std::string& str)
	{
		try {
			std::string tmp(str);
			for (size_t i = 0; i < tmp.size(); i++) {
				tmp[i] = toupper(tmp[i]);
			}
			return std::move(tmp);
		}
		catch (...) {
			return "";
		}
	}

	/*++
	Description:
		string to lower
	Arguments:
		wstr - origin wstring
	Return:
		result lower string
	--*/
	tstring StrToLower(const tstring& wstr)
	{
		try {
			tstring tmp(wstr);
			for (size_t i = 0; i < tmp.size(); i++) {
				tmp[i] = tolower(tmp[i]);
			}
			return std::move(tmp);
		}
		catch (...) {
			return _T("");
		}
	}

	std::string StrToLowerA(const std::string& wstr)
	{
		try {
			std::string tmp(wstr);
			for (size_t i = 0; i < tmp.size(); i++) {
				tmp[i] = tolower(tmp[i]);
			}
			return std::move(tmp);
		}
		catch (...) {
			return "";
		}
	}

	/*++
	Description:
		UNICODE to CP_ACP
		eg:
		L"Hello UNONE" => "Hello UNONE"
	Arguments:
		wstr - wide string
	Return:
		string
	--*/
	std::string StrToString(const std::wstring& wstr)
	{
		return StrWideToCode(CP_ACP, wstr);
	}

	/*++
	Description:
		CP_ACP to UNICODE
		eg:
		"Hello UNONE" => L"Hello UNONE"
	Arguments:
		str - string
	Return:
		wide string
	--*/
	std::wstring StrToWstring(const std::string& str)
	{
		return StrCodeToWide(CP_ACP, str);
	}

	/*++
	Description:
		wide to code (The custom code page)
	Arguments:
		wstr - wide string
	Return:
		string
	--*/
	std::string StrWideToCode(unsigned int code, const std::wstring& wstr)
	{
		try {
			if (wstr.empty()) return "";
			int templen = WideCharToMultiByte(code, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
			if (!templen) return "";
			char* tempstr = new(std::nothrow) char[templen];
			if (!tempstr) return "";
			memset(tempstr, 0, templen);
			WideCharToMultiByte(code, 0, wstr.c_str(), -1, tempstr, templen, NULL, NULL);
			std::string str(tempstr);
			delete[] tempstr;
			return str;
		}
		catch (...) {
			return "";
		}
	}


	/*++
	Description:
		CP_UTF8 to UNICODE
	Arguments:
		str - string
	Return:
		wstring
	--*/
	std::wstring StrUTF8ToWide(__in const std::string& str)
	{
		return StrCodeToWide(CP_UTF8, str);
	}

	/*++
	Description:
		UNICODE to CP_UTF8
		eg:
		L"Hello UNONE" => "Hello UNONE"
	Arguments:
		wstring
	Return:
		string
	--*/
	std::string StrWideToUTF8(__in const std::wstring& wstr)
	{
		return StrWideToCode(CP_UTF8, wstr);
	}

	/*++
	Description:
		code to wide
	Arguments:
		str - string
	Return:
		string
	--*/
	std::wstring StrCodeToWide(__in unsigned int code, __in const std::string& str)
	{
		try {
			if (str.empty()) return L"";
			int templen = MultiByteToWideChar(code, 0, str.c_str(), -1, NULL, 0);
			if (!templen) return L"";
			wchar_t* tempstr = new(std::nothrow) wchar_t[templen * 2];
			if (!tempstr) return L"";
			memset(tempstr, 0, templen * 2);
			MultiByteToWideChar(code, 0, str.c_str(), -1, tempstr, templen);
			std::wstring wstr(tempstr);
			delete[] tempstr;
			return wstr;
		}
		catch (...) {
			return L"";
		}
	}

	/*++
	Description:
		wide string to hex
	Arguments:
		wstr - hex wide string
	Return:
		hex
	--*/
	UINT StrToHex(const tstring& Str)
	{
		return _tcstoul(Str.c_str(), NULL, 16);
	}

	/*++
	Description:
		string to decimal integer
	Arguments:
		Str - decimal integer string
	Return:
		integer
	--*/
	UINT StrToDecimal(const tstring& Str)
	{
		return _tcstoul(Str.c_str(), NULL, 10);
	}

	/*++
	Description:
		string to decimal integer 64
	Arguments:
		Str - decimal integer string
	Return:
		decimal 64
	--*/
	UINT64 StrToDecimal64(const tstring& Str)
	{
		return _tcstoui64(Str.c_str(), NULL, 10);
	}


	/*++
	Description:
		string to binary
	Arguments:
		str - binary string
	Return:
		binary
	--*/
	UINT StrToBinary(const tstring& Str)
	{
		return _tcstoul(Str.c_str(), NULL, 2);
	}

	/*++
	Description:
		string to binary 64
	Arguments:
		str - binary string
	Return:
		binary 64
	--*/
	UINT64 StrToBinary64(const tstring& Str)
	{
		return _tcstoui64(Str.c_str(), NULL, 2);
	}


	/*++
	Description:
		binary stream to hex string
		eg:
		L"\xAB\xCD\xEF" => "AB00CD00EF00", little endian
	Arguments:
		stream - binary stream
	Return:
		hex string
	--*/
	std::string StrStreamToHexStr(const std::string& stream_s)
	{
#ifndef HEX_TO_CHAR
#define HEX_TO_CHAR(x)	((unsigned char)(x) > 9 ? (unsigned char)(x) -10 + 'A': (unsigned char)(x) + '0')
#endif
		std::string hexstr;
		try {

			for (size_t i = 0; i < stream_s.size(); i++) {
				unsigned char ch = stream_s[i];
				hexstr.push_back(HEX_TO_CHAR(ch >> 4));
				hexstr.push_back(HEX_TO_CHAR(ch % 16));
			}
			return hexstr;
		}
		catch (...) {
			return "";
		}
	}

	/*++
	Description:
		hex string to binary stream
		eg:
		"AB00CD00EF00" => L"\xAB\xCD\xEF", little endian
	Arguments:
		str - hex string
	Return:
		binary stream
	--*/
	std::string StrHexStrToStream(__in const std::string& inhexstr)
	{
		std::string hexstr = inhexstr;

		std::string stream;
		try {

			bool odd = false;
			unsigned char last = 0;
			size_t size = hexstr.size();

			//if hexstr length is odd£¬the last char would be handle differently. 
			if (size % 2 != 0) {
				last = CHAR_TO_HEX(hexstr[size - 1]) % 16;
				size--;
				odd = true;
			}
			for (size_t i = 0; i < size; i += 2) {
				unsigned char ch = 0;
				ch = CHAR_TO_HEX(hexstr[i]) << 4;
				ch |= CHAR_TO_HEX(hexstr[i + 1]) % 16;
				stream.push_back(ch);
			}
			if (odd) {
				stream.push_back(last);
			}
		}
		catch (...) {
			return "";
		}
		return stream;
	}


	/*++
	Routine Description:
		String to numeric version
		N.B.
		2014.10.21.1 => 566890646046310401
	Arguments:
		version - String
	Return Value:
		numeric version
	--*/
	UINT64 StrVersionToNumber(const tstring& version)
	{
		try {
			LARGE_INTEGER li = { 0 };
			std::vector<tstring> vec;
			StrSplit(version, _T("."), vec);
			int size = (int)vec.size();
			if (size >= 1)
				li.HighPart += ((unsigned short)StrToDecimal(vec[0])) << 16;
			if (size >= 2)
				li.HighPart += StrToDecimal(vec[1]) & 0xFFFF;
			if (size >= 3)
				li.LowPart += ((unsigned short)StrToDecimal(vec[2])) << 16;
			if (size >= 4)
				li.LowPart += StrToDecimal(vec[3]) & 0xFFFF;
			return li.QuadPart;
		}
		catch (...) {
			return 0;
		}
	}

	/*++
	Routine Description:
		numeric version to String
		N.B.
		566890646046310401 => 2014.10.21.1
	Arguments:
		version - number
	Return Value:
		version
	--*/
	tstring StrNumberToVersion(LONGLONG version)
	{
		LARGE_INTEGER li;
		li.QuadPart = version;
		WORD Version1 = HIWORD(li.HighPart);
		WORD Version2 = LOWORD(li.HighPart);
		WORD Version3 = HIWORD(li.LowPart);
		WORD Version4 = LOWORD(li.LowPart);
		return StrFormat(_T("%d.%d.%d.%d"), Version1, Version2, Version3, Version4);
	}

	/*++
	Description:
		compare two wstring
	Arguments:
		str1 - string
		str2 - string
		CaseInsensitive - case insensitive
	Return:
		bool
	--*/
	bool StrCompare(const tstring& Str1, const tstring& Str2, bool CaseInsensitive)
	{
		try {
			if (true)
			{
				if (!CaseInsensitive) {
					return StrToLower(Str1).compare(StrToLower(Str2)) == 0;
				}
				return Str1.compare(Str2) == 0;
			}
		}
		catch (...) {
			return false;
		}
	}

	bool StrCompareA(const std::string& Str1, const std::string& Str2, bool CaseInsensitive)
	{
		try {
			if (true)
			{
				if (!CaseInsensitive) {
					return StrToLowerA(Str1).compare(StrToLowerA(Str2)) == 0;
				}
				return Str1.compare(Str2) == 0;
			}
		}
		catch (...) {
			return false;
		}
	}

	/*++
	Description:
		compare two string
	Arguments:
		str1 - string
		str2 - string
		CaseInsensitive - case insensitive
	Return:
		bool
	--*/
	bool StrCompare(const tstring& Str1, const std::vector<tstring>& Str2, bool CaseInsensitive)
	{
		for (auto iter = Str2.begin(); iter != Str2.end(); iter++)
		{
			if (WinLib::StrCompare(Str1, *iter, CaseInsensitive)) {
				return true;
			}
		}
		return false;
	}

	/*++
	Description:
		format wstring
	Arguments:
		formats - format control chars
		... - variable parameter
	Return:
		formated wstring
	--*/
	tstring StrFormat(const TCHAR* formats, ...)
	{
		tstring str;
		try {
			va_list lst;
			va_start(lst, formats);
			str = StrFormatVaList(formats, lst);
			va_end(lst);
		}
		catch (...) {
			str.clear();
		}
		return str;
	}

	/*++
	Description:
		format wstring with va_list
	Arguments:
		formats - format control chars
		lst - variable parameter list
	Return:
		formated string
	--*/
	tstring StrFormatVaList(const TCHAR* formats, va_list lst)
	{
		try {
			int bufsize = _vsctprintf(formats, lst);
			if (bufsize == 0) {
				return _T("");
			}
			TCHAR* buffer = new (std::nothrow) TCHAR[bufsize + 1];
			if (buffer == NULL) {
				return _T("");
			}
			_vsntprintf_s(buffer, bufsize + 1, bufsize, formats, lst);
			tstring str(buffer);
			delete[]buffer;
			return str;
		}
		catch (...) {
			return _T("");
		}
	}

	/*++
	Description:
		format wstring
	Arguments:
		formats - format control chars
		... - variable parameter
	Return:
		formated wstring
	--*/
	std::string StrFormatA(const char* formats, ...)
	{
		std::string str;
		try {
			va_list lst;
			va_start(lst, formats);
			str = StrFormatVaListA(formats, lst);
			va_end(lst);
		}
		catch (...) {
			str.clear();
		}
		return str;
	}

	/*++
	Description:
		format wstring with va_list
	Arguments:
		formats - format control chars
		lst - variable parameter list
	Return:
		formated string
	--*/
	std::string StrFormatVaListA(const char* formats, va_list lst)
	{
		try {
			int bufsize = _vscprintf(formats, lst);
			if (bufsize == 0)
				return "";
			bufsize++;
			char* buffer = (char*)malloc(bufsize);
			if (buffer == NULL)
				return "";
			memset(buffer, 0, bufsize);
			_vsnprintf_s(buffer, bufsize, bufsize - 1, formats, lst);
			std::string str(buffer);
			free(buffer);
			return str;
		}
		catch (...) {
			return "";
		}
	}

	/*++
	Description:
		split string
	Arguments:
		str - primary
		sep - separator string
		vec - result
	Return:
		bool
	--*/
	bool StrSplit(tstring Str, const tstring& Sep, std::vector<tstring>& Vec)
	{
		try {
			tstring Str2 = Str;
			size_t pos = 0;
			if (!Str2.empty()) {
				do {
					pos = Str2.find(Sep);
					if (pos == tstring::npos) {
						Vec.push_back(Str2);
						break;
					}
					Vec.push_back(Str2.substr(0, pos));
					Str2 = Str2.substr(pos + Sep.size());
				} while (true);
			}
			return true;
		}
		catch (...) {
			Vec.clear();
			return false;
		}
	}

	/*++
	Description:
		split string
	Arguments:
		str - primary
		sep - separator string
		vec - result
	Return:
		bool
	--*/
	bool StrSplitA(const std::string& Str, const std::string& Sep, std::vector<std::string>& Vec)
	{
		try {
			std::string Str2 = Str;
			size_t pos = 0;
			if (!Str2.empty()) {
				do {
					pos = Str2.find(Sep);
					if (pos == std::string::npos) {
						Vec.push_back(Str2);
						break;
					}
					Vec.push_back(Str2.substr(0, pos));
					Str2 = Str2.substr(pos + Sep.size());
				} while (true);
			}
			return true;
		}
		catch (...) {
			Vec.clear();
			return false;
		}
	}

	/*++
	Description:
		split string to lines(CRLF/LF/CR)
	Arguments:
		str - primary
		lines - result
	Return:
		bool
	--*/
	bool StrSplitLines(const tstring& str, std::vector<tstring>& lines)
	{
		try {
			tstring TmpStr = str;
			size_t pos = 0;
			if (!TmpStr.empty()) {
				do {
					pos = TmpStr.find(_T('\n'));
					if (pos == tstring::npos) {
						if (!TmpStr.empty() && TmpStr[TmpStr.size() - 1] == _T('\r')) {
							lines.push_back(TmpStr.substr(0, TmpStr.size() - 1));
						}
						else {
							lines.push_back(TmpStr);
						}
						break;
					}
					tstring&& line = TmpStr.substr(0, pos);
					if (line[line.size() - 1] == _T('\r')) {
						lines.push_back(line.substr(0, line.size() - 1));
					}
					else {
						lines.push_back(line);
					}
					TmpStr = TmpStr.substr(pos + 1);
				} while (true);
			}
			return true;
		}
		catch (...) {
			lines.clear();
			return false;
		}
	}

	bool StrSplitLinesA(const std::string& str, std::vector<std::string>& lines)
	{
		try {
			std::string TmpStr = str;
			size_t pos = 0;
			if (!TmpStr.empty()) {
				do {
					pos = TmpStr.find('\n');
					if (pos == std::string::npos) {
						if (!TmpStr.empty() && TmpStr[TmpStr.size() - 1] == '\r') {
							lines.push_back(TmpStr.substr(0, TmpStr.size() - 1));
						}
						else {
							lines.push_back(TmpStr);
						}
						break;
					}
					std::string&& line = TmpStr.substr(0, pos);
					if (line[line.size() - 1] == '\r') {
						lines.push_back(line.substr(0, line.size() - 1));
					}
					else {
						lines.push_back(line);
					}
					TmpStr = TmpStr.substr(pos + 1);
				} while (true);
			}
			return true;
		}
		catch (...) {
			lines.clear();
			return false;
		}
	}

	/*++
	Description:
		replace wide string
	Arguments:
		source - source string
		pattern - pattern string
		replaced - replaced string
	Return:
		replaced
	--*/
	tstring StrReplace(const tstring& source, const tstring& pattern, const tstring& replaced)
	{
		tstring retsource = source;
		try {
			bool result = false;
			if (retsource.empty() || pattern.empty()) {
				return retsource;
			}
			size_t pos = 0;
			while ((pos = retsource.find(pattern, pos)) != tstring::npos) {
				retsource.replace(pos, pattern.size(), replaced);
				pos += replaced.size();
				result = true;
			}
			return retsource;
		}
		catch (...) {
			return retsource;
		}
	}

	std::string StrReplaceA(const std::string& source, const std::string& pattern, const std::string& replaced)
	{
		std::string retsource = source;
		try {
			bool result = false;
			if (retsource.empty() || pattern.empty()) {
				return retsource;
			}
			size_t pos = 0;
			while ((pos = retsource.find(pattern, pos)) != std::string::npos) {
				retsource.replace(pos, pattern.size(), replaced);
				pos += replaced.size();
				result = true;
			}
			return retsource;
		}
		catch (...) {
			return retsource;
		}
	}

	/*++
	Description:
		file path to name
	Arguments:
		fpath - file path
	Return:
		file name
	--*/
	tstring StrPathToName(const tstring& fpath)
	{
		try {
			return fpath.substr(fpath.find_last_of(_T("\\/")) + 1);
		}
		catch (...) {
			return _T("");
		}
	}

	/*++
	Description:
		file path to dir
	Arguments:
		fpath - file path
		up_level - up level
	Return:
		dir
	--*/
	tstring StrPathToDir(const tstring& path)
	{
		try {
			if (path.empty())
				return _T("");
			int offset = (int)tstring::npos;
			wchar_t end = path[path.size() - 1];
			if (end == _T('\\') || end == _T('/'))
				offset = (int)path.size() - 2;
			return path.substr(0, path.find_last_of(_T("\\/"), offset));
		}
		catch (...) {
			return _T("");
		}
	}

	/*++
	Description:
		file path to extension
	Arguments:
		fpath - file path
	Return:
		file extension
	--*/
	tstring StrNameToExt(const tstring& FileName)
	{
		tstring str = FileName;
		int pos = (int)str.find_last_of(_T("."));
		if (pos == tstring::npos) return _T("");
		return str.substr(pos);
	}

	tstring StrNameWithoutExt(const tstring& FileName)
	{
		tstring str = FileName;
		int pos = (int)str.find_last_of(_T("."));
		if (pos == tstring::npos) return _T("");
		return str.substr(0, pos);
	}

	/*++
	Routine Description:
		ParseCmdline
		N.B.
		// singsing.exe bone7
		// "c:\Program x64\singsing.exe" bone7
		// "c:\Program x64\singsing.exe" bone7 "111 222"
		// "c:\Program x64\singsing.exe" "bone7" 111
		// "c:\Program x64\singsing.exe" "\"bone7\"" 111
	Arguments:
		Cmdline - Cmdline
		Argv - Argv
	Return Value:
		bool
	--*/
	bool StrParseCmdline(const tstring& Cmdline, std::vector<tstring>& Argv)
	{
		if (Cmdline.empty()) {
			return false;
		}
		try {
			int Argc = 0;
			LPWSTR* ArgvW = CommandLineToArgvW(
				Cmdline.c_str(),
				&Argc);

			for (int Index = 0; Index < Argc; ++Index)
			{
				Argv.push_back(ArgvW[Index]);
			}
			HeapFree(GetProcessHeap(), 0, ArgvW);
			return !Argv.empty();
		}
		catch (...) {
			Argv.clear();
			return false;
		}
	}

	/*++
	Routine Description:
		StrJoinCmdline
	Arguments:
		Argv - Argv
		Cmdline - Cmdline
	Return Value:
		bool
	--*/
	bool StrJoinCmdline(const std::vector<tstring>& Argv, tstring& Cmdline)
	{
		try {
			tstring Str;
			for (auto ArgvItem = Argv.begin(); ArgvItem != Argv.end(); ++ArgvItem)
			{
				if (ArgvItem != Argv.begin())
					Str += _T(" ");

				if (ArgvItem->find(_T(" ")) != tstring::npos)
					Str += _T("\"") + *ArgvItem + _T("\"");
				else
					Str += *ArgvItem;
			}
			Cmdline = Str;
			return !Argv.empty();
		}
		catch (...) {
			Cmdline.clear();
			return false;
		}
	}

	/*++
	Routine Description:
		UNICODE_STRING string
	Arguments:
		Ustr - UNICODE_STRING
	Return Value:
		wstring
	--*/
	std::wstring StrUnicodeToWstr(void* Ustr)
	{
		typedef struct _UNICODE_STRING {
			USHORT Length;
			USHORT MaximumLength;
			PWSTR  Buffer;
		} UNICODE_STRING, *PUNICODE_STRING;

		try {
			std::wstring Wstr;
			if (Ustr != nullptr) {
				Wstr.assign(((PUNICODE_STRING)Ustr)->Buffer, ((PUNICODE_STRING)Ustr)->Length / 2);
			}
			return Wstr;
		}
		catch (...) {
			return L"";
		}
	}

	/*++
	Routine Description:
		URL Code
	Arguments:
		Url - URL(GBK CODE)
	Return Value:
		URLCode
	--*/
	std::string StrUrlEncode(const std::string& Url)
	{
		std::string Str;
		try {
			static const char* kUrlReservedCharset = ("!*'();:@&=+$,/?#[]");
			static const char* kUrlNonReservedCharset = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~");
			std::string CharSet = kUrlNonReservedCharset;
			std::string Utf8Url = StrWideToUTF8(StrToWstring(Url));
			for (size_t i = 0; i < Utf8Url.size(); i++) {
				unsigned char temp[4] = { 0 };
				unsigned char ch = (unsigned char)Utf8Url[i];
				if (CharSet.find(ch) != std::string::npos) {
					temp[0] = ch;
				}
				else {
					temp[0] = '%';
					temp[1] = HEX_TO_CHAR(ch >> 4);
					temp[2] = HEX_TO_CHAR(ch % 16);
				}
				Str += (char*)temp;
			}
		}
		catch (...) {
			Str.clear();
		}
		return std::move(Str);
	}

	/*++
	Routine Description:
		URL DeCode
	Arguments:
		Url
	Return Value:
		URL DeCode
	--*/
	std::string StrUrlDecode(const std::string& Url)
	{
		if (Url.empty()) {
			return "";
		}
		std::string Str;
		try
		{
			std::string bits;
			bits.assign(Url.size(), 0);
			for (size_t i = 0; i < Url.size(); i++) {
				if (Url[i] == '%') {
					bits[i] = 1;
					bits[i + 1] = 1;
					bits[i + 2] = 1;
					i += 2;
				}
			}
			auto& decode = [](std::string& s)->std::string {
				std::string out;
				for (size_t i = 0; i < s.size(); i += 3) {
					unsigned char ch = 0;
					ch = CHAR_TO_HEX(s[i + 1]) << 4;
					ch |= CHAR_TO_HEX(s[i + 2]) % 16;
					out.push_back(ch);
				}
				out = StrToString(StrUTF8ToWide(out));
				return out;
			};
			size_t last = 0;
			size_t i = 0;
			for (i = 0; i < bits.size(); i++) {
				if (bits[i] == 0) {
					if (last < i) {
						Str += decode(Url.substr(last, i - last));
					}
					Str += Url[i];
					last = i + 1;
				}
			}
			if (bits.back() == 1) {
				if (last < i) {
					Str += decode(Url.substr(last, i - last));
				}
			}

		}
		catch (...) {
			Str.clear();
		}
		return std::move(Str);
	}

	/*++
	Description:
		ntstatus to dos error
	Arguments:
		status - NTSTATUS
	Return:
		dos error
	--*/
	DWORD StrNtToDosError(LONG status)
	{
		typedef ULONG(WINAPI *__RtlNtStatusToDosError)(
			IN NTSTATUS Status
			);

		DWORD err = -1;
		__RtlNtStatusToDosError pRtlNtStatusToDosError = (__RtlNtStatusToDosError)
			GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlNtStatusToDosError");
		if (pRtlNtStatusToDosError)
			err = pRtlNtStatusToDosError(status);
		return err;
	}

	/*++
	Description:
		dos error to message
	Arguments:
		err - dos error
	Return:
		error message
	--*/
	tstring StrErrorMsg(DWORD Error)
	{
		tstring str;
		LPVOID msg_buff = NULL;
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			Error,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)&msg_buff,
			0,
			NULL);
		if (msg_buff) {
			str = (LPTSTR)msg_buff;
			LocalFree(msg_buff);
		}
		return str;
	}

	/*++
	Routine Description:
		rand str£¬use WRNG
		Global random number (thread independent)
		charset:"0123456789ABCDEF"
	Arguments:
		count - count of str
	Return Value:
		failed - empty string
		success - rand str
	--*/
	tstring StrRandString(int Count, const tstring& Charset)
	{
		TCHAR str_temp[2] = { 0 };
		tstring str;
		int i, x;
		tstring tmpcharset = Charset;
		unsigned int randnum = 0;
		if (tmpcharset.empty())
			tmpcharset = _T("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
		if (Count <= 0) {
			return _T("");
		}
		for (i = 0; i < Count; ++i)
		{
			::rand_s(&randnum);
			x = randnum % (unsigned)(tmpcharset.size() - 1);
			_stprintf_s(str_temp, _T("%c"), tmpcharset[x]);
			str.append(str_temp);
		}
		return str;
	}

	/*++
	Routine Description:
		rand int range [min,max)£¬use WRNG
		Global random number (thread independent)
	Arguments:
		min - min
		max - max
	Return Value:
		failed - 0
		success - rand number
	--*/
	int StrRandInteger(int min, int max)
	{
		int ret;
		unsigned int randnum = 0;
		if (max < 0 || min < 0 || max <= min)
			return 0;
		::rand_s(&randnum);
		ret = (randnum % (unsigned)(max - min)) + min;
		return ret;
	}

	/*++
	Routine Description:
		"C:\Windows\explore.exe" -> "\Device\HarddiskVolume2\Windows\explore.exe"
	Arguments:
		DosPath
	Return Value:
		NtPath
	--*/
	tstring StrDosToNtPath(const tstring& DosPath)
	{
		bool Result = false;
		if (DosPath.size() < 2 || DosPath[1] != _T(':'))
		{
			return _T("");
		}
		tstring Volume = DosPath.substr(0, 2);
		tstring RelPath = DosPath.substr(2);
		TCHAR Target[MAX_PATH * 2] = { 0 };
		if (::QueryDosDevice(Volume.c_str(), Target, MAX_PATH * 2 - 1) == 0)
		{
			return _T("");
		}
		tstring NtPath;
		NtPath.append(Target);
		NtPath.append(RelPath);
		return NtPath;
	}

	tstring StrNtToDosPath(const tstring& NtPath)
	{
		TCHAR szTemp[MAX_PATH + 1] = { 0 };
		if (!::GetLogicalDriveStrings(_countof(szTemp) - 1, szTemp)) {
			return _T("");
		}

		TCHAR szName[MAX_PATH + 1];
		TCHAR szDrive[3] = TEXT(" :");
		bool bFound = false;
		TCHAR* p = szTemp;
		tstring DosPath;
		do {

			*szDrive = *p;

			// Look up each device name
			if (::QueryDosDevice(szDrive, szName, _countof(szName)))
			{
				UINT uNameLen = (UINT)_tcslen(szName);
				if (uNameLen < MAX_PATH)
				{
					bFound = _tcsnicmp(NtPath.c_str(), szName, uNameLen) == 0;

					if (bFound) {
						// Reconstruct pszFilename using szTemp
						// Replace device path with DOS path
						TCHAR szTempFile[MAX_PATH] = { 0 };
						_stprintf_s(szTempFile, TEXT("%s%s"), szDrive, NtPath.c_str() + uNameLen);
						DosPath = szTempFile;
					}
				}
			}

			// Go to the next NULL character.
			while (*p++);
		} while (!bFound && *p); // end of string

		return DosPath;
	}
}