/************************************************************************/
/*
/*				WinLibTest
/*
/************************************************************************/
#include "../../include/WinLib.h"
#include <iostream>
#include "resource.h"

#ifdef _AMD64_
#ifdef _DEBUG
#pragma comment(lib, "../../project/Bin/WinLib64-d.lib")
#else
#pragma comment(lib, "../../project/Bin/WinLib64.lib")
#endif

#else
#ifdef _DEBUG
#pragma comment(lib, "../../project/Bin/WinLib32-d.lib")
#else
#pragma comment(lib, "../../project/Bin/WinLib32.lib")
#endif
#endif

#ifdef _UNICODE
#define tcout std::wcout 
#else
#define tcout std::cout 
#endif

void WinLibPsTest()
{
	//ö�ٽ���Pid
	{
		std::vector<DWORD> Pids;
		WinLib::PsEnumProcessId(Pids);
		for (auto iter = Pids.cbegin(); iter != Pids.cend(); iter++)
		{
			tcout << _T("Pid:") << *iter << std::endl;
		}
	}

	//�жϽ����Ƿ���X64
	DWORD CurrentPid = ::GetCurrentProcessId();
	if (WinLib::PsIsX64(CurrentPid))
	{
		tcout << _T("Pid:") << CurrentPid << _T(" X64") << std::endl;
	}
	else
	{
		tcout << _T("Pid:") << CurrentPid << _T(" X86") << std::endl;
	}

	//�жϽ����Ƿ����
	if (WinLib::PsIsExisted(CurrentPid))
	{
		tcout << _T("Pid:") << CurrentPid << _T(" IsExisted") << std::endl;
	}

	//�жϽ������Ƿ����
	tstring ProcName = _T("explorer.exe");
	if (WinLib::PsIsNameExisted(ProcName))
	{
		tcout << _T("ProcName:") << ProcName << _T(" IsExisted") << std::endl;
	}

	//��ȡ����·��
	tcout << _T("Pid:") << CurrentPid << _T(" ") << WinLib::PsGetProcessPath(CurrentPid) << std::endl;
	
	//��ȡ�ý���������Pid
	ProcName = _T("svchost.exe");
	std::vector<DWORD> Pids;
	WinLib::PsFindProcessByName(ProcName, Pids);
	for (auto iter = Pids.cbegin(); iter != Pids.cend(); iter++)
	{
		tcout << _T("ProcName:") << ProcName << _T("Pid:") << *iter << std::endl;
	}

	//ͨ����������ȡ����
	DWORD ExporerPid = WinLib::PsGetPidByWindow(_T("Progman"), _T("Program Manager"));
	tcout << _T("PsGetPidByWindow Pid:") << ExporerPid << std::endl;

	//��ȡ�����ӽ���
	std::vector<DWORD> ChildPids;
	if (WinLib::PsGetChildPids(ExporerPid, ChildPids))
	{
		for (auto iter = ChildPids.cbegin(); iter != ChildPids.cend(); iter++)
		{
			tcout << _T("Pid:") << ExporerPid << _T("ChildPid:")  << *iter << std::endl;
		}
	}

	//��ȡ��������
	std::map<DWORD, tstring> ProcNames;
	if (WinLib::PsEnumProcessNames(ProcNames))
	{
		for (auto iter = ProcNames.cbegin(); iter != ProcNames.cend(); iter++)
		{
			tcout << _T("Pid:") << iter->first << _T("Name:") << iter->second << std::endl;
		}
	}

	//��ȡ��������ģ����Ϣ
	std::vector<MODULEENTRY32> Modules;
	if (WinLib::PsEnumModule(CurrentPid, Modules))
	{
		tcout << _T("Pid:") << CurrentPid << std::endl;
		for (auto iter = Modules.cbegin(); iter != Modules.cend(); iter++)
		{
			tcout << _T("DllName:") << iter->szExePath << std::endl;
			tcout << _T("DllBaseAddr:") << iter->modBaseAddr << std::endl;
		}
	}

	//DWORD TestPid = 0x1234;
	//��ͣ����
	//WinLib::PsSuspendProcess(TestPid);
	//��ͣ�߳�
	//WinLib::PsSuspendThread(TestPid);
	//�ָ�����
	//WinLib::PsResumeProcess(TestPid);
	//�ָ��߳�
	//WinLib::PsResumeThread(TestPid);

	//��������
	//WinLib::PsTerminate(TestPid)
	//�������̰�����
	//WinLib::PsTerminateProcessByName(_T("test.exe"));
	
	//��ȡ������Ϣ
	WinLib::PROCESS_BASE_INFO Info;
	if (WinLib::PsGetProcessInfo(CurrentPid, Info))
	{
		tcout << _T("CommandLine:") << Info.CommandLine << std::endl;
		tcout << _T("CurrentDirectory:") << Info.CurrentDirectory << std::endl;
		tcout << _T("ImagePathName:") << Info.ImagePathName << std::endl;
		tcout << _T("WindowTitle:") << Info.WindowTitle << std::endl;
	}

	//�޸Ľ��������в���
	WinLib::PsSetProcessCommandLine(CurrentPid, _T("XXXX"));

	//Զ�߳�ע��
	//PsCreateRemoteThread32(DWORD Pid, ULONG StartAddress, ULONG Parameter, DWORD CreationFlags = 0);
	//PsReadProcessMemory32(DWORD Pid, ULONG Address, PVOID Buffer, ULONG Size, PULONG BytesRead);
	//PsWriteProcessMemory32(DWORD pid, ULONG addr, PVOID buff, ULONG size, SIZE_T* writelen);
}

void WinLibStrTest()
{
	//wchar ת std::string 
	{
		wchar_t* xxx = (wchar_t*)L"xxx";
		std::cout << WinLib::StrToString(xxx) << std::endl;;
	}

	//std::wstring ת std::string 
	{
		std::wstring xxx = L"xxx";
		std::cout << WinLib::StrToString(xxx) << std::endl;;
	}

	//char ת std::wstring 
	{
		char* xxx = (char*)"xxx";
		std::wcout << WinLib::StrToWstring(xxx) << std::endl;;
	}

	//std::string ת std::wstring 
	{
		std::string xxx = "xxx";
		std::wcout << WinLib::StrToWstring(xxx) << std::endl;;
	}

	//gbkתutf-8
	{
		std::cout << WinLib::StrWideToUTF8(WinLib::StrToWstring("ABC")) << std::endl;;
	}

	//UNICODE_STRINGתwstring
	{
		typedef struct _UNICODE_STRING
		{
			USHORT Length;
			USHORT MaximumLength;
			PWSTR  Buffer;
		} UNICODE_STRING, *PUNICODE_STRING;
		UNICODE_STRING Ustr;
		Ustr.Buffer = L"12345";
		Ustr.Length = 10;
		Ustr.Length = 12;
		std::wstring wstr = WinLib::StrUnicodeToWstr(&Ustr);
		std::wcout << wstr << std::endl;
	}

	{
		//��Сдת��
		tstring str = _T("123*xYzBBc");
		str = WinLib::StrToUpper(str);
		tcout << str << std::endl;
		str = WinLib::StrToLower(str);
		tcout << str << std::endl;
	}

	{
		//��������ת�ַ���
		//L"\xAB\xCD\xEF" = > "AB00CD00EF00"
		std::string hexstr = WinLib::StrStreamToHexStr("\xAB\xCD\xEF");
		std::cout << hexstr << std::endl;

		//�ַ���ת��������
		//"AB00CD00EF00" = > L"\xAB\xCD\xEF"
		std::string stream = WinLib::StrHexStrToStream(hexstr);
	}

	{
		//�ַ���ת����
		std::cout << WinLib::StrToHex(L"AB") << std::endl;
		std::cout << WinLib::StrToDecimal(L"100") << std::endl;
		std::cout << WinLib::StrToDecimal64(L"10000") << std::endl;
		std::cout << WinLib::StrToBinary(L"1010") << std::endl;
	}

	{
		//�ַ������� ��Сд������
		if (WinLib::StrFind(_T("ABCDEFG123"), _T("CDe"), true))
		{
			tcout << _T("StrFind") << std::endl;
		}

		std::vector<tstring> vec = { _T("Cde"), _T("123") };
		if (WinLib::StrFind(_T("ABCDEFG123"), vec, true))
		{
			tcout << _T("StrFind") << std::endl;
		}

		//�ַ���ƥ�� ��Сд������
		if (WinLib::StrCompare(_T("ABCDEFG123"), _T("abcdefg123"), true))
		{
			tcout << _T("StrCompare") << std::endl;
		}

		std::vector<tstring> vec2 = { _T("abcdefg123"), _T("abcdefg1234") };
		if (WinLib::StrCompare(_T("ABCDEFG123"), vec2, true))
		{
			tcout << _T("StrCompare") << std::endl;
		}

		//�ַ����滻
		tcout << WinLib::StrReplace(_T("ABCDEFG123"), _T("123"), _T("456")) << std::endl;
	}

	//�ļ�·�������ļ���
	tcout << WinLib::StrPathToName(_T("C:\\windows\\svchost.exe")) << std::endl;
	//�ļ�·������Ŀ¼��
	tcout << WinLib::StrPathToDir(_T("C:\\windows\\svchost.exe")) << std::endl;
	//�ļ���������׺
	tcout << WinLib::StrNameToExt(_T("svchost.exe")) << std::endl;
	//�ļ�����ȥ��׺
	tcout << WinLib::StrNameWithoutExt(_T("svchost.exe")) << std::endl;

	//���������
	tcout << WinLib::StrRandInteger(100, 3000) << std::endl;
	//����ַ��� �ֵ�
	tcout << WinLib::StrRandString(10, _T("1234567890ABCDEFG")) << std::endl;
	//Dos·��תNt·��
	//"C:\Windows\explore.exe" -> "\Device\HarddiskVolume2\Windows\explore.exe"
	tcout << WinLib::StrDosToNtPath(_T("C:\\Windows\\explore.exe")) << std::endl;
	tcout << WinLib::StrNtToDosPath(_T("\\Device\\HarddiskVolume2\\Windows\\explore.exe")) << std::endl;

	{
		//�����з��ָ��ַ���
		std::vector<tstring> vec;
		WinLib::StrSplitLines(_T("123\n456\r\n789\njqk"), vec);

		//��";"�ָ��ַ���
		WinLib::StrSplit(_T("123;222;111;"), _T(";"), vec);
		WinLib::StrSplit(_T("123;222;111;444"), _T(";"), vec);
	}
}

void WinLibOsTest()
{
	//ϵͳ�Ƿ���X64
	if (WinLib::OsIs64())
	{
		tcout << _T("Os X64") << std::endl;
	}
	else
	{
		tcout << _T("Os X86") << std::endl;
	}

	//��ǰ�û���
	tcout << _T("CurrentUserName:") << WinLib::OsCurrentUserName() << std::endl;

	//��ǰ������
	tcout << _T("PcName:") << WinLib::OsPcName() << std::endl;

	//CPU������
	tcout << _T("CPUCount:") << WinLib::OsGetCPUCount() << std::endl;

	//�ڴ��С
	tcout << _T("MemoryMb:") << WinLib::OsGetMemoryMb() << std::endl;

	//��Ļ�ֱ���
	int x, y;
	WinLib::OsGetScreenResolution(x, y);
	tcout << _T("MemoryMb:") << x << _T("x") << y << std::endl;

	//ö�ٴ���
	std::vector<tstring> LogicalDriveNames;
	WinLib::OsEnumLogicalDriveName(LogicalDriveNames);
	for (auto iter = LogicalDriveNames.cbegin(); iter != LogicalDriveNames.cend(); iter++)
	{
		tcout << _T("LogicalDrive:") << *iter << std::endl;
	}

	//�ر�ϵͳ�ض����� ��X86���̿��Զ�дC:\Windows\System32
	PVOID OldValue = 0;
	//WinLib::OsDisableFileRedirection(OldValue);
	//WinLib::OsEnableFileRedirection(OldValue);

	//ϵͳ�汾��
	DWORD MajorVer, MinorVer, BuildNumber;
	WinLib::OsVersionNumber(MajorVer, MinorVer, BuildNumber);
	std::string OsVer = "unknown";
	if (MajorVer == 10)
	{
		OsVer = "Windows 10";
		if (BuildNumber >= 22000)
		{
			OsVer = "Windows 11";
		}
	}
	else if (MajorVer == 6 && MinorVer == 3)
	{
		OsVer = "Windows 8.1";
	}
	else if (MajorVer == 6 && MinorVer == 2)
	{
		OsVer = "Windows 8";
	}
	else if (MajorVer == 6 && MinorVer == 1)
	{
		OsVer = "Windows 7";
	}
	else if (MajorVer == 6 && MinorVer == 0)
	{
		OsVer = "Windows Vista";
	}
	else if (MajorVer == 6 && MinorVer == 0)
	{
		OsVer = "Windows Vista";
	}
	else if (MajorVer == 5 && MinorVer == 2)
	{
		OsVer = "Windows XP 64";
	}
	else if (MajorVer == 5 && MinorVer == 1)
	{
		OsVer = "Windows XP";
	}
	std::cout << "OsVer:" << OsVer << std::endl;
}

void WinLibFsTest()
{
	tstring FilePath = WinLib::OsGetWindowsDirectory() + _T("\\explorer.exe");
	{
		//��ȡ�ļ���С
		DWORD Size = WinLib::FsGetFileSize(FilePath);
		tcout << FilePath << _T(" Size:") << Size << std::endl;

		//��ȡ�ļ���С ����4GB
		DWORD64 Size2 = WinLib::FsGetFileSize64(FilePath);
		tcout << FilePath << _T(" Size:") << Size2 << std::endl;		
	}

	{
		//�ļ��Ƿ����
		WinLib::FsIsFile(_T("c:\\windows\\notepad.exe"));

		//Ŀ¼�Ƿ����
		WinLib::FsIsDirectory(_T("c:\\windows"));
	}

	{
		//д�ļ�
		WinLib::FsWriteFileData(_T("d:\\1.txt"), "txt");

		//�ļ�����׷��
		WinLib::FsAppendFileData(_T("d:\\1.txt"), "txt2");

		//���ļ�
		std::string Data;
		WinLib::FsReadFileData(_T("d:\\1.txt"), Data);
		std::cout << Data << std::endl;
	}

	{
		//��ȡ�ļ���Դ��Ϣ
		WinLib::FILE_RESOURCEINFO ResourceInfo;
		WinLib::FsGetFileResourceInfo(FilePath, ResourceInfo);
		std::cout << "OriginalFileName:" << TSTRTOSTING(ResourceInfo.OriginalFileName) << std::endl;
		std::cout << "FileDescription:" << TSTRTOSTING(ResourceInfo.FileDescription) << std::endl;
		std::cout << "FileVersion:" << TSTRTOSTING(ResourceInfo.FileVersion) << std::endl;
		std::cout << "CompanyName:" << TSTRTOSTING(ResourceInfo.CompanyName) << std::endl;
		std::cout << "InternalName:" << TSTRTOSTING(ResourceInfo.InternalName) << std::endl;
		std::cout << "LegalCopyright:" << TSTRTOSTING(ResourceInfo.LegalCopyright) << std::endl;
		std::cout << "ProductName:" << TSTRTOSTING(ResourceInfo.ProductName) << std::endl;
		std::cout << "ProductVersion:" << TSTRTOSTING(ResourceInfo.ProductVersion) << std::endl;
	}

	{
		//����Ŀ¼
		WinLib::FsCreateDirectory(_T("d:\\123\\456\\789"));

		//ɾ��Ŀ¼
		WinLib::FsDeleteDirectory(_T("d:\\123\\456"));
	}

	{
		//ö��Ŀ¼�ļ�
		std::vector<tstring> Files;
		WinLib::FsEnumDirectoryFiles(_T("c:\\windows"), Files);

		//ö��Ŀ¼
		std::vector<tstring> Dirs;
		WinLib::FsEnumDirectory(_T("c:\\windows"), Dirs);
	}
	
	//�����ļ�����Դ�ļ�
	WinLib::FsUpdataResource(_T("d:\\test.exe"), "asdasd", 101, _T("BMP"));

	//��ȡ�ļ�ʱ����Ϣ
	FILETIME CreateTime, AccessTime, ModifyTime;
	WinLib::FsGetFileTimeInfo(FilePath, CreateTime, AccessTime, ModifyTime);
	FILETIME LocalTime;
	FileTimeToLocalFileTime(&CreateTime, &LocalTime);
	SYSTEMTIME SystemTime;
	FileTimeToSystemTime(&LocalTime, &SystemTime);
	char buf[128] = { 0 };
	sprintf_s(buf, "%04d-%02d-%02d %02d:%02d:%02d:%03d", 
		SystemTime.wYear, SystemTime.wMonth, SystemTime.wDay,
		SystemTime.wHour, SystemTime.wMinute, SystemTime.wSecond, SystemTime.wMilliseconds);
	std::cout << "����ʱ��:" << buf << std::endl;
}

void WinLibNetTest()
{
	WinLib::NetStartSocket();
	//Ip��ȡ
	tcout << _T("GetHostByName:") << WinLib::NetIpToStr(WinLib::NetGetHostByName("www.baidu.com")) << std::endl;

	//Dns��ѯ
	std::map<ULONG, tstring> DnsInfo;
	WinLib::NetGetDnsQuery(_T("www.baidu.com"), DnsInfo);

	//Ip��ȡ����
	std::vector<UINT32> IpList;
	WinLib::NetGetaddrinfo("www.baidu.com", IpList);

	//�ַ���תip
	ULONG Ip = WinLib::NetStrToIp(_T("127.0.0.1"));

	//ipת�ַ���
	tcout << WinLib::NetIpToStr(Ip) << std::endl;;

	//����mac
	tcout << _T("LocalMac:") << WinLib::NetGetMac() << std::endl;

	//����ip
	tcout << _T("LocalIp:") << WinLib::NetIpToStr(WinLib::NetGetIp()) << std::endl;

	//·����mac
	tcout << _T("RouteMac:") << WinLib::NetGetRouterMac() << std::endl;

	//·����Ip
	tcout << _T("RouteIp:") << WinLib::NetGetRouteIP() << std::endl;

	//��ȡ������������Ϣ
	std::vector<WinLib::ADAPTER_INFO> Adapters;
	WinLib::NetGetAdapterInfos(Adapters);
	for (auto iter = Adapters.cbegin(); iter != Adapters.cend(); iter++)
	{
		std::cout << "Description:" << iter->Description << std::endl;
		//iter->Mac
		for (auto iter2 = iter->Gateways.cbegin(); iter2 != iter->Gateways.cend(); iter2++)
		{
			tcout << _T("Gateway:") << WinLib::NetIpToStr(::ntohl(*iter2)) << std::endl;
		}
		for (auto iter2 = iter->Ips.cbegin(); iter2 != iter->Ips.cend(); iter2++)
		{
			tcout << _T("Ip:") << WinLib::NetIpToStr(::ntohl(*iter2)) << std::endl;
		}	
	}

	WinLib::NetCleanSocket();
}

void WinLibSeTest()
{
	//�����ļ�������
	WinLib::SeTakeFileOwnership(WinLib::OsCurrentUserName(), _T("d:\\test.exe"));

	//��ȡ�ļ�Ȩ��
	WinLib::SeSetFileAllowAccess(WinLib::OsCurrentUserName(), _T("d:\\test.exe"));
}

void WinLibMmTest()
{
	//��ȡģ����Դ�ļ�
	std::string ResourceData;
	WinLib::MmReleaseResource(NULL, IDR_TXT1, _T("TXT"), ResourceData);

	//�����ļ�ӳ��
	HANDLE hFileMap = NULL;
	tstring FileMapName = _T("Global\\test2022");
	PCHAR Buf = WinLib::MmCreateFileMapping(FileMapName, (DWORD)4, hFileMap);
	if (Buf)
	{
		RtlCopyMemory(Buf, "123\0", 4);
	}
	//::CloseHandle(hFileMap);

	//������һ�����̴��ļ�ӳ��ʵ�ֽ���ͨ��
	//HANDLE hFileMap = NULL;
	//PCHAR pBuf = WinLib::MmOpenFileMapping(FileMapName, hFileMap);
	//if (pBuf)
	//{
	//	char Buf2[4];
	//	::RtlCopyMemory(Buf2, pBuf, 4);
	//}
}

int _tmain(int argc, _TCHAR* argv[])
{
	WinLibFsTest();
	WinLibOsTest();
	WinLibPsTest();
	WinLibStrTest();
	WinLibNetTest();
	WinLibSeTest();
	WinLibMmTest();

	system("pause");
	return 0;
}


