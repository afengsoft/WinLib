# WinLib
Windows Api Enclosing C++ Library
	
Windows Api 封装 C++ 库

还在天天翻MSDN看API参数吗，还在无数次的造轮子吗，还在一个项目里面看见各种版本的封装库吗，还在天天和同事撕逼吗，还在加班调试自己写的BUG吗。

有了这个库，一切烦恼皆没有，6点下班。

包含操作系统相关、网络、进程、文件、内存、字符串等常见winapi封装。

一些代码演示：

———————————————————————————————————————————————
	
#include "WinLibOs.h"
	
	//系统是否是X64
	WinLib::OsIs64()

	//当前用户名
	tcout << _T("CurrentUserName:") << WinLib::OsCurrentUserName() << std::endl;

	//当前机器名
	tcout << _T("PcName:") << WinLib::OsPcName() << std::endl;

	//CPU核心数
	tcout << _T("CPUCount:") << WinLib::OsGetCPUCount() << std::endl;

	//内存大小
	tcout << _T("MemoryMb:") << WinLib::OsGetMemoryMb() << std::endl;

	//屏幕分辨率
	WinLib::OsGetScreenResolution(x, y);

	//枚举磁盘
	std::vector<tstring> LogicalDriveNames;
	WinLib::OsEnumLogicalDriveName(LogicalDriveNames);

	//关闭系统重定向功能 让X86进程可以读写C:\Windows\System32
	PVOID OldValue = 0;
	//WinLib::OsDisableFileRedirection(OldValue);
	//WinLib::OsEnableFileRedirection(OldValue);

	//系统版本号
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
	//...
	std::cout << "OsVer:" << OsVer << std::endl;
———————————————————————————————————————————————
	
#include "WinLibSe.h"
	
	//设置文件所有者
	WinLib::SeTakeFileOwnership(WinLib::OsCurrentUserName(), _T("d:\\test.exe"));

	//获取文件权限
	WinLib::SeSetFileAllowAccess(WinLib::OsCurrentUserName(), _T("d:\\test.exe"));
———————————————————————————————————————————————
	
#include "WinLibFs.h"
	
	//获取文件大小
	tstring FilePath = WinLib::OsGetWindowsDirectory() + _T("\\explorer.exe");
	DWORD Size = WinLib::FsGetFileSize(FilePath);
	tcout << FilePath << _T(" Size:") << Size << std::endl;

	//获取文件大小 超过4GB
	DWORD64 Size2 = WinLib::FsGetFileSize64(FilePath);
	tcout << FilePath << _T(" Size:") << Size2 << std::endl;		

	//文件是否存在
	WinLib::FsIsFile(_T("c:\\windows\\notepad.exe"));

	//目录是否存在
	WinLib::FsIsDirectory(_T("c:\\windows"));

	//写文件
	WinLib::FsWriteFileData(_T("d:\\1.txt"), "txt");

	//文件内容追加
	WinLib::FsAppendFileData(_T("d:\\1.txt"), "txt2");

	//读文件
	std::string Data;
	WinLib::FsReadFileData(_T("d:\\1.txt"), Data);
	std::cout << Data << std::endl;

	//获取文件资源信息
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

	//创建目录
	WinLib::FsCreateDirectory(_T("d:\\123\\456\\789"));

	//删除目录
	WinLib::FsDeleteDirectory(_T("d:\\123\\456"));

	//枚举目录文件
	std::vector<tstring> Files;
	WinLib::FsEnumDirectoryFiles(_T("c:\\windows"), Files);

	//枚举目录
	std::vector<tstring> Dirs;
	WinLib::FsEnumDirectory(_T("c:\\windows"), Dirs);	
	
	//更新文件的资源文件
	WinLib::FsUpdataResource(_T("d:\\test.exe"), "asdasd", 101, _T("BMP"));

	//获取文件时间信息
	FILETIME CreateTime, AccessTime, ModifyTime;
	WinLib::FsGetFileTimeInfo(FilePath, CreateTime, AccessTime, ModifyTime);
———————————————————————————————————————————————
	
#include "WinLibMm.h"
	
	//读取模块资源文件
	std::string ResourceData;
	WinLib::MmReleaseResource(NULL, IDR_TXT1, _T("TXT"), ResourceData);

	//创建文件映射
	HANDLE hFileMap = NULL;
	tstring FileMapName = _T("Global\\test2022");
	PCHAR Buf = WinLib::MmCreateFileMapping(FileMapName, (DWORD)4, hFileMap);
	if (Buf)
	{
		RtlCopyMemory(Buf, "123\0", 4);
	}
	//::CloseHandle(hFileMap);

	//在另外一个进程打开文件映射实现进程通信
	//HANDLE hFileMap = NULL;
	//PCHAR pBuf = WinLib::MmOpenFileMapping(FileMapName, hFileMap);
	//if (pBuf)
	//{
	//	char Buf2[4];
	//	::RtlCopyMemory(Buf2, pBuf, 4);
	//}


———————————————————————————————————————————————
	
#include "WinLibNet.h"
	
	//Ip获取
	tcout << _T("GetHostByName:") << WinLib::NetIpToStr(WinLib::NetGetHostByName("www.baidu.com")) << std::endl;

	//Dns查询
	std::map<ULONG, tstring> DnsInfo;
	WinLib::NetGetDnsQuery(_T("www.baidu.com"), DnsInfo);

	//Ip获取所有
	std::vector<UINT32> IpList;
	WinLib::NetGetaddrinfo("www.baidu.com", IpList);

	//字符串转ip
	ULONG Ip = WinLib::NetStrToIp(_T("127.0.0.1"));

	//ip转字符串
	tcout << WinLib::NetIpToStr(Ip) << std::endl;;

	//本地mac
	tcout << _T("LocalMac:") << WinLib::NetGetMac() << std::endl;

	//本地ip
	tcout << _T("LocalIp:") << WinLib::NetIpToStr(WinLib::NetGetIp()) << std::endl;

	//路由器mac
	tcout << _T("RouteMac:") << WinLib::NetGetRouterMac() << std::endl;

	//路由器Ip
	tcout << _T("RouteIp:") << WinLib::NetGetRouteIP() << std::endl;

	//获取网络适配器信息
	std::vector<WinLib::ADAPTER_INFO> Adapters;
	WinLib::NetGetAdapterInfos(Adapters);

———————————————————————————————————————————————
	

#include "WinLibStr.h"
	
	//wchar 转 std::string 
	{
		wchar_t* xxx = (wchar_t*)L"xxx";
		std::cout << WinLib::StrToString(xxx) << std::endl;;
	}

	//std::wstring 转 std::string 
	{
		std::wstring xxx = L"xxx";
		std::cout << WinLib::StrToString(xxx) << std::endl;;
	}

	//char 转 std::wstring 
	{
		char* xxx = (char*)"xxx";
		std::wcout << WinLib::StrToWstring(xxx) << std::endl;;
	}

	//std::string 转 std::wstring 
	{
		std::string xxx = "xxx";
		std::wcout << WinLib::StrToWstring(xxx) << std::endl;;
	}

	//gbk转utf-8
	{
		std::cout << WinLib::StrWideToUTF8(WinLib::StrToWstring("ABC")) << std::endl;;
	}

	{
		//大小写转换
		tstring str = _T("123*xYzBBc");
		str = WinLib::StrToUpper(str);
		tcout << str << std::endl;
		str = WinLib::StrToLower(str);
		tcout << str << std::endl;
	}

	{
		//二进制流转字符串
		//L"\xAB\xCD\xEF" = > "AB00CD00EF00"
		std::string hexstr = WinLib::StrStreamToHexStr("\xAB\xCD\xEF");
		std::cout << hexstr << std::endl;

		//字符串转二进制流
		//"AB00CD00EF00" = > L"\xAB\xCD\xEF"
		std::string stream = WinLib::StrHexStrToStream(hexstr);
	}

	{
		//字符串转整型
		std::cout << WinLib::StrToHex(L"AB") << std::endl;
		std::cout << WinLib::StrToDecimal(L"100") << std::endl;
		std::cout << WinLib::StrToDecimal64(L"10000") << std::endl;
		std::cout << WinLib::StrToBinary(L"1010") << std::endl;
	}

	{
		//字符串查找 大小写不敏感
		if (WinLib::StrFind(_T("ABCDEFG123"), _T("CDe"), true))
		{
			tcout << _T("StrFind") << std::endl;
		}

		std::vector<tstring> vec = { _T("Cde"), _T("123") };
		if (WinLib::StrFind(_T("ABCDEFG123"), vec, true))
		{
			tcout << _T("StrFind") << std::endl;
		}

		//字符串匹配 大小写不敏感
		if (WinLib::StrCompare(_T("ABCDEFG123"), _T("abcdefg123"), true))
		{
			tcout << _T("StrCompare") << std::endl;
		}

		std::vector<tstring> vec2 = { _T("abcdefg123"), _T("abcdefg1234") };
		if (WinLib::StrCompare(_T("ABCDEFG123"), vec2, true))
		{
			tcout << _T("StrCompare") << std::endl;
		}

		//字符串替换
		tcout << WinLib::StrReplace(_T("ABCDEFG123"), _T("123"), _T("456")) << std::endl;
	}

	//文件路径保留文件名
	tcout << WinLib::StrPathToName(_T("C:\\windows\\svchost.exe")) << std::endl;
	//文件路径保留目录名
	tcout << WinLib::StrPathToDir(_T("C:\\windows\\svchost.exe")) << std::endl;
	//文件名保留后缀
	tcout << WinLib::StrNameToExt(_T("svchost.exe")) << std::endl;
	//文件名除去后缀
	tcout << WinLib::StrNameWithoutExt(_T("svchost.exe")) << std::endl;

	//随机数整型
	tcout << WinLib::StrRandInteger(100, 3000) << std::endl;
	//随机字符串 字典
	tcout << WinLib::StrRandString(10, _T("1234567890ABCDEFG")) << std::endl;
	//Dos路径转Nt路径
	//"C:\Windows\explore.exe" -> "\Device\HarddiskVolume2\Windows\explore.exe"
	tcout << WinLib::StrDosToNtPath(_T("C:\\Windows\\explore.exe")) << std::endl;
	tcout << WinLib::StrNtToDosPath(_T("\\Device\\HarddiskVolume2\\Windows\\explore.exe")) << std::endl;


———————————————————————————————————————————————
	
#include "WinLibPs.h"
	
	//枚举进程Pid
	{
		std::vector<DWORD> Pids;
		WinLib::PsEnumProcessId(Pids);
		for (auto iter = Pids.cbegin(); iter != Pids.cend(); iter++)
		{
			tcout << _T("Pid:") << *iter << std::endl;
		}
	}

	//判断进程是否是X64
	DWORD CurrentPid = ::GetCurrentProcessId();
	if (WinLib::PsIsX64(CurrentPid))
	{
		tcout << _T("Pid:") << CurrentPid << _T(" X64") << std::endl;
	}
	else
	{
		tcout << _T("Pid:") << CurrentPid << _T(" X86") << std::endl;
	}

	//判断进程是否存在
	if (WinLib::PsIsExisted(CurrentPid))
	{
		tcout << _T("Pid:") << CurrentPid << _T(" IsExisted") << std::endl;
	}

	//判断进程名是否存在
	tstring ProcName = _T("explorer.exe");
	if (WinLib::PsIsNameExisted(ProcName))
	{
		tcout << _T("ProcName:") << ProcName << _T(" IsExisted") << std::endl;
	}

	//获取进程路径
	tcout << _T("Pid:") << CurrentPid << _T(" ") << WinLib::PsGetProcessPath(CurrentPid) << std::endl;
	
	//获取该进程名所有Pid
	ProcName = _T("svchost.exe");
	std::vector<DWORD> Pids;
	WinLib::PsFindProcessByName(ProcName, Pids);
	for (auto iter = Pids.cbegin(); iter != Pids.cend(); iter++)
	{
		tcout << _T("ProcName:") << ProcName << _T("Pid:") << *iter << std::endl;
	}

	//通过窗口名获取进程
	DWORD ExporerPid = WinLib::PsGetPidByWindow(_T("Progman"), _T("Program Manager"));
	tcout << _T("PsGetPidByWindow Pid:") << ExporerPid << std::endl;

	//获取所有子进程
	std::vector<DWORD> ChildPids;
	if (WinLib::PsGetChildPids(ExporerPid, ChildPids))
	{
		for (auto iter = ChildPids.cbegin(); iter != ChildPids.cend(); iter++)
		{
			tcout << _T("Pid:") << ExporerPid << _T("ChildPid:")  << *iter << std::endl;
		}
	}

	//获取进程名字
	std::map<DWORD, tstring> ProcNames;
	if (WinLib::PsEnumProcessNames(ProcNames))
	{
		for (auto iter = ProcNames.cbegin(); iter != ProcNames.cend(); iter++)
		{
			tcout << _T("Pid:") << iter->first << _T("Name:") << iter->second << std::endl;
		}
	}

	//获取进程所有模块信息
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
	//暂停进程
	//WinLib::PsSuspendProcess(TestPid);
	//暂停线程
	//WinLib::PsSuspendThread(TestPid);
	//恢复进程
	//WinLib::PsResumeProcess(TestPid);
	//恢复线程
	//WinLib::PsResumeThread(TestPid);

	//结束进程
	//WinLib::PsTerminate(TestPid)
	//结束进程按名字
	//WinLib::PsTerminateProcessByName(_T("test.exe"));
	
	//获取进程信息
	WinLib::PROCESS_BASE_INFO Info;
	if (WinLib::PsGetProcessInfo(CurrentPid, Info))
	{
		tcout << _T("CommandLine:") << Info.CommandLine << std::endl;
		tcout << _T("CurrentDirectory:") << Info.CurrentDirectory << std::endl;
		tcout << _T("ImagePathName:") << Info.ImagePathName << std::endl;
		tcout << _T("WindowTitle:") << Info.WindowTitle << std::endl;
	}

	//修改进程命令行参数
	WinLib::PsSetProcessCommandLine(CurrentPid, _T("XXXX"));

	//远线程注入
	//PsCreateRemoteThread32(DWORD Pid, ULONG StartAddress, ULONG Parameter, DWORD CreationFlags = 0);
	//PsReadProcessMemory32(DWORD Pid, ULONG Address, PVOID Buffer, ULONG Size, PULONG BytesRead);
	//PsWriteProcessMemory32(DWORD pid, ULONG addr, PVOID buff, ULONG size, SIZE_T* writelen);
