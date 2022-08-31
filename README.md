# WinLib
Windows Api Enclosing C++ Library
Windows Api 封装 C++ 库

#include "WinLibOs.h"
//系统是否是X64
	if (WinLib::OsIs64())

	//当前用户名
	tcout << _T("CurrentUserName:") << WinLib::OsCurrentUserName() << std::endl;

	//当前机器名
	tcout << _T("PcName:") << WinLib::OsPcName() << std::endl;

	//CPU核心数
	tcout << _T("CPUCount:") << WinLib::OsGetCPUCount() << std::endl;

	//内存大小
	tcout << _T("MemoryMb:") << WinLib::OsGetMemoryMb() << std::endl;

	//屏幕分辨率
	int x, y;
	WinLib::OsGetScreenResolution(x, y);
	tcout << _T("MemoryMb:") << x << _T("x") << y << std::endl;

	//枚举磁盘
	std::vector<tstring> LogicalDriveNames;
	WinLib::OsEnumLogicalDriveName(LogicalDriveNames);
	for (auto iter = LogicalDriveNames.cbegin(); iter != LogicalDriveNames.cend(); iter++)
	{
		tcout << _T("LogicalDrive:") << *iter << std::endl;
	}

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

#include "WinLibSe.h"
//设置文件所有者
//获取文件权限

#include "WinLibMm.h"
//读取模块资源文件
//创建文件映射

#include "WinLibNet.h"

#include "WinLibStr.h"
#include "WinLibPs.h"
