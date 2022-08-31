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
#include <map>

namespace WinLib
{
	typedef std::basic_string<TCHAR> tstring;

	typedef struct _ADAPTER_INFO
	{
		std::string Description;
		UINT8 Mac[6];
		std::vector<UINT32> Gateways;
		std::vector<UINT32> Ips;
	}ADAPTER_INFO;

	bool 			NetGetAdapterInfos(std::vector<ADAPTER_INFO>& Adapters);
	ULONG 			NetGetHostByName(const std::string& Host);
	tstring 		NetIpToStr(UINT32 Ip);
	ULONG 			NetStrToIp(const tstring& IpStr);
	bool 			NetGetDnsQuery(const tstring Dns, std::map<ULONG, tstring>& DnsInfo);
	tstring 		NetGetMac();
	UINT32 			NetGetIp();
	tstring 		NetGetRouteIP();
	tstring 		NetGetRouterMac();
	bool 			NetStartSocket(WORD Version = MAKEWORD(2, 2));
	bool 			NetCleanSocket();
	bool 			NetGetaddrinfo(const std::string& Domain, std::vector<UINT32>& IpList);
	bool 			NetSendUdp(const char* pBuf, int iLen, UINT32 Ip, USHORT iPort);
}