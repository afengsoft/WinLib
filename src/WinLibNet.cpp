//winsock2
#include <winsock2.h>
#include <Ws2tcpip.h>
#include "WinLibNet.h"
//Windows SDK
#include <iphlpapi.h>
#include <WinDNS.h>
//Other
#include "WinLibStr.h"
#include "WinLibOs.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment (lib, "Dnsapi.lib")

namespace WinLib
{
	ULONG NetGetHostByName(const std::string& Host)
	{
		if (Host.empty()) {
			return 0;
		}

		HOSTENT *pHostEnt = ::gethostbyname(Host.c_str());
		if (pHostEnt == NULL || pHostEnt->h_length != sizeof(in_addr) || pHostEnt->h_addrtype != 2) {
			return 0;
		}

		ULONG ulHash;
		if (pHostEnt->h_addr_list[0] != NULL)
		{
			RtlCopyMemory(&ulHash, pHostEnt->h_addr_list[0], pHostEnt->h_length);
			return ulHash;
		}
		return 0;
	}

	tstring NetIpToStr(UINT32 Ip)
	{
		struct in_addr Addr;
		Addr.S_un.S_addr = Ip;
		return STRTOTSTING(inet_ntoa(Addr));
	}

	ULONG NetStrToIp(const tstring& IpStr)
	{
		return inet_addr(TSTRTOSTING(IpStr).c_str());
	}

	bool NetGetDnsQuery(const tstring Dns, std::map<ULONG, tstring>& DnsInfo)
	{
		PDNS_RECORD pResult = NULL;
		DNS_STATUS dnsStatus = 0;

		dnsStatus = ::DnsQuery(Dns.c_str(), DNS_TYPE_A,
			DNS_QUERY_STANDARD, NULL, &pResult, NULL);
		if (pResult == NULL) {
			return false;
		}
		PDNS_RECORD pTmpResult = pResult;
		while (pTmpResult)
		{
			IN_ADDR ipaddr;
			ipaddr.S_un.S_addr = pTmpResult->Data.A.IpAddress;
			DnsInfo.insert(std::pair<ULONG, tstring>(ipaddr.S_un.S_addr, Dns));
			pTmpResult = pTmpResult->pNext;
		}
		::DnsRecordListFree(pResult, DnsFreeRecordListDeep);
		return true;
	}

	bool NetGetAdapterInfos(std::vector<ADAPTER_INFO>& Adapters)
	{
		PIP_ADAPTER_INFO AdapterInfo;
		PIP_ADAPTER_INFO Adapter = NULL;
		AdapterInfo = (IP_ADAPTER_INFO*)::malloc(sizeof(IP_ADAPTER_INFO));
		ULONG OutBufLen = sizeof(IP_ADAPTER_INFO);
		if (AdapterInfo == NULL) {
			return false;
		}
		if (::GetAdaptersInfo(AdapterInfo, &OutBufLen) != ERROR_SUCCESS) {
			::free(AdapterInfo);
			AdapterInfo = (IP_ADAPTER_INFO*)::malloc(OutBufLen);
		}

		bool Ret = false;
		if (::GetAdaptersInfo(AdapterInfo, &OutBufLen) == ERROR_SUCCESS)
		{
			Adapter = AdapterInfo;
			while (Adapter)
			{
				if (Adapter->Type == MIB_IF_TYPE_ETHERNET)
				{
					if (Adapter->AddressLength == 6)
					{
						WinLib::ADAPTER_INFO Info;
						Info.Description = Adapter->Description;
						RtlCopyMemory(Info.Mac, Adapter->Address, sizeof(Info.Mac));

						_IP_ADDR_STRING* IpAddress = &Adapter->IpAddressList;
						while (IpAddress)
						{
							Info.Ips.push_back(::htonl(IpAddress->Context));
							IpAddress = IpAddress->Next;
						}
						_IP_ADDR_STRING* Gateway = &Adapter->GatewayList;
						while (Gateway)
						{
							Info.Gateways.push_back(::htonl(Gateway->Context));
							Gateway = Gateway->Next;
						}

						Adapters.push_back(Info);
					}
				}
				Adapter = Adapter->Next;
			}
			Ret = true;
		}
		if (AdapterInfo != NULL) {
			::free(AdapterInfo);
		}
		return Ret;
	}

	tstring NetGetMac()
	{
		tstring MacStr;
		std::vector<ADAPTER_INFO> Adapters;
		if (NetGetAdapterInfos(Adapters)
			&& !Adapters.empty())
		{
			TCHAR Buffer[64] = { 0 };
			_stprintf_s(Buffer, 64, _T("%02X-%02X-%02X-%02X-%02X-%02X"),
				Adapters[0].Mac[0],
				Adapters[0].Mac[1],
				Adapters[0].Mac[2],
				Adapters[0].Mac[3],
				Adapters[0].Mac[4],
				Adapters[0].Mac[5]);
			MacStr = Buffer;
		}
		return MacStr;
	}

	UINT32 NetGetIp()
	{
		std::vector<UINT32> IpList;	
		if (NetGetaddrinfo(TSTRTOSTING(WinLib::OsPcName()), IpList)
			&& !IpList.empty())
		{		
			return IpList[0];				
		}
		return 0;
	}

	void FreeIpForwardTable(PMIB_IPFORWARDTABLE pIpRouteTab)
	{
		if (pIpRouteTab != NULL)
			::GlobalFree(pIpRouteTab);
	}

	PMIB_IPFORWARDTABLE GetIpForwardTable(BOOL bOrder)
	{
		PMIB_IPFORWARDTABLE pIpRouteTab = NULL;
		DWORD dwActualSize = 0;
		if (::GetIpForwardTable(pIpRouteTab, &dwActualSize, bOrder) == ERROR_INSUFFICIENT_BUFFER)
		{
			pIpRouteTab = (PMIB_IPFORWARDTABLE)::GlobalAlloc(GPTR, dwActualSize);
			if (::GetIpForwardTable(pIpRouteTab, &dwActualSize, bOrder) == NO_ERROR)
				return pIpRouteTab;
			::GlobalFree(pIpRouteTab);
		}

		return NULL;
	}

	tstring NetGetRouteIP()
	{
		PMIB_IPFORWARDTABLE pIpRouteTable = GetIpForwardTable(TRUE);
		if (pIpRouteTable != NULL)
		{
			struct in_addr inadGateway;
			PMIB_IPADDRTABLE pIpAddrTable = NULL;

			if (pIpRouteTable->dwNumEntries > 0)
			{
				inadGateway.s_addr = pIpRouteTable->table[0].dwForwardNextHop;
				return STRTOTSTING(::inet_ntoa(inadGateway));
			}

			FreeIpForwardTable(pIpRouteTable);
		}
		return _T("");
	}

	tstring NetGetRouterMac()
	{
		u_char arDestMac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
		ULONG ulLen = 6;
		tstring ip = NetGetRouteIP();

		TCHAR wmck[64] = { 0 };
		if (::SendARP(::inet_addr(TSTRTOSTING(ip).c_str()), 0, (ULONG*)arDestMac, &ulLen) == NO_ERROR)
		{
			u_char* p = arDestMac;
			_stprintf_s(wmck, 64, _T("%02X-%02X-%02X-%02X-%02X-%02X"), p[0], p[1], p[2], p[3], p[4], p[5]);
		}
		return wmck;
	}

	bool NetStartSocket(WORD Version)
	{
		WSADATA WsaData;
		int Ret = ::WSAStartup(Version, &WsaData);
		if (Ret != 0) {
			return false;
		}
		return true;
	}

	bool NetCleanSocket()
	{
		::WSACleanup();
		return true;
	}

	bool NetGetaddrinfo(const std::string& Domain, std::vector<UINT32>& IpList)
	{
		bool Retval = false;
		if (NetStartSocket()) {
			struct addrinfo *AddrInfo = NULL;
			struct addrinfo *Res = NULL;
			struct addrinfo Hints = { 0 };
			Hints.ai_family = AF_UNSPEC;
			Hints.ai_socktype = SOCK_STREAM;
			Hints.ai_protocol = IPPROTO_TCP;
			int Sockret = ::getaddrinfo(Domain.c_str(), NULL, &Hints, &Res);
			if (Sockret == 0) {
				for (AddrInfo = Res; AddrInfo != NULL; AddrInfo = AddrInfo->ai_next)
				{
					switch (AddrInfo->ai_family)
					{
					case AF_INET:
						sockaddr_in* Sockaddr = (struct sockaddr_in*)AddrInfo->ai_addr;
						if (Sockaddr != NULL) {
							IpList.push_back(Sockaddr->sin_addr.S_un.S_addr);
						}
					}
				}
				::freeaddrinfo(Res);
				Retval = true;
			}

			NetCleanSocket();
		}
		return Retval;
	}

	bool NetSendUdp(const char* pBuf, int iLen, UINT32 Ip, USHORT iPort)
	{
		bool ret = false;
		if (pBuf != NULL && iLen != 0)
		{
			SOCKET m_sUdpClient = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (m_sUdpClient != INVALID_SOCKET)
			{
				struct sockaddr_in addr = { 0 };
				addr.sin_family = AF_INET;
				addr.sin_port = ::htons(iPort);
				addr.sin_addr.S_un.S_addr = Ip;
				if (SOCKET_ERROR != ::sendto(m_sUdpClient, pBuf, iLen, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)))
				{
					ret = true;
				}
				::closesocket(m_sUdpClient);
			}
		}
		return ret;
	}
}