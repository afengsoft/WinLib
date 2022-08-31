#include "WinLibSe.h"
#include "WinLibOs.h"
#include "WinLibStr.h"

namespace WinLib
{
#define SE_DELALLACCESS_FLAG	L"{55F0FA66-7567-450A-8F39-087ACB43810F}"

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) {   \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
	(p)->RootDirectory = r;                             \
	(p)->Attributes = a;                                \
	(p)->ObjectName = n;                                \
	(p)->SecurityDescriptor = s;                        \
	(p)->SecurityQualityOfService = NULL;               \
}
#endif

#define OBJ_CASE_INSENSITIVE    0x00000040L

#define FILE_OPEN                       0x00000001

#define NT_SUCCESS(Status)								((NTSTATUS)(Status) >= 0)
	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR  Buffer;
	} UNICODE_STRING, *PUNICODE_STRING;

	typedef struct _OBJECT_ATTRIBUTES {
		ULONG Length;
		HANDLE RootDirectory;
		PUNICODE_STRING ObjectName;
		ULONG Attributes;
		PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
		PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
	} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

	typedef struct _IO_STATUS_BLOCK
	{
		union
		{
			NTSTATUS Status;
			PVOID Pointer;
		};
		ULONG_PTR Information;
	} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

	//NtCreateFile
	typedef NTSTATUS(NTAPI *__NTCREATEFILE)(
		OUT PHANDLE FileHandle,
		IN  ACCESS_MASK DesiredAccess,
		IN  POBJECT_ATTRIBUTES ObjectAttributes,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		IN  PLARGE_INTEGER AllocationSize,
		IN  ULONG FileAttributes,
		IN  ULONG ShareAccess,
		IN  ULONG CreateDisposition,
		IN  ULONG CreateOptions,
		IN  PVOID EaBuffer,
		IN  ULONG EaLength);

	typedef VOID(NTAPI* __RtlInitUnicodeString)(
		PUNICODE_STRING DestinationString,
		PCWSTR SourceString
		);

	bool SeAddAccess(PACL& Acl, const tstring& UserName, ACCESS_MASK AccessMask, bool IsAccessAllow)
	{
		bool Result = false;
		PSID Sid = NULL;
		PACL NewAcl = NULL;
		PACCESS_ALLOWED_ACE Ace = NULL;
		DWORD AceIndex;
		BYTE AceType;
		if (IsAccessAllow)
		{
			AceType = ACCESS_ALLOWED_ACE_TYPE;
			AceIndex = MAXDWORD; //允许的ACE添加到ACL尾部
		}
		else
		{
			AceType = ACCESS_DENIED_ACE_TYPE;
			AceIndex = 0;	//拒绝的ACE添加到ACL开头
		}
		do
		{
			if (WinLib::OsGetUserSid(UserName, &Sid) != ERROR_SUCCESS)
			{
				break;
			}

			ACL_SIZE_INFORMATION AclSizeInfo;
			if (!GetAclInformation(Acl, &AclSizeInfo, sizeof(AclSizeInfo), AclSizeInformation))
			{
				break;
			}
			//分配临时ACL
			PACCESS_ALLOWED_ACE TempAce = NULL;
			DWORD NewAclSize = AclSizeInfo.AclBytesInUse + (sizeof(ACCESS_ALLOWED_ACE)) + (GetLengthSid(Sid)) - (sizeof(DWORD));
			NewAcl = (PACL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, NewAclSize);
			if (!NewAcl)
			{
				break;
			}
			//初始化临时ACL
			if (!InitializeAcl(NewAcl, NewAclSize, ACL_REVISION))
			{
				break;
			}
			//拷贝源ACE
			bool IsInsert = true;
			DWORD AceCount = AclSizeInfo.AceCount;
			for (DWORD i = 0; i < AceCount; i++)
			{
				if (!GetAce(Acl, i, (LPVOID*)&TempAce))
				{
					free(Sid);
					HeapFree(GetProcessHeap(), 0, NewAcl);
					return false;
				}
				//过滤掉已有的AccessMask
				if (TempAce->Header.AceType == AceType && EqualSid(Sid, (PSID)&TempAce->SidStart))
				{
					TempAce->Mask |= AccessMask;
					IsInsert = false;
				}
				if (!AddAce(NewAcl, ACL_REVISION, MAXDWORD, TempAce, TempAce->Header.AceSize))
				{
					free(Sid);
					HeapFree(GetProcessHeap(), 0, NewAcl);
					return false;
				}
			}
			if (IsInsert)
			{
				Ace = (ACCESS_ALLOWED_ACE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(Sid) - sizeof(DWORD));
				if (!Ace)
				{
					break;
				}
				Ace->Header.AceType = AceType;
				Ace->Header.AceFlags = CONTAINER_INHERIT_ACE;
				Ace->Header.AceSize = LOWORD(sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(Sid) - sizeof(DWORD));
				Ace->Mask = AccessMask;
				if (!CopySid(GetLengthSid(Sid), &Ace->SidStart, Sid))
				{
					break;
				}
				if (!AddAce(NewAcl, ACL_REVISION, AceIndex, Ace, Ace->Header.AceSize))
				{
					break;
				}
			}

			//返回新的Acl，调用者释放
			Acl = NewAcl;
			NewAcl = NULL;
			Result = true;
		} while (0);
		if (NewAcl)
			HeapFree(GetProcessHeap(), 0, NewAcl);
		if (Ace)
			HeapFree(GetProcessHeap(), 0, Ace);
		if (Sid)
			free(Sid);
		return Result;
	}

	bool SeDelAllAccess(PACL Acl)
	{
		bool Result = true;
		ACL_SIZE_INFORMATION AclSizeInfo;
		PACCESS_ALLOWED_ACE Ace;
		DWORD AceCount = 0;
		do
		{
			if (!GetAclInformation(Acl, &AclSizeInfo, sizeof(AclSizeInfo), AclSizeInformation))
			{
				Result = false;
				break;
			}
			AceCount = AclSizeInfo.AceCount;
			for (DWORD i = 0; i < AceCount; ++i)
			{
				if (!GetAce(Acl, 0, (LPVOID*)&Ace))
				{
					Result = false;
					break;
				}
				if (!DeleteAce(Acl, 0))
				{
					Result = false;
					break;
				}
			}
		} while (0);
		return Result;
	}

	bool SeDelAccess(PACL& Acl, const tstring& UserName, ACCESS_MASK AccessMask, bool IsAccessAllow)
	{
		//UserName == SE_DELALLACCESS_FLAG
		if (WinLib::StrCompare(UserName, SE_DELALLACCESS_FLAG))
			return SeDelAllAccess(Acl);

		bool Result = true;
		PSID Sid = NULL;
		ACL_SIZE_INFORMATION AclSizeInfo;
		PACCESS_ALLOWED_ACE Ace;
		DWORD AceCount = 0;
		BYTE AceType = IsAccessAllow ? ACCESS_ALLOWED_ACE_TYPE : ACCESS_DENIED_ACE_TYPE;
		do
		{
			if (WinLib::OsGetUserSid(UserName, &Sid) != ERROR_SUCCESS)
			{
				Sid = NULL;
				Result = false;
				break;
			}
			if (!GetAclInformation(Acl, &AclSizeInfo, sizeof(AclSizeInfo), AclSizeInformation))
			{
				Result = false;
				break;
			}
			AceCount = AclSizeInfo.AceCount;
			for (DWORD i = 0; i < AceCount; ++i)
			{
				if (GetAce(Acl, i, (LPVOID*)&Ace) == FALSE)
				{
					Result = false;
					break;
				}
				if (Ace->Header.AceType != AceType)
					continue;

				if (!EqualSid(Sid, (PSID)&Ace->SidStart) || !(Ace->Mask & AccessMask))
					continue;

				Ace->Mask &= ~AccessMask;
				if (Ace->Mask != 0)
					continue;

				if (!DeleteAce(Acl, i))
				{
					Result = false;
					break;
				}

				AceCount--;
				i--;
			}
		} while (0);
		if (Sid)
			free(Sid);
		return Result;
	}

	bool SeSetObjectAccess(const tstring& UserName, HANDLE Object, SE_OBJECT_TYPE ObjectType, ACCESS_MASK AccessMask, bool IsAdd, bool IsAccessAllow, bool ForbidInherit)
	{
		bool Result = false;
		bool IsFreeAcl = false;
		PACL Acl = NULL;
		PSECURITY_DESCRIPTOR Sd = NULL;
		do
		{
			if (::GetSecurityInfo(Object, ObjectType, DACL_SECURITY_INFORMATION, NULL, NULL, &Acl, NULL, &Sd) != ERROR_SUCCESS)
			{
				break;
			}

			Result = IsAdd ? SeAddAccess(Acl, UserName, AccessMask, IsAccessAllow) : SeDelAccess(Acl, UserName, AccessMask, IsAccessAllow);
			if (!Result)
			{
				break;
			}

			if (!Acl)
			{
				Result = true;
				break;
			}
			IsFreeAcl = IsAdd;

			SECURITY_INFORMATION SecurityInfo = DACL_SECURITY_INFORMATION;
			if (ForbidInherit)
				SecurityInfo |= PROTECTED_DACL_SECURITY_INFORMATION;

			if (::SetSecurityInfo(Object, ObjectType, SecurityInfo, NULL, NULL, Acl, NULL) != ERROR_SUCCESS)
			{
				break;
			}
			Result = true;
		} while (0);
		if (IsFreeAcl)
			::HeapFree(GetProcessHeap(), 0, Acl);
		if (Sd)
			::LocalFree(Sd);
		return Result;
	}

	bool SeTakeObjectOwnership(const tstring& UserName, HANDLE Object, SE_OBJECT_TYPE ObjectType)
	{
		DWORD Result = ERROR_SUCCESS;
		PSID Sid = NULL;
		do
		{
			Result = OsGetUserSid(UserName, &Sid);
			if (Result != ERROR_SUCCESS)
				break;
			Result = SetSecurityInfo(Object, ObjectType, OWNER_SECURITY_INFORMATION, Sid, NULL, NULL, NULL);
		} while (0);

		if (Sid)
			free(Sid);

		return Result == ERROR_SUCCESS;
	}

/*++
Routine Description:
	[D] 设置文件所有者
	需要SE_TAKE_OWNERSHIP_NAME权限，PsSetPrivilege
Arguments:
	UserName - 用户名
	FilePath - 文件路径
Return Value:
	失败 - false
	成功 - true
--*/
	bool SeTakeFileOwnership(const tstring& UserName, const tstring& FilePath)
	{
		auto pNtCreateFile = (__NTCREATEFILE)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateFile");
		if (!pNtCreateFile) {
			return false;
		}

#ifdef _UNICODE
		std::wstring Tempstr = L"\\??\\" + FilePath;
#else
		std::wstring Tempstr = L"\\??\\" + STRTOTSTING(FilePath);
#endif
		UNICODE_STRING Ustr;
		OBJECT_ATTRIBUTES oa;
		IO_STATUS_BLOCK	isb;
		NTSTATUS Status;
		HANDLE FileHandle;
		bool Result = false;
		auto pRtlInitUnicodeString = (__RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
		if (!pRtlInitUnicodeString) {
			return false;
		}

		pRtlInitUnicodeString(&Ustr, Tempstr.c_str());
		InitializeObjectAttributes(&oa, &Ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
		Status = pNtCreateFile(
			&FileHandle,
			WRITE_OWNER,
			&oa,
			&isb,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			0,
			FILE_OPEN,
			0,
			NULL,
			0);
		if (!NT_SUCCESS(Status))
		{
			return false;
		}
		Result = SeTakeObjectOwnership(UserName.c_str(), FileHandle, SE_FILE_OBJECT);
		CloseHandle(FileHandle);
		return Result;
	}

/*++
Routine Description:
	设置文件允许访问
	N.B.
	文件写权限:FILE_WRITE_DATA（基本）
	文件读权限:FILE_READ_DATA（基本）
Arguments:
	UserName - 用户名
	FilePath - 文件路径
	DesiredAccess - 允许的权限，默认是GENERIC_ALL
	DelAllAccess - 表示删除所有权限（阻止继承）,再给当前用户添加允许权限
Return Value:
	失败 - false
	成功 - true
--*/
	bool SeSetFileAllowAccess(const tstring& UserName, const tstring& FilePath, DWORD DesiredAccess, bool DelAllAccess)
	{
		auto pNtCreateFile = (__NTCREATEFILE)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateFile");
		if (!pNtCreateFile)
			return false;
		std::wstring Tempstr = L"\\??\\" + FilePath;
		UNICODE_STRING Ustr;
		OBJECT_ATTRIBUTES oa;
		IO_STATUS_BLOCK	isb;
		NTSTATUS Status;
		HANDLE FileHandle;
		bool Result = false;
		auto pRtlInitUnicodeString = (__RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
		if (!pRtlInitUnicodeString)
			return false;
		pRtlInitUnicodeString(&Ustr, Tempstr.c_str());
		InitializeObjectAttributes(&oa, &Ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
		Status = pNtCreateFile(
			&FileHandle,
			WRITE_DAC | READ_CONTROL,
			&oa,
			&isb,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			0,
			FILE_OPEN,
			0,
			NULL,
			0);
		if (!NT_SUCCESS(Status))
			return false;

		if (DelAllAccess)
		{
			//删除所有权限（阻止继承），再给当前用户添加允许权限
			if (SeSetObjectAccess(SE_DELALLACCESS_FLAG, FileHandle, SE_FILE_OBJECT, DesiredAccess, false, false, true)
				&& SeSetObjectAccess(OsCurrentUserName(), FileHandle, SE_FILE_OBJECT, DesiredAccess, true, true))
				Result = true;
		}
		else
		{
			//先删除拒绝权限，再增加允许权限
			if (SeSetObjectAccess(UserName, FileHandle, SE_FILE_OBJECT, DesiredAccess, false, false) &&
				SeSetObjectAccess(UserName, FileHandle, SE_FILE_OBJECT, DesiredAccess, true, true))
				Result = true;
		}
		::CloseHandle(FileHandle);
		return Result;
	}

	/*++
	Routine Description:
		设置文件拒绝访问
		N.B.
		文件写权限:FILE_WRITE_DATA（基本）
		文件读权限:FILE_READ_DATA（基本）
	Arguments:
		UserName - 用户名，为(SE_DELALLACCESS_FLAG宏定义)表示删除所有权限（阻止继承）
		FilePath - 文件路径
		DesiredAccess - 拒绝的权限，默认是GENERIC_ALL
	Return Value:
		失败 - false
		成功 - true
	--*/
	bool SeSetFileDenyAccess(const tstring& UserName, const tstring& FilePath, DWORD DesiredAccess, bool DelAllAccess)
	{
		auto pNtCreateFile = (__NTCREATEFILE)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateFile");
		if (!pNtCreateFile)
			return false;
		std::wstring Tempstr = L"\\??\\" + FilePath;
		UNICODE_STRING Ustr;
		OBJECT_ATTRIBUTES oa;
		IO_STATUS_BLOCK	isb;
		NTSTATUS Status;
		HANDLE FileHandle;
		bool Result = false;
		auto pRtlInitUnicodeString = (__RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
		if (!pRtlInitUnicodeString)
			return false;
		pRtlInitUnicodeString(&Ustr, Tempstr.c_str());
		InitializeObjectAttributes(&oa, &Ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
		Status = pNtCreateFile(
			&FileHandle,
			WRITE_DAC | READ_CONTROL,
			&oa,
			&isb,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			0,
			FILE_OPEN,
			0,
			NULL,
			0);
		if (!NT_SUCCESS(Status))
			return false;

		if (DelAllAccess)
		{
			//删除所有权限（阻止继承）
			Result = SeSetObjectAccess(UserName, FileHandle, SE_FILE_OBJECT, DesiredAccess, false, false, true);
		}
		else
		{
			//增加拒绝权限
			Result = SeSetObjectAccess(UserName, FileHandle, SE_FILE_OBJECT, DesiredAccess, true, false);
		}
		::CloseHandle(FileHandle);
		return Result;
	}
}