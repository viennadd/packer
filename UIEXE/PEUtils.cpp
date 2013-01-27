#include "stdafx.h"
#include "PEUtils.h"


/*
#include "../zlib-1.2.7/zlib.h"

#pragma comment(lib, "zlibstat")
*/
#include "../aplib.h"
#pragma comment(lib, "../aplib")


PEUtils::PEUtils(void)
{
	m_pImageBase = NULL;
}


PEUtils::~PEUtils(void)
{
	
}

PEUtils::PEUtils(WCHAR *lpImagePath)
{
	PEUtils();
	wcscpy(m_szImagePath, lpImagePath);

	if (pkLoadImage( lpImagePath )) {
		/*
			干点什么
		*/
	} else {
		;
	}
}

BOOL PEUtils::pkLoadImage(WCHAR *lpImagePath)
{
	DWORD dwReaded = 0;
	HANDLE hImage = CreateFile(
		lpImagePath,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hImage == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	/*
		初始化FileSize, ImageBase, ImageSize
	*/
	m_dwFileSize = GetFileSize(hImage, NULL);

	PIMAGE_DOS_HEADER pDosHeader = new IMAGE_DOS_HEADER;
	ReadFile(hImage, pDosHeader, sizeof(IMAGE_DOS_HEADER), &dwReaded, NULL);
	SetFilePointer(hImage, pDosHeader->e_lfanew, NULL, FILE_BEGIN);

	PIMAGE_NT_HEADERS pNtHeader = new IMAGE_NT_HEADERS;
	ReadFile(hImage, pNtHeader, sizeof(IMAGE_NT_HEADERS), &dwReaded, NULL);
	m_dwImageSize = pNtHeader->OptionalHeader.SizeOfImage;

	// 这里需要再增加stub的体积，，不然在内存中增加区段放stub时就越届了。。。
	m_dwImageSize += 9216;	
	m_dwImageSize = round_up(m_dwImageSize, pNtHeader->OptionalHeader.SectionAlignment);

	/*
		分配内存给ImageBase
	*/
	m_pImageBase = (DWORD)new byte[m_dwImageSize];
	ZeroMemory((PVOID)m_pImageBase, m_dwImageSize);

	/*
		分配了内存后，把不受数据对齐影响的数据(DOS头+NT头+区段数组)复制进来
		和把成员NT Header指向我们分配的内存中的对应位置
		这部分的大小刚好有个结构成员写了出来
	*/
	DWORD dwHeadersSize = pNtHeader->OptionalHeader.SizeOfHeaders;
	SetFilePointer(hImage, 0, NULL, FILE_BEGIN);
	ReadFile(hImage, (PVOID)m_pImageBase, dwHeadersSize, &dwReaded, NULL);
	m_pNtHeader = (PIMAGE_NT_HEADERS)(m_pImageBase + pDosHeader->e_lfanew);

	/*
		初始化Section Header起始地址
	
	DWORD dwSizeOfNtHeader = 
			sizeof(m_pNtHeader->FileHeader)
		+	sizeof(m_pNtHeader->Signature)
		+	m_pNtHeader->FileHeader.SizeOfOptionalHeader;  // 谁叫不一定是16个data dictionary呢，确认实际大小
	*/
	// 指向内存中PE头的区段头数组起始地址
	// 原来有个宏可以简单点
	m_pSectionHeader = IMAGE_FIRST_SECTION( m_pNtHeader );
		

	/*
		复制各区段到已分配的内存
	*/
	DWORD dwVA		= NULL;
	DWORD dwRSize	= 0;
	DWORD dwROffset	= 0;
	DWORD nSection	= m_pNtHeader->FileHeader.NumberOfSections;

	for (int i = 0; i < nSection; ++i) {
		dwVA		= m_pSectionHeader[i].VirtualAddress + m_pImageBase;
		dwRSize		= m_pSectionHeader[i].SizeOfRawData;
		dwROffset	= m_pSectionHeader[i].PointerToRawData; 
		
		SetFilePointer(hImage, dwROffset, NULL, FILE_BEGIN);
		ReadFile(hImage, (PVOID)dwVA, dwRSize, &dwReaded, NULL);
	}

	CloseHandle( hImage );
	return TRUE;
}


DWORD PEUtils::round_up(DWORD x, DWORD y)
{
	// return (x + y - 1) / y * y;
	// 感谢炉子解释这段取整
	return (x + y - 1) & ~(y - 1);
}


DWORD PEUtils::GetEntryPoint(void)
{
	return m_pNtHeader->OptionalHeader.AddressOfEntryPoint;
}


PIMAGE_IMPORT_DESCRIPTOR PEUtils::GetImportDescriptor(void)
{
	return (PIMAGE_IMPORT_DESCRIPTOR)
		(GetDataDirectoryRVA(IMAGE_DIRECTORY_ENTRY_IMPORT) + m_pImageBase);
}


PIMAGE_THUNK_DATA PEUtils::GetFirstThunkData(PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor)
{
	return (PIMAGE_THUNK_DATA)
		(pImportDescriptor->FirstThunk + m_pImageBase);
}

PIMAGE_THUNK_DATA PEUtils::GetOriginThunkData(PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor)
{
	return (PIMAGE_THUNK_DATA)
		(pImportDescriptor->OriginalFirstThunk + m_pImageBase);
}


PCHAR PEUtils::GetFunctionName(PIMAGE_THUNK_DATA pThunkData)
{
	return (PCHAR)((PIMAGE_IMPORT_BY_NAME)
		(pThunkData->u1.AddressOfData + m_pImageBase))->Name;
}


PCHAR PEUtils::GetDllName(PIMAGE_IMPORT_DESCRIPTOR pImportDecriptor)
{
	return (PCHAR)
		(pImportDecriptor->Name + m_pImageBase);
}



PIMAGE_SECTION_HEADER PEUtils::AddSection(PCHAR szSectionName, DWORD dwRSize, DWORD dwFlag)
{
	// 没有做检测。。。。碰巧遇到Headers没位置那真是悲哀了，应该不会出现吧

	// 拿现在最顶那个区段计算新增区段的位置数值
	DWORD nSection = 
		m_pNtHeader->FileHeader.NumberOfSections;

	// 末段区段地址+大小取整 和 映像大小是相等的。。应该是没分别吧取那一个
	DWORD dwRVA = 
		m_pSectionHeader[nSection - 1].VirtualAddress + 
		round_up(m_pSectionHeader[nSection - 1].Misc.VirtualSize, m_pNtHeader->OptionalHeader.SectionAlignment);
	
	DWORD dwVSize = dwRSize;

	dwRSize = 
		round_up(dwRSize, m_pNtHeader->OptionalHeader.FileAlignment);

	DWORD dwROffset = 
		m_pSectionHeader[nSection - 1].PointerToRawData + dwRSize;

	ZeroMemory(&m_pSectionHeader[nSection], sizeof(IMAGE_SECTION_HEADER));

	memcpy(m_pSectionHeader[nSection].Name, szSectionName, 8);
	m_pSectionHeader[nSection].VirtualAddress	= dwRVA;
	m_pSectionHeader[nSection].Misc.VirtualSize	= dwVSize;
	m_pSectionHeader[nSection].PointerToRawData	= dwROffset;
	m_pSectionHeader[nSection].SizeOfRawData	= dwRSize;
	m_pSectionHeader[nSection].Characteristics	= dwFlag;

	// 更新区段数目、映像大小
	m_pNtHeader->FileHeader.NumberOfSections++;
	m_pNtHeader->OptionalHeader.SizeOfImage = dwRVA + round_up(dwVSize, m_pNtHeader->OptionalHeader.SectionAlignment);
	return &m_pSectionHeader[nSection];
}


DWORD PEUtils::GetNumberOfSection(void)
{
	return m_pNtHeader->FileHeader.NumberOfSections;
}


PIMAGE_SECTION_HEADER PEUtils::GetSectionHeader(void)
{
	return m_pSectionHeader;
}


DWORD PEUtils::GetImageSize(void)
{
	return m_dwImageSize;
}


DWORD PEUtils::GetImageFileSize(void)
{
	return m_dwFileSize;
}


DWORD PEUtils::GetImageBase(void)
{
	return m_pImageBase;
}


PIMAGE_NT_HEADERS PEUtils::GetNtHeader(void)
{
	return m_pNtHeader;
}


BOOL PEUtils::WriteImageToFile(void)
{
	WCHAR *szNewFile = wcscat(m_szImagePath, L".packed.exe");
	DWORD dwWritten = 0;
	HANDLE hFile = CreateFile(
		szNewFile,
		GENERIC_WRITE | GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	// 复制Headers
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	WriteFile(hFile, (PVOID)m_pImageBase, m_pNtHeader->OptionalHeader.SizeOfHeaders, &dwWritten, NULL);

	// 复制原来的text和data
	DWORD dwROffset = 0;
	DWORD dwRSize = 0;
	DWORD dwVA = 0;
	for (int i = 0; i < m_pNtHeader->FileHeader.NumberOfSections; ++i) {
		dwVA		= m_pSectionHeader[i].VirtualAddress + m_pImageBase;
		dwROffset	= m_pSectionHeader[i].PointerToRawData;
		dwRSize		= m_pSectionHeader[i].SizeOfRawData;

		SetFilePointer(hFile, dwROffset, NULL, FILE_BEGIN);
		WriteFile(hFile, (PVOID)dwVA, dwRSize, &dwWritten, NULL);
	}
	
	CloseHandle( hFile );
	return TRUE;
}


PIMAGE_BASE_RELOCATION PEUtils::GetRelocationBase(void)
{
	return (PIMAGE_BASE_RELOCATION)(m_pImageBase + 
		GetDataDirectoryRVA(IMAGE_DIRECTORY_ENTRY_BASERELOC));
}


VOID PEUtils::PerformRelocation(DWORD dwDiff)
{
	PIMAGE_BASE_RELOCATION pRelocBase = GetRelocationBase();
	DWORD nData = 0;
	WORD *TypeOffset = NULL;

	while ( pRelocBase->VirtualAddress ) {
		nData = (pRelocBase->SizeOfBlock - 0x8) >> 1;
		TypeOffset = (WORD *)(((BYTE *)pRelocBase) + 0x8);

		for (int i = 0; i < nData; ++i) {
			if ( (TypeOffset[i] >> 12) == IMAGE_REL_BASED_HIGHLOW ) {

				TypeOffset[i] &= 0x0FFF;
				*(DWORD *)(TypeOffset[i] + pRelocBase->VirtualAddress + m_pImageBase) -= 
					dwDiff;

			} else {
				
				break;
			}
		}

		pRelocBase = (PIMAGE_BASE_RELOCATION)((BYTE *)pRelocBase + pRelocBase->SizeOfBlock);
	}

	return;
}


PENTRY_DATA PEUtils::OutSourceEntryData(DWORD EntryType)
{
	
	DWORD dwEntrySize = 
		GetDataDirectorySize(EntryType);

	if (!dwEntrySize) 
		return NULL;
	
	PENTRY_DATA pEntry = new ENTRY_DATA;
	PVOID srcData = (PVOID)
		(GetDataDirectoryRVA(EntryType) + m_pImageBase);

	PVOID pDestData = new char[dwEntrySize];

	ZeroMemory(pDestData, dwEntrySize);
	CopyMemory(pDestData, srcData, dwEntrySize);
	// ZeroMemory(srcData, dwEntrySize);

	pEntry->dwSize = dwEntrySize;
	pEntry->pAddress = pDestData;

	return pEntry;
}


DWORD PEUtils::RVA_TO_OFFSET(DWORD RVA)
{

	for (int i = 0; i < m_pNtHeader->FileHeader.NumberOfSections; ++i) {
		if (RVA > m_pSectionHeader[i].VirtualAddress &&
			RVA < (m_pSectionHeader[i].VirtualAddress + m_pSectionHeader[i].Misc.VirtualSize))
		{
			
			return m_pSectionHeader[i].PointerToRawData + 
				(RVA - m_pSectionHeader[i].VirtualAddress);
		}
	}

	return 0;
}



BOOL PEUtils::IsNeedPack(DWORD nSection)
{
	// 资源段，Tls不压缩

	DWORD dwSectionAddress	= m_pSectionHeader[nSection].VirtualAddress;

	DWORD dwResAddress		= GetDataDirectoryRVA(IMAGE_DIRECTORY_ENTRY_RESOURCE);
	DWORD dwTlsAddress		= GetDataDirectoryRVA(IMAGE_DIRECTORY_ENTRY_TLS);

	if (dwSectionAddress == dwResAddress ||
		dwSectionAddress == dwTlsAddress)
	{
		return FALSE;
	}

	return TRUE;
}


VOID PEUtils::Pack(void)
{
	DWORD *pDest	= NULL;
	PVOID pWorkMem = NULL;
	DWORD *pSrc	= NULL;
	DWORD dwSize = 0;
	DWORD dwPackedSize = 0;
	DWORD nSection = m_pNtHeader->FileHeader.NumberOfSections;

	// 循环区段并压缩(区段数减一，stub不压缩)
	for (int i = 0; i < nSection - 1; ++i) {
		if (IsNeedPack(i)) {

			dwSize	= m_pSectionHeader[i].SizeOfRawData;

			// 处理下有些区段大小为0的情况
			if ( !dwSize )
				goto _skip_pack;
			
			pSrc	= (DWORD *)(m_pSectionHeader[i].VirtualAddress + m_pImageBase);

			// snappy

			// aplib
			DWORD dwWrokMem = aP_workmem_size(dwSize);
			
			pDest = (DWORD *)new char[dwSize];
			ZeroMemory(pDest, dwSize);
			PVOID pWorkMem = new char[dwWrokMem];
			dwPackedSize =  aPsafe_pack(pSrc, pDest, dwSize, pWorkMem, NULL, NULL);
			
			/* zlib 
			int Ret = compress(
				pDest,
				&dwPackedSize,
				pSrc,
				dwSize);

			if (Ret == Z_MEM_ERROR) {
				Ret = 0;
			} else if (Ret == Z_BUF_ERROR) {
				Ret = 0;
			}
			*/

			if ( dwPackedSize ) {
				ZeroMemory(pSrc, dwSize);
				*pSrc = 'PACK';		// 标记
				*(pSrc + 1) = dwPackedSize;	// 长度用于安全解压
				CopyMemory(pSrc + 2, pDest, dwPackedSize);

				m_pSectionHeader[i].SizeOfRawData = 
					round_up(dwPackedSize, m_pNtHeader->OptionalHeader.FileAlignment);



			} else {
				// 压缩出现错误
			}

			delete []pDest;
			delete []pWorkMem;
		}

		// 非首区段修正一下区段Offset
_skip_pack:
		if ( i ) {
			m_pSectionHeader[i].PointerToRawData = 
				m_pSectionHeader[i - 1].PointerToRawData + 
				m_pSectionHeader[i - 1].SizeOfRawData;
		}
	}

	// 末区段不参与压缩，但还是要修正Offset
	m_pSectionHeader[nSection - 1].PointerToRawData = 
			m_pSectionHeader[nSection - 2].PointerToRawData + 
			m_pSectionHeader[nSection - 2].SizeOfRawData;

}


BOOL PEUtils::IsExecutable(void)
{
	// 暂时照顾不到

	// 暂时不搞这个了
	return TRUE;
}


DWORD PEUtils::GetDataDirectoryRVA(DWORD nDirectory)
{
	return m_pNtHeader->OptionalHeader.DataDirectory[nDirectory].VirtualAddress;
}


DWORD PEUtils::GetDataDirectorySize(DWORD nDirectory)
{
	return m_pNtHeader->OptionalHeader.DataDirectory[nDirectory].Size;
}
