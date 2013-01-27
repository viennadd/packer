// MainDlg.cpp : implementation of the CMainDlg class
//
/////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "resource.h"

#include "aboutdlg.h"
#include "MainDlg.h"
#include "PEUtils.h"


BOOL CMainDlg::PreTranslateMessage(MSG* pMsg)
{
	return CWindow::IsDialogMessage(pMsg);
}

BOOL CMainDlg::OnIdle()
{
	UIUpdateChildWindows();
	return FALSE;
} 

LRESULT CMainDlg::OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
{
	// center the dialog on the screen
	CenterWindow();

	// set icons
	HICON hIcon = AtlLoadIconImage(IDR_MAINFRAME, LR_DEFAULTCOLOR, ::GetSystemMetrics(SM_CXICON), ::GetSystemMetrics(SM_CYICON));
	SetIcon(hIcon, TRUE);
	HICON hIconSmall = AtlLoadIconImage(IDR_MAINFRAME, LR_DEFAULTCOLOR, ::GetSystemMetrics(SM_CXSMICON), ::GetSystemMetrics(SM_CYSMICON));
	SetIcon(hIconSmall, FALSE);

	// register object for message filtering and idle updates
	CMessageLoop* pLoop = _Module.GetMessageLoop();
	ATLASSERT(pLoop != NULL);
	pLoop->AddMessageFilter(this);
	pLoop->AddIdleHandler(this);

	UIAddChildWindowContainer(m_hWnd);

	return TRUE;
}

LRESULT CMainDlg::OnDestroy(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
{
	// unregister message filtering and idle updates
	CMessageLoop* pLoop = _Module.GetMessageLoop();
	ATLASSERT(pLoop != NULL);
	pLoop->RemoveMessageFilter(this);
	pLoop->RemoveIdleHandler(this);

	return 0;
}

LRESULT CMainDlg::OnDropFiles(UINT /*uMsg*/, WPARAM wParam, LPARAM /*lParam*/, BOOL& /*bHandled*/)
{
	DragQueryFile((HDROP)wParam, 0, m_szImagePath, MAX_PATH);
	SetDlgItemText(IDC_EDIT_FILEPATH, m_szImagePath);
	_wsplitpath(m_szImagePath, NULL, NULL, m_szImageName, NULL);
	
	return 0;
}

LRESULT CMainDlg::OnAppAbout(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
	CAboutDlg dlg;
	dlg.DoModal();
	return 0;
}

LRESULT CMainDlg::OnOK(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
	// TODO: Add validation code 
	CloseDialog(wID);
	return 0;
}

LRESULT CMainDlg::OnCancel(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
	CloseDialog(wID);
	return 0;
}

void CMainDlg::CloseDialog(int nVal)
{
	DestroyWindow();
	::PostQuitMessage(nVal);
}


LRESULT CMainDlg::OnBnClickedButtonGo(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
	PEUtils PE( m_szImagePath );
	// 输出导入表测试下
	/*
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = PE.GetImportDescriptor();
	PIMAGE_THUNK_DATA pThunkData = NULL;
	for (int i = 0; pImportDescriptor[i].FirstThunk; ++i) {

		pThunkData = PE.GetThunkData( &pImportDescriptor[i] );
		OutputDebugStringA("\n");
		OutputDebugStringA(PE.GetDllName( &pImportDescriptor[i] ));
		for (int j = 0; pThunkData[j].u1.Function; ++j) {
			// 最高位是1：序号方式输入
			// 最高位是0：名字方式输入
			if (pThunkData[j].u1.AddressOfData & 0x80000000) {
				
			} else {
				char *p = PE.GetFunctionName( &pThunkData[j] );
				OutputDebugStringA("\n\t");
				OutputDebugStringA(p);
				
			}
		}
	}

	*/
	

	// 新增一个区段试试
	// 打印区段
	/*
	PIMAGE_SECTION_HEADER pSectionHeader = utils.GetSectionHeader();
	for (int i = 0; i < utils.GetNumberOfSection(); ++i) {
		OutputDebugStringA("\n");
		OutputDebugStringA((PCHAR)pSectionHeader[i].Name);
	}
	utils.AddSection("new_sec", 0x450, IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE);
	for (int i = 0; i < utils.GetNumberOfSection(); ++i) {
		OutputDebugStringA("\n");
		OutputDebugStringA((PCHAR)pSectionHeader[i].Name);
	}
	*/

	/*
		流程：
			载入两个PE，然后揉合
			修改原PE各种标志配合，先运行新区段的stub代码
			读取stub的重定位数据，模拟进行重定位
			新文件的text放原程序各种代码数据的压缩版
			新文件的资源段使用原来的（如果有导出表应该也是不能动吧。。现在还没对dll考虑周到）
			新文件的重定位使用stub的，stub负责模拟新文件的重定位
			新文件的导入表使用stub的，stub负责还原解压后原程序要用的IAT
			好像还要处理tls。。还没看
	*/

	PEUtils stub(L"stub.dll");


		/*
		清零一些地方
	*/
	if (PE.IsExecutable()) {

		if (PE.GetDataDirectorySize(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT)) {
			ZeroMemory(
				(PVOID)(PE.GetDataDirectoryRVA(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT) + PE.GetImageBase()), 
				PE.GetDataDirectorySize(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT));
			ZeroMemory(
				&(PE.GetNtHeader()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]),
				sizeof(IMAGE_DATA_DIRECTORY));
		}
	} else {}

	/*
		复制stub进去新区段
	*/
	// 先只要第一个.text段就行了
	// tls directory 也塞进去吧。。。。。
	DWORD dwVSizeOfStub = stub.GetSectionHeader()->Misc.VirtualSize;

	if (PE.GetDataDirectorySize(IMAGE_DIRECTORY_ENTRY_TLS))
		dwVSizeOfStub += sizeof (IMAGE_TLS_DIRECTORY);

	PIMAGE_SECTION_HEADER pStubSection =
		PE.AddSection(".stub", dwVSizeOfStub, IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_SHARED);

	PENTRY_DATA pTls = PE.OutSourceEntryData(IMAGE_DIRECTORY_ENTRY_TLS);

	/*
		新区段其实就是新文件的CodeBase(也是stub的CodeBase了)
		EntryPoint改成stub的EntryPoint
		然后开始模拟stub的重新位
	*/
	DWORD dwOEP = 
		PE.GetNtHeader()->OptionalHeader.ImageBase + PE.GetEntryPoint();

	PE.GetNtHeader()->OptionalHeader.AddressOfEntryPoint = 
		pStubSection->VirtualAddress + 
		(stub.GetEntryPoint() - 
		stub.GetNtHeader()->OptionalHeader.BaseOfCode);

	// 进行stub的模拟重定位工作

	// 基址差值
	DWORD dwImageBaseDiff = 
		stub.GetNtHeader()->OptionalHeader.ImageBase - 
		PE.GetNtHeader()->OptionalHeader.ImageBase;
	// 以为自己在第一个区段, 实际运行是寄生在最后一个区段，差值就不用减这么多
	dwImageBaseDiff -= pStubSection->VirtualAddress;
	// stub以为数据在第一个区段，但我们直接就执行了，实际运行偏移是0，不是第一个区段了
	dwImageBaseDiff += stub.GetSectionHeader()->VirtualAddress;

	stub.PerformRelocation( dwImageBaseDiff );



	// 把改好的内容复制进去新区段
	memcpy(
		(PVOID)(pStubSection->VirtualAddress + PE.GetImageBase()),
		(PVOID)(stub.GetSectionHeader()->VirtualAddress + stub.GetImageBase()),
		dwVSizeOfStub);


	// 记录一下原来的导入表地址
	DWORD dwImportTable = 
		PE.GetDataDirectoryRVA(IMAGE_DIRECTORY_ENTRY_IMPORT);

	// DOS 头上用不上的地方给我用用吧。。
	*(((DWORD *)PE.GetImageBase()) + 1) = dwOEP;
	*(((DWORD *)PE.GetImageBase()) + 2) = dwImportTable;



	// 原输入表指向stub的输入表，IAT不用改，届时PE loader载入PE时会把地址填入原IAT处
	// stub还原原IAT时直接覆盖stub的IAT。。。反正只用一次
	// 不想shellcode搞函数地址就得这样搞。。。。
	DWORD dwAddrDiff = pStubSection->VirtualAddress - stub.GetNtHeader()->OptionalHeader.BaseOfCode;

	PE.GetNtHeader()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 
		stub.GetDataDirectoryRVA(IMAGE_DIRECTORY_ENTRY_IMPORT) + dwAddrDiff;

	PE.GetNtHeader()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 
		stub.GetDataDirectorySize(IMAGE_DIRECTORY_ENTRY_IMPORT);

	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = PE.GetImportDescriptor();
	PIMAGE_THUNK_DATA pFirstThunkData = NULL;
	PIMAGE_THUNK_DATA pOriginThunkData = NULL;
	for (int i = 0; pImportDescriptor[i].FirstThunk; ++i) {

		pImportDescriptor[i].FirstThunk += dwAddrDiff;
		pImportDescriptor[i].OriginalFirstThunk += dwAddrDiff;
		pImportDescriptor[i].Name += dwAddrDiff;

		pFirstThunkData = PE.GetFirstThunkData( &pImportDescriptor[i] );
		pOriginThunkData = PE.GetOriginThunkData( &pImportDescriptor[i] );
		for (int j = 0; pFirstThunkData[j].u1.AddressOfData; j++) {
			
			if (pFirstThunkData[j].u1.AddressOfData & 0x80000000) {
				; // stub里没序号导入函数
			} else {
				pFirstThunkData[j].u1.AddressOfData = pFirstThunkData[j].u1.AddressOfData + dwAddrDiff;
				pOriginThunkData[j].u1.AddressOfData = pOriginThunkData[j].u1.AddressOfData + dwAddrDiff;
			}
		}
	}

	// 结束输入表指向

	// 如果有tls则处理
	if (PE.GetDataDirectorySize(IMAGE_DIRECTORY_ENTRY_TLS)) {
		
		// 把tls复制去新区段的stub代码和数据之后
		memcpy(
			(PVOID)(pStubSection->VirtualAddress + PE.GetImageBase() + stub.GetSectionHeader()->Misc.VirtualSize),
			pTls->pAddress,
			pTls->dwSize);

		// 记录Tls表地址
		DWORD dwTls = 
			PE.GetDataDirectoryRVA(IMAGE_DIRECTORY_ENTRY_TLS);
		*(((DWORD *)PE.GetImageBase()) + 3) = dwTls;

	
		// Tls 指向移位后的位置
		PE.GetNtHeader()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 
			pStubSection->VirtualAddress + stub.GetSectionHeader()->Misc.VirtualSize;

		PIMAGE_TLS_DIRECTORY pTlsDirectory = (PIMAGE_TLS_DIRECTORY)
			(PE.GetDataDirectoryRVA(IMAGE_DIRECTORY_ENTRY_TLS) + PE.GetImageBase());

		// stub导入表和代码之间有点00....就塞进去吧。。。。。
		DWORD dwImportVA = 
			PE.GetDataDirectoryRVA(IMAGE_DIRECTORY_ENTRY_IMPORT) + PE.GetNtHeader()->OptionalHeader.ImageBase;
		DWORD dwRawSize = pTlsDirectory->EndAddressOfRawData - pTlsDirectory->StartAddressOfRawData;
		pTlsDirectory->StartAddressOfRawData	= dwImportVA - 0x250;
		pTlsDirectory->EndAddressOfRawData		= dwImportVA - 0x250 + dwRawSize;
		pTlsDirectory->AddressOfIndex			= dwImportVA - 0x250 + dwRawSize;
		pTlsDirectory->AddressOfCallBacks		= dwImportVA - 0x250 + dwRawSize + 0x50;
	}


	/*
		清零一些地方
	*/
	if (PE.IsExecutable()) {

		if (PE.GetDataDirectorySize(IMAGE_DIRECTORY_ENTRY_BASERELOC)) {
			ZeroMemory(
				(PVOID)(PE.GetDataDirectoryRVA(IMAGE_DIRECTORY_ENTRY_BASERELOC) + PE.GetImageBase()), 
				PE.GetDataDirectorySize(IMAGE_DIRECTORY_ENTRY_BASERELOC));
		}

		if (PE.GetDataDirectorySize(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)) {
			ZeroMemory(
				(PVOID)(PE.GetDataDirectoryRVA(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) + PE.GetImageBase()), 
				PE.GetDataDirectorySize(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG));
			ZeroMemory(
				&(PE.GetNtHeader()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]),
				sizeof(IMAGE_DATA_DIRECTORY));
		}

		if (PE.GetDataDirectorySize(IMAGE_DIRECTORY_ENTRY_DEBUG)) {
			ZeroMemory(
				(PVOID)(PE.GetDataDirectoryRVA(IMAGE_DIRECTORY_ENTRY_DEBUG) + PE.GetImageBase()), 
				PE.GetDataDirectorySize(IMAGE_DIRECTORY_ENTRY_DEBUG));
			ZeroMemory(
				&(PE.GetNtHeader()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]),
				sizeof(IMAGE_DATA_DIRECTORY));
		}
	} else {
	
		/*
			开始把PE的重定位表指向stub的
			解压后的重定位工作交给stub
		*/

	

		// 结束重定位转向
	}

	PE.Pack();

	PE.WriteImageToFile();

	return 0;
}


LRESULT CMainDlg::OnBnClickedButtonBrowse(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
	// TODO: Add your control notification handler code here
	CFileDialog FileDlg(TRUE, NULL, NULL, NULL, L"EXE文件(*.exe)\0*.exe\0所有文件(*.*)\0*.*\0", *this);

	if (IDOK == FileDlg.DoModal()) {
		/*
			保存文件路径和文件名
		*/
		wcscpy_s(m_szImagePath, _MAX_FNAME, FileDlg.m_szFileName);
		wcscpy_s(m_szImageName, _MAX_FNAME, FileDlg.m_szFileTitle);

		SetDlgItemText(IDC_EDIT_FILEPATH, m_szImagePath);
	}
	return 0;
}
