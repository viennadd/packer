#pragma once


typedef struct _PENTRY_DATA {
	PVOID pAddress;
	DWORD dwSize;
} ENTRY_DATA, *PENTRY_DATA;

class PEUtils {
protected:
	PIMAGE_SECTION_HEADER m_pSectionHeader;
	PIMAGE_NT_HEADERS m_pNtHeader;
	WCHAR m_szImagePath[_MAX_PATH];
	DWORD m_dwImageSize;
	DWORD m_dwFileSize;
	DWORD m_pImageBase;

public:
	PEUtils(void);

	~PEUtils(void);

	PEUtils(WCHAR *lpImagePath);


	BOOL pkLoadImage(WCHAR *lpImagePath);
	DWORD round_up(DWORD x, DWORD y);

	DWORD GetEntryPoint(void);


	PIMAGE_IMPORT_DESCRIPTOR GetImportDescriptor(void);



	PIMAGE_THUNK_DATA GetFirstThunkData(PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor);


	PIMAGE_THUNK_DATA GetOriginThunkData(PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor);


	PCHAR GetFunctionName(PIMAGE_THUNK_DATA pThunkData);


	PCHAR GetDllName(PIMAGE_IMPORT_DESCRIPTOR pImportDecriptor);



	PIMAGE_SECTION_HEADER AddSection(PCHAR szSectionName, DWORD dwRSize, DWORD dwFlag);


	DWORD GetNumberOfSection(void);


	PIMAGE_SECTION_HEADER GetSectionHeader(void);



	DWORD GetImageSize(void);


	DWORD GetImageFileSize(void);


	DWORD GetImageBase(void);

	
	PIMAGE_NT_HEADERS GetNtHeader(void);


	BOOL WriteImageToFile(void);


	PIMAGE_BASE_RELOCATION GetRelocationBase(void);

	VOID PerformRelocation(DWORD dwDiff);

	PENTRY_DATA OutSourceEntryData(DWORD EntryType);

	DWORD RVA_TO_OFFSET(DWORD RVA);


	BOOL IsNeedPack(DWORD nSection);
	VOID Pack(void);
	BOOL IsExecutable(void);
	DWORD GetDataDirectoryRVA(DWORD nDirectory);
	DWORD GetDataDirectorySize(DWORD nDirectory);
};