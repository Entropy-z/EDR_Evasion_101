#include <stdio.h>
#include <windows.h>
#include <intrin.h> 
#include "syscall.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

extern void SysFuncProtect();
extern void SysFuncAlloc();

PVOID NtAllocateVirtualMemory ;

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

void DirectSyscall() {
    HANDLE hCurrentProcess = GetCurrentProcess();
    LPVOID pAllocMem;
    DWORD dwOldProtection=NULL;

    const char* message = "Allocated!";
    SIZE_T dwSize = strlen(message) + 1;


    if (pAllocMem == NULL) {
        printf("Failed to allocate memory. %d\n", GetLastError());
        return;
    }

    //SysFuncAlloc();

    printf("MemAllocated in: 0x%p\n", pAllocMem);
    printf("Of Size: %zu\n", dwSize);


    SIZE_T dwSizeProtected = dwSize;
    /*NTSTATUS status1 = fNtProtectVirtualMemory(hCurrentProcess, &pAllocMem, &dwSizeProtected, PAGE_EXECUTE_READWRITE, &dwOldProtection);
    if (!NT_SUCCESS(status1)) {
        printf("[!] NtProtectVirtualMemory Failed With Status : 0x%0.8X \n", status1);
        return;
    }*/

    //SysFuncProtect();


    printf("Direct Syscall Done...!\n");

    // Após a syscall, o manipulador do arquivo pode ser usado, e o status da operação pode ser verificado através de ioStatusBlock
    VirtualFree(pAllocMem, 0, MEM_RELEASE);
}

int main() {
    DirectSyscall();
    return 0;
}
