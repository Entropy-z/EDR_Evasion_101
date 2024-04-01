#include <Windows.h>

VOID PrintState(char* SyscallName, PVOID pSyscallAddress) {
	printf("[#] %s [ 0x%p ] ---> %s \n", SyscallName, pSyscallAddress, (*(ULONG*)pSyscallAddress != 0xb8d18b4c) == TRUE ? "[ HOOKED ]" : "[ UNHOOKED ]");
}

int main(){

    //PrintState("Nt");

}