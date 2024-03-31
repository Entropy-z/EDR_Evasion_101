.data 
    wSysProtect DWORD 50h
    wSysAlloc DWORD 18h

.code
    SysFuncProtect PROC
        mov r10, rcx
        mov eax, wSysProtect
        syscall
        ret
    SysFuncProtect ENDP

    SysFuncAlloc PROC
        mov r10, rcx
        mov eax, wSysAlloc
        syscall
        ret
    SysFuncAlloc ENDP
end