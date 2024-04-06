.code
    SysFuncAlloc PROC
        mov r10, rcx
        mov eax, 18h
        syscall
        ret
    SysFuncAlloc ENDP

    SysFuncThread PROC
        mov r10, rcx
        mov eax, 0C7h
        syscall
        ret
    SysFuncThread ENDP
end