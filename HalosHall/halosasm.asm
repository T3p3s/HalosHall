.data
  wSsn DWORD 0h
  qSyscallRet QWORD 0h

.code 
  SetSSn PROC
    mov wSsn, 0h
    mov qSyscallRet, 0h
    mov wSsn, ecx
    mov qSyscallRet, rdx
    ret
  SetSSn ENDP

  SyscallExec PROC
    mov r10, rcx
    mov eax, wSsn
    jmp qword ptr [qSyscallRet]
    ret
  SyscallExec ENDP
end
