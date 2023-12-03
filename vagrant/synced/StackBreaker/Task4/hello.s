global _start

section .text

_start:
    ; Write system call (sys_write)
    mov eax, 4      ; syscall number for sys_write
    mov ebx, 1      ; file descriptor 1 is stdout
    mov ecx, msg    ; pointer to the message
    mov edx, len    ; length of the message
    int 0x80        ; call kernel

    ; Exit system call (sys_exit)
    mov eax, 1      ; syscall number for sys_exit
    mov ebx, 0      ; exit status
    int 0x80        ; call kernel

section .rodata
msg: db "Hello, World!", 10
len: equ $ - msg
