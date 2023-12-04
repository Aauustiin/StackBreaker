global _start

section .text

_start:
    mov eax, 0
      
    dec eax               ; Decrements EAX by 1
      
    dec eax               ; Decrements EAX by 1
      
    not eax               ; Performs bitwise NOT on EAX
      
    neg eax               ; Negates the value in EAX (two's complement negation)
      
    inc eax               ; Increments EAX by 1
    mov ebx, data       ; Get the address of the .data section
    mov [ebx], eax      ; Store the value of EAX at .data

    ; Set up for the 'write' system call
    mov eax, 4          ; System call number for 'write'
    mov ebx, 1          ; File descriptor 1 (stdout)
    mov ecx, data       ; Address of the data to write
    mov edx, 4          ; Number of bytes to write (size of the data)
    int 0x80            ; Invoke the system call

section .data
data: dd 0             ; Allocate 4 bytes for storing a 32-bit value
