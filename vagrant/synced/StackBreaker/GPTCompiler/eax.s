global _start
section .text
_start:
    mov eax, 0
      
    dec eax               ; Decrements EAX by 1
      
    and eax, 0xFF         ; Performs bitwise AND on EAX with 0xFF
      
    xor eax, 0xFF         ; Performs bitwise XOR on EAX with 0xFF
      
    sub eax, 5            ; Subtracts 5 from EAX
      
    and eax, 0xFF         ; Performs bitwise AND on EAX with 0xFF
    mov ebx, data       ; Get the address of the .data section
    mov [ebx], eax      ; Store the value of EAX at .data
    mov eax, 4          ; System call number for 'write'
    mov ebx, 1          ; File descriptor 1 (stdout)
    mov ecx, data       ; Address of the data to write
    mov edx, 4          ; Number of bytes to write (size of the data)
    int 0x80            ; Invoke the system call
section .rodata
data: dd 0             ; Allocate 4 bytes for storing a 32-bit value
