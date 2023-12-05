global _start

section .text

_start:
    ; Initialize eax with a test value and perform operations
    mov eax, 0
      
    dec eax               ; Decrements EAX by 1
      
    dec eax               ; Decrements EAX by 1
      
    not eax               ; Performs bitwise NOT on EAX
      
    neg eax               ; Negates the value in EAX (two's complement negation)
      
    inc eax               ; Increments EAX by 1

    ; Convert eax to a string
    mov edi, buffer     ; Point EDI to the buffer
    call int_to_ascii   ; Call conversion routine

    ; Prepare for the 'write' system call
    mov eax, 4          ; sys_write
    mov ebx, 1          ; file descriptor (stdout)
    mov ecx, buffer     ; pointer to data to write
    mov edx, [num_len]  ; number of bytes to write, stored at num_len
    int 0x80            ; call kernel

    ; Exit the program
    mov eax, 1          ; sys_exit
    xor ebx, ebx        ; exit code 0
    int 0x80
; Integer to ASCII conversion
; EDI points to the buffer, EAX contains the integer
int_to_ascii:
    mov ebx, 10         ; divisor (base 10)
    lea esi, [buffer]   ; Point ESI to the start of the buffer
    mov edi, esi        ; Copy ESI to EDI

convert_loop:
    xor edx, edx        ; clear edx for 'div'
    div ebx             ; divide eax by 10, result in eax, remainder in edx
    add dl, '0'         ; convert remainder to ASCII
    mov [edi], dl       ; store ASCII character
    inc edi             ; move buffer pointer
    test eax, eax       ; check if quotient is zero
    jnz convert_loop    ; if not, keep dividing

    ; Mark the end of the string with a newline and store its length
    mov byte [edi], 0xA ; Add newline at the end
    inc edi             ; Adjust for the newline

reverse_loop:
    ; Initialize pointers for reversal
    dec edi             ; Point to the last digit (before the newline)
    reverse_loop_start:
        cmp esi, edi    ; Compare start and end pointers
        jge end_reverse ; If start >= end, end the loop
        mov al, byte [esi]  ; Load character from start into AL
        mov bl, byte [edi]  ; Load character from end into BL
        mov byte [esi], bl  ; Swap the characters
        mov byte [edi], al
        inc esi             ; Move start pointer forward
        dec edi             ; Move end pointer backward
        jmp reverse_loop_start
    end_reverse:

    ; Calculate and store the length of the string
    lea edi, [buffer]   ; Point EDI to the start of the buffer
    mov ecx, edi        ; Copy buffer start to ECX
    add ecx, 12         ; Move ECX to the end of the buffer
    sub ecx, esi        ; Subtract to find the length
    mov [num_len], ecx  ; Store the length

    ret

section .data
buffer db 0,0,0,0,0,0,0,0,0,0,0,0 ; Buffer for 11 digits + null terminator
num_len dd 0             ; Length of the number string