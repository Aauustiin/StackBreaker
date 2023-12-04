; Write a value into EAX
mov eax, 0  ; This is an example value in hexadecimal 
            
imul eax, 3           ; Multiplies EAX by 3. Result is in EAX. If the result is too large, EDX:EAX is used.
            
add eax, 4            ; Adds 4 to EAX
            
and eax, 0xFF         ; Performs bitwise AND on EAX with 0xFF
            
neg eax               ; Negates the value in EAX (two's complement negation)
            
dec eax               ; Decrements EAX by 1
            
and eax, 0xFFFFFFFF
mov ebx, .data       ; Get the address of the .data section
mov [ebx], eax       ; Store the value of EAX at .data

; Set up for the 'write' system call
mov eax, 4           ; System call number for 'write'
mov ebx, 1           ; File descriptor 1 (stdout)
mov ecx, .data       ; Address of the data to write
mov edx, 4           ; Number of bytes to write (size of the data)
int 0x80             ; Invoke the system call