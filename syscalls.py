# x86_64 syscall numbers
FILE_SYSCALLS = {
    0: 'read',
    1: 'write',
    2: 'open',
    3: 'close',
    257: 'openat',
}

# Syscall argument positions (x86_64 calling convention)
SYSCALL_ARGS = {
    'open': ['filename', 'flags', 'mode'],      # rdi, rsi, rdx
    'openat': ['dirfd', 'filename', 'flags', 'mode'],  # rdi, rsi, rdx, r10
    'read': ['fd', 'buffer', 'count'],          # rdi, rsi, rdx
    'write': ['fd', 'buffer', 'count'],         # rdi, rsi, rdx
    'close': ['fd'],                            # rdi
}

def is_file_syscall(syscall_num):
    """Check if syscall is file-related"""
    return syscall_num in FILE_SYSCALLS

def get_syscall_name(syscall_num):
    """Get syscall name from number"""
    return FILE_SYSCALLS.get(syscall_num, f"syscall_{syscall_num}") 