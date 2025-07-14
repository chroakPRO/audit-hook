import os

def format_flags(flags):
    """Convert open flags to readable format"""
    flag_names = []
    # Common flags
    if flags & 0o0:     flag_names.append('O_RDONLY')
    if flags & 0o1:     flag_names.append('O_WRONLY') 
    if flags & 0o2:     flag_names.append('O_RDWR')
    if flags & 0o100:   flag_names.append('O_CREAT')
    if flags & 0o1000:  flag_names.append('O_TRUNC')
    if flags & 0o2000:  flag_names.append('O_APPEND')
    return '|'.join(flag_names) if flag_names else f'0x{flags:x}'

def get_process_name(pid):
    """Get process name from PID"""
    try:
        with open(f'/proc/{pid}/comm', 'r') as f:
            return f.read().strip()
    except:
        return 'unknown'

def validate_pid(pid):
    """Check if PID exists and is accessible"""
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False 