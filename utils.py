import os
import pwd
import grp
import socket
import psutil
from datetime import datetime

def get_socket_info(pid, inode):
    """Get detailed socket information"""
    try:
        # Try to get TCP and UDP socket information
        conns = psutil.Process(pid).connections()
        for conn in conns:
            if conn.raddr and hasattr(conn, 'inode') and str(conn.inode) in inode:
                return f"socket:[{inode}] ({conn.type}) {conn.laddr[0]}:{conn.laddr[1]} -> {conn.raddr[0]}:{conn.raddr[1]}"
            elif hasattr(conn, 'inode') and str(conn.inode) in inode:
                return f"socket:[{inode}] ({conn.type}) {conn.laddr[0]}:{conn.laddr[1]} (listening)"
    except:
        pass
    return f"socket:[{inode}]"

def get_file_metadata(path):
    """Get file ownership and permissions"""
    try:
        stat = os.stat(path)
        user = pwd.getpwuid(stat.st_uid).pw_name
        group = grp.getgrgid(stat.st_gid).gr_name
        mode = oct(stat.st_mode)[-4:]  # Get permission bits in octal
        size = stat.st_size
        mtime = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        return f"owner={user}:{group} mode={mode} size={size} mtime={mtime}"
    except:
        return ""

def get_process_info(pid):
    """Get detailed process information"""
    try:
        proc = psutil.Process(pid)
        return {
            'name': proc.name(),
            'user': proc.username(),
            'cmdline': ' '.join(proc.cmdline()),
            'cwd': proc.cwd(),
            'start_time': datetime.fromtimestamp(proc.create_time()).strftime('%Y-%m-%d %H:%M:%S')
        }
    except:
        return None

def fd_to_path(pid, fd):
    """Enhanced fd to path resolution with metadata"""
    try:
        path = os.readlink(f'/proc/{pid}/fd/{fd}')
        
        # Handle different types of file descriptors
        if path.startswith('socket:['):
            inode = path.split('[')[1].rstrip(']')
            return get_socket_info(pid, inode)
        elif os.path.exists(path):
            metadata = get_file_metadata(path)
            return f"{path} ({metadata})" if metadata else path
        else:
            return path
    except Exception as e:
        return f'fd={fd}'

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
    if flags & 0o4000:  flag_names.append('O_NONBLOCK')
    if flags & 0o200000: flag_names.append('O_CLOEXEC')
    return '|'.join(flag_names) if flag_names else f'0x{flags:x}'

def validate_pid(pid):
    """Check if PID exists and is accessible"""
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False 