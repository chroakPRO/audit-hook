import os
import pwd
import grp
import socket
import psutil
from datetime import datetime

def get_socket_info(pid, inode):
    """Get detailed socket information by inode for a process."""
    try:
        proc = psutil.Process(pid)
        for conn in proc.connections(kind='all'):
            # psutil returns inode as int, so compare as int
            if hasattr(conn, 'inode') and conn.inode == int(inode):
                sock_type = {socket.SOCK_STREAM: 'TCP', socket.SOCK_DGRAM: 'UDP'}.get(conn.type, 'UNIX')
                # laddr and raddr can be tuples or strings (for UNIX)
                if isinstance(conn.laddr, tuple):
                    laddr = f"{conn.laddr[0]}:{conn.laddr[1]}"
                else:
                    laddr = str(conn.laddr)
                if conn.raddr:
                    if isinstance(conn.raddr, tuple):
                        raddr = f"{conn.raddr[0]}:{conn.raddr[1]}"
                    else:
                        raddr = str(conn.raddr)
                else:
                    raddr = ''
                state = getattr(conn, 'status', '')
                if raddr:
                    return f"socket:[{inode}] ({sock_type}) {laddr} -> {raddr} {state}"
                else:
                    return f"socket:[{inode}] ({sock_type}) {laddr} {state}"
    except Exception as e:
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