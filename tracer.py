import os
import sys
import ctypes
import signal
from ctypes import c_long, c_int, c_void_p, Structure
from syscalls import is_file_syscall, get_syscall_name
from utils import format_flags, fd_to_path, get_process_info, get_socket_info
import time
import psutil
import socket

# ptrace constants
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_SYSCALL = 24
PTRACE_GETREGS = 12

class user_regs_struct(Structure):
    """x86_64 register structure"""
    _fields_ = [
        ("r15", c_long), ("r14", c_long), ("r13", c_long), ("r12", c_long),
        ("rbp", c_long), ("rbx", c_long), ("r11", c_long), ("r10", c_long),
        ("r9", c_long), ("r8", c_long), ("rax", c_long), ("rcx", c_long),
        ("rdx", c_long), ("rsi", c_long), ("rdi", c_long), ("orig_rax", c_long),
        ("rip", c_long), ("cs", c_long), ("eflags", c_long), ("rsp", c_long),
        ("ss", c_long), ("fs_base", c_long), ("gs_base", c_long),
        ("ds", c_long), ("es", c_long), ("fs", c_long), ("gs", c_long),
    ]

class ProcessTracer:
    def __init__(self, pid):
        self.pid = pid
        self.libc = ctypes.CDLL("libc.so.6")
        self.attached = False
        self.process_info = get_process_info(pid)
        if self.process_info:
            print(f"[INFO] Process details:")
            print(f"  Name: {self.process_info['name']}")
            print(f"  User: {self.process_info['user']}")
            print(f"  Command: {self.process_info['cmdline']}")
            print(f"  Working Dir: {self.process_info['cwd']}")
            print(f"  Started: {self.process_info['start_time']}")
            print("-" * 50)
        
    def attach(self):
        """Attach to target process"""
        result = self.libc.ptrace(PTRACE_ATTACH, self.pid, 0, 0)
        if result == -1:
            raise Exception(f"Failed to attach to PID {self.pid}")
        os.waitpid(self.pid, 0)
        self.attached = True
        print(f"[INFO] Attached to process {self.pid}")
        
    def detach(self):
        """Detach from process"""
        if self.attached:
            self.libc.ptrace(PTRACE_DETACH, self.pid, 0, 0)
            self.attached = False
            print(f"[INFO] Detached from process {self.pid}")
            
    def continue_syscall(self):
        """Continue execution until next syscall"""
        self.libc.ptrace(PTRACE_SYSCALL, self.pid, 0, 0)
        os.waitpid(self.pid, 0)
        
    def get_registers(self):
        """Get current register values"""
        regs = user_regs_struct()
        result = self.libc.ptrace(PTRACE_GETREGS, self.pid, 0, ctypes.byref(regs))
        if result == -1:
            return None
        return regs

    def read_string(self, address, max_len=256):
        """Read null-terminated string from process memory"""
        if address == 0:
            return None
        result = ""
        for i in range(0, max_len, 8):
            try:
                data = self.libc.ptrace(1, self.pid, address + i, 0)  # PTRACE_PEEKDATA
                if data == -1:
                    break
                bytes_data = data.to_bytes(8, 'little')
                for byte in bytes_data:
                    if byte == 0:
                        return result
                    result += chr(byte)
            except:
                break
        return result

    def parse_syscall_args(self, regs, syscall_name):
        """Extract syscall arguments"""
        args = {}
        if syscall_name == 'open':
            args['filename'] = self.read_string(regs.rdi)
            args['flags'] = regs.rsi
            args['mode'] = regs.rdx
        elif syscall_name == 'openat':
            args['dirfd'] = regs.rdi
            args['filename'] = self.read_string(regs.rsi)
            args['flags'] = regs.rdx
            args['mode'] = regs.r10
        elif syscall_name in ['read', 'write']:
            args['fd'] = regs.rdi
            args['count'] = regs.rdx
        elif syscall_name == 'close':
            args['fd'] = regs.rdi
        return args

    def handle_syscall(self, regs):
        """Process syscall entry"""
        syscall_num = regs.orig_rax
        if is_file_syscall(syscall_num):
            syscall_name = get_syscall_name(syscall_num)
            args = self.parse_syscall_args(regs, syscall_name)
            timestamp = time.strftime("%H:%M:%S")
            self.log_file_access(timestamp, syscall_name, args)

    def log_file_access(self, timestamp, syscall_name, args):
        """Enhanced log file access event with detailed information"""
        proc_name = self.process_info['name'] if self.process_info else 'unknown'
        proc_user = self.process_info['user'] if self.process_info else 'unknown'
        
        if syscall_name in ['open', 'openat']:
            filename = args.get('filename', 'unknown')
            flags = format_flags(args.get('flags', 0))
            mode = oct(args.get('mode', 0))[-4:]
            print(f"[{timestamp}] {proc_name}({self.pid})[{proc_user}] OPEN: {filename}")
            print(f"  Flags: {flags}")
            print(f"  Mode: {mode}")
            
        elif syscall_name == 'read':
            fd = args.get('fd', -1)
            count = args.get('count', 0)
            path = fd_to_path(self.pid, fd)
            print(f"[{timestamp}] {proc_name}({self.pid})[{proc_user}] READ: {path}")
            print(f"  Bytes requested: {count}")
            
        elif syscall_name == 'write':
            fd = args.get('fd', -1)
            count = args.get('count', 0)
            path = fd_to_path(self.pid, fd)
            print(f"[{timestamp}] {proc_name}({self.pid})[{proc_user}] WRITE: {path}")
            print(f"  Bytes written: {count}")
            
        elif syscall_name == 'close':
            fd = args.get('fd', -1)
            path = fd_to_path(self.pid, fd)
            print(f"[{timestamp}] {proc_name}({self.pid})[{proc_user}] CLOSE: {path}")

    def monitor_syscalls(self):
        """Enhanced monitoring with file syscall handling"""
        try:
            while True:
                self.continue_syscall()
                regs = self.get_registers()
                if regs:
                    self.handle_syscall(regs)
                self.continue_syscall()
        except KeyboardInterrupt:
            print("\n[INFO] Monitoring stopped")
        except ProcessLookupError:
            print(f"[INFO] Process {self.pid} terminated")
        finally:
            self.detach() 