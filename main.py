#!/usr/bin/env python3
import sys
import signal
from tracer import ProcessTracer
from utils import validate_pid, get_process_info

def signal_handler(signum, frame):
    print("\n[INFO] Shutting down...")
    sys.exit(0)

def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py <PID>")
        sys.exit(1)
    try:
        pid = int(sys.argv[1])
    except ValueError:
        print("Error: PID must be a number")
        sys.exit(1)
    if not validate_pid(pid):
        print(f"Error: Process {pid} not found or not accessible")
        sys.exit(1)
    signal.signal(signal.SIGINT, signal_handler)
    process_name = get_process_info(pid)
    print(f"[INFO] Monitoring file access for PID {pid} ({process_name})")
    print("[INFO] Press Ctrl+C to stop")
    print("-" * 50)
    tracer = ProcessTracer(pid)
    try:
        tracer.attach()
        tracer.monitor_syscalls()
    except PermissionError:
        print("Error: Permission denied. Try running with sudo.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()
