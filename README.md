# PID-Based File Access Monitor

Monitor file-related syscalls (open, read, write, close) for a running Linux process using ptrace.

## Usage

```bash
python main.py <PID>
```
- Hooks into the process with the given PID and prints file access events in real time.
- Press Ctrl+C to stop monitoring.

## Requirements
- Linux (x86_64)
- Python 3.x
- Run as root or with sudo for permission to trace other processes.

## Example

### Start a test program in one terminal:
```bash
python3 -c "import time\nfor i in range(3):\n    with open(f'test_{i}.txt', 'w') as f:\n        f.write('Hello World')\n    time.sleep(2)"
```

### In another terminal, monitor the process:
```bash
python main.py <PID_FROM_ABOVE>
```

### Expected Output
```
[INFO] Monitoring file access for PID 12345 (python3)
[INFO] Press Ctrl+C to stop
--------------------------------------------------
[14:23:15] OPEN: test_0.txt (O_WRONLY|O_CREAT|O_TRUNC)
[14:23:15] WRITE: fd=3, bytes=11
[14:23:15] CLOSE: fd=3
[14:23:17] OPEN: test_1.txt (O_WRONLY|O_CREAT|O_TRUNC)
[14:23:17] WRITE: fd=3, bytes=11
[14:23:17] CLOSE: fd=3
```

## Project Structure
- `main.py` - Entry point & argument parsing
- `tracer.py` - Core ptrace implementation
- `syscalls.py` - Syscall definitions & helpers
- `utils.py` - Helper functions

## Notes
- Only works on Linux (x86_64) with /proc available.
- You must have permission to trace the target process (usually requires root).
- This is a learning tool and not production-hardened.
