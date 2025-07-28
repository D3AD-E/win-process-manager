# win-process-manager

A native Windows process manager written in Rust.

## Features

- List all running processes with PID, name, executable path, and command line.
- Duplicate (spawn) a selected process with its original command line.
- Refresh the process list.

## How it works

- Uses Windows native APIs (`ToolHelp32Snapshot`, `ReadProcessMemory`, `NtQueryInformationProcess`, etc.) for process enumeration and command line extraction.
- No WMI or PowerShell required.
- Requires appropriate permissions to read process memory.

## Usage

1. **Build and run:**

   ```sh
   cargo run --release
   ```

2. **Menu options:**
   - `1` — List all processes
   - `2` — Refresh process list
   - `3` — Duplicate a process (enter PID)
   - `4` — Exit

## Requirements

- Windows 10/11
- Rust toolchain
- Run as Administrator for full access

## Notes

- Some system processes may not show command lines due to access restrictions.
- Duplicating a process will attempt to launch a new instance with the same executable and arguments.

## License

MIT
