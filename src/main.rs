mod monitor;
use std::collections::HashMap;
use windows::Win32::Foundation::MAX_PATH;
use windows::Win32::Foundation::UNICODE_STRING;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::PROCESS_BASIC_INFORMATION;
use windows::Win32::System::Threading::{
    CREATE_NEW_CONSOLE, OpenProcess, PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW, STARTUPINFOW,
};
use windows::Win32::System::Threading::{CreateProcessW, PROCESS_VM_READ};
use windows::core::PCWSTR;
use windows::core::{BSTR, PWSTR, Result as WinResult};
#[derive(Debug, Clone)]
struct ProcessInfo {
    pid: u32,
    name: String,
    command_line: String,
    executable_path: String,
    current_directory: String,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationProcess(
        ProcessHandle: windows::Win32::Foundation::HANDLE,
        ProcessInformationClass: u32,
        ProcessInformation: *mut std::ffi::c_void,
        ProcessInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> i32;
}

struct ProcessManager {
    processes: HashMap<u32, ProcessInfo>,
}

impl ProcessManager {
    fn new() -> Self {
        Self {
            processes: HashMap::new(),
        }
    }

    fn refresh_processes(&mut self) -> WinResult<()> {
        self.processes.clear();

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;

            let mut pe32 = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snapshot, &mut pe32).is_ok() {
                loop {
                    let pid = pe32.th32ProcessID;
                    let name = Self::wide_string_to_string(&pe32.szExeFile);

                    // Get command line and executable path
                    let (command_line, executable_path, current_directory) =
                        self.get_process_details(pid);

                    let process_info = ProcessInfo {
                        pid,
                        name,
                        command_line,
                        executable_path,
                        current_directory,
                    };

                    self.processes.insert(pid, process_info);

                    if Process32NextW(snapshot, &mut pe32).is_err() {
                        break;
                    }
                }
            }

            CloseHandle(snapshot);
        }

        Ok(())
    }

    fn get_process_details(&self, pid: u32) -> (String, String, String) {
        let mut command_line = String::new();
        let mut current_directory = String::new();
        let mut executable_path = String::new();

        if let Some(cmd) = ProcessManager::get_command_line_native(pid) {
            command_line = cmd;
        }

        if let Some(dir) = ProcessManager::get_current_directory_native(pid) {
            current_directory = dir;
        }
        // Get executable path
        unsafe {
            let process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);

            if let Ok(handle) = process_handle {
                let mut buffer = [0u16; MAX_PATH as usize];
                let mut size = buffer.len() as u32;

                if QueryFullProcessImageNameW(
                    handle,
                    windows::Win32::System::Threading::PROCESS_NAME_FORMAT(0),
                    PWSTR(buffer.as_mut_ptr()),
                    &mut size,
                )
                .is_ok()
                {
                    executable_path = String::from_utf16_lossy(&buffer[..size as usize]);
                }

                CloseHandle(handle);
            }
        }

        (command_line, executable_path, current_directory)
    }

    fn get_current_directory_native(pid: u32) -> Option<String> {
        unsafe {
            let handle =
                OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).ok()?;

            let mut pbi = PROCESS_BASIC_INFORMATION::default();
            let mut ret_len = 0u32;
            if NtQueryInformationProcess(
                handle,
                0,
                &mut pbi as *mut _ as *mut _,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                &mut ret_len,
            ) != 0
            {
                CloseHandle(handle);
                return None;
            }

            let peb_addr = pbi.PebBaseAddress as usize;
            let mut proc_params_addr = 0usize;

            if ReadProcessMemory(
                handle,
                (peb_addr + 0x20) as _,
                &mut proc_params_addr as *mut _ as *mut _,
                std::mem::size_of::<usize>(),
                None,
            )
            .is_err()
            {
                CloseHandle(handle);
                return None;
            }

            // Read address of CurrentDirectory UNICODE_STRING (offset 0x38 inside RTL_USER_PROCESS_PARAMETERS)
            let mut cur_dir_unicode = UNICODE_STRING::default();
            if ReadProcessMemory(
                handle,
                (proc_params_addr + 0x38) as _,
                &mut cur_dir_unicode as *mut _ as *mut _,
                std::mem::size_of::<UNICODE_STRING>(),
                None,
            )
            .is_err()
            {
                CloseHandle(handle);
                return None;
            }

            let mut buffer = vec![0u16; (cur_dir_unicode.Length / 2) as usize];
            if ReadProcessMemory(
                handle,
                cur_dir_unicode.Buffer.0 as _,
                buffer.as_mut_ptr() as *mut _,
                cur_dir_unicode.Length as usize,
                None,
            )
            .is_err()
            {
                CloseHandle(handle);
                return None;
            }

            CloseHandle(handle);
            Some(String::from_utf16_lossy(&buffer))
        }
    }

    fn get_command_line_native(pid: u32) -> Option<String> {
        unsafe {
            // Open the process
            let handle =
                OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).ok()?;

            // Query basic info to get PEB address
            let mut pbi = PROCESS_BASIC_INFORMATION::default();
            let mut ret_len = 0u32;
            let status = NtQueryInformationProcess(
                handle,
                0, // ProcessBasicInformation
                &mut pbi as *mut _ as *mut _,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                &mut ret_len,
            );
            if status != 0 {
                CloseHandle(handle);
                return None;
            }

            // Read PEB address
            let peb_addr = pbi.PebBaseAddress as usize;

            // Read address of ProcessParameters
            let mut proc_params_addr = 0usize;
            let ok = ReadProcessMemory(
                handle,
                (peb_addr + 0x20) as _,
                &mut proc_params_addr as *mut _ as *mut _,
                std::mem::size_of::<usize>(),
                None,
            )
            .is_ok();
            if !ok {
                CloseHandle(handle);
                return None;
            }

            // Read address of CommandLine UNICODE_STRING
            let mut cmdline_unicode = UNICODE_STRING::default();
            let ok = ReadProcessMemory(
                handle,
                (proc_params_addr + 0x70) as _,
                &mut cmdline_unicode as *mut _ as *mut _,
                std::mem::size_of::<UNICODE_STRING>(),
                None,
            )
            .is_ok();
            if !ok {
                CloseHandle(handle);
                return None;
            }

            // Read the actual command line string
            let mut buffer = vec![0u16; (cmdline_unicode.Length / 2) as usize];
            let ok = ReadProcessMemory(
                handle,
                cmdline_unicode.Buffer.0 as _,
                buffer.as_mut_ptr() as *mut _,
                cmdline_unicode.Length as usize,
                None,
            )
            .is_ok();
            CloseHandle(handle);
            if !ok {
                return None;
            }

            Some(String::from_utf16_lossy(&buffer))
        }
    }

    fn wide_string_to_string(wide_str: &[u16]) -> String {
        let len = wide_str
            .iter()
            .position(|&x| x == 0)
            .unwrap_or(wide_str.len());
        String::from_utf16_lossy(&wide_str[..len])
    }

    fn list_processes(&self) {
        println!(
            "{:<8} {:<30} {:<50} {}",
            "PID", "Name", "Executable Path", "Command Line"
        );
        println!("{}", "-".repeat(150));

        let mut processes: Vec<_> = self.processes.values().collect();
        processes.sort_by_key(|p| p.pid);

        for process in processes {
            println!(
                "{:<8} {:<30} {:<50} {}",
                process.pid,
                process.name,
                if process.executable_path.len() > 47 {
                    format!("{}...", &process.executable_path[..47])
                } else {
                    process.executable_path.clone()
                },
                process.command_line
            );
        }
    }

    fn duplicate_process(&self, pid: u32) -> WinResult<()> {
        if let Some(process_info) = self.processes.get(&pid) {
            println!("Duplicating process {} ({})", pid, process_info.name);
            println!("Command line: {}", process_info.command_line);

            // Parse command line to extract executable and arguments
            let (executable, args) =
                self.parse_command_line(&process_info.command_line, &process_info.executable_path);

            unsafe {
                let mut startup_info: STARTUPINFOW = std::mem::zeroed();
                startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

                let mut process_info_struct: PROCESS_INFORMATION = std::mem::zeroed();
                let cur_dir_wide: Vec<u16> = process_info
                    .current_directory
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();
                // Convert strings to wide strings
                let exe_wide: Vec<u16> = executable
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();
                let mut args_wide: Vec<u16> =
                    args.encode_utf16().chain(std::iter::once(0)).collect();

                let result = CreateProcessW(
                    PCWSTR(exe_wide.as_ptr()),
                    Some(PWSTR(args_wide.as_mut_ptr())),
                    None,
                    None,
                    false,
                    CREATE_NEW_CONSOLE,
                    None,
                    PCWSTR(cur_dir_wide.as_ptr()),
                    &startup_info,
                    &mut process_info_struct,
                );

                match result {
                    Ok(_) => {
                        println!(
                            "Successfully created new process with PID: {}",
                            process_info_struct.dwProcessId
                        );
                        CloseHandle(process_info_struct.hProcess);
                        CloseHandle(process_info_struct.hThread);
                    }
                    Err(e) => {
                        println!("Failed to create process: {:?}", e);
                        return Err(e);
                    }
                }
            }
        } else {
            println!("Process with PID {} not found", pid);
        }

        Ok(())
    }

    fn parse_command_line(&self, command_line: &str, executable_path: &str) -> (String, String) {
        if command_line.is_empty() {
            return (executable_path.to_string(), String::new());
        }

        // Simple command line parsing - handles quoted executables
        let trimmed = command_line.trim();

        if trimmed.starts_with('"') {
            // Find the closing quote for the executable
            if let Some(end_quote) = trimmed[1..].find('"') {
                let executable = trimmed[1..end_quote + 1].to_string();
                let args = trimmed[end_quote + 2..].trim().to_string();
                return (executable, args);
            }
        }

        // Simple space-based splitting
        let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();

        if parts.len() == 1 {
            (trimmed.to_string(), String::new())
        } else {
            (parts[0].to_string(), parts[1].to_string())
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut process_manager = ProcessManager::new();

    loop {
        println!("\n=== Windows Process Manager ===");
        println!("1. List all processes");
        println!("2. Refresh process list");
        println!("3. Duplicate a process");
        println!("4. Monitor AppData\\Local\\Temp for new files with prefix");
        println!("5. Exit");
        print!("Enter your choice: ");

        use std::io::{self, Write};
        io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        match input.trim() {
            "1" => {
                if process_manager.processes.is_empty() {
                    println!("Loading processes...");
                    process_manager.refresh_processes()?;
                }
                process_manager.list_processes();
            }
            "2" => {
                println!("Refreshing process list...");
                process_manager.refresh_processes()?;
                println!(
                    "Process list refreshed. Found {} processes.",
                    process_manager.processes.len()
                );
            }
            "3" => {
                if process_manager.processes.is_empty() {
                    println!("Loading processes...");
                    process_manager.refresh_processes()?;
                }

                print!("Enter PID to duplicate: ");
                io::stdout().flush()?;
                let mut pid_input = String::new();
                std::io::stdin().read_line(&mut pid_input)?;

                if let Ok(pid) = pid_input.trim().parse::<u32>() {
                    if let Err(e) = process_manager.duplicate_process(pid) {
                        println!("Error duplicating process: {:?}", e);
                    }
                } else {
                    println!("Invalid PID format");
                }
            }
            "4" => {
                print!("Enter file prefix to monitor: ");
                io::stdout().flush()?;
                let mut prefix = String::new();
                std::io::stdin().read_line(&mut prefix)?;
                let prefix = prefix.trim().to_string();
                println!("Press Ctrl+C to stop monitoring.");
                monitor::monitor_appdata_for_prefix(&prefix);
            }
            "5" => {
                println!("Goodbye!");
                break;
            }
            _ => {
                println!("Invalid choice. Please try again.");
            }
        }
    }

    Ok(())
}
