use std::io::{Error, ErrorKind};

use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;

#[allow(non_snake_case)]
pub struct Process {
    pub dwSize: u32,
    pub cntUsage: u32,
    pub th32ProcessID: u32,
    pub th32DefaultHeapID: usize,
    pub th32ModuleID: u32,
    pub cntThreads: u32,
    pub th32ParentProcessID: u32,
    pub pcPriClassBase: i32,
    pub dwFlags: u32,
    pub szExeFile: [CHAR; 260],
    pub str_szExeFile: String,
}

#[allow(non_snake_case)]
pub struct ProcessModule {
    pub dwSize: u32,
    pub th32ModuleID: u32,
    pub th32ProcessID: u32,
    pub GlblcntUsage: u32,
    pub ProccntUsage: u32,
    pub modBaseAddr: *mut u8,
    pub modBaseSize: u32,
    pub hModule: HINSTANCE,
    pub szModule: [CHAR; 256],
    pub szExePath: [CHAR; 260],
    pub str_szModule: String,
    pub str_szExePath: String,
}

pub unsafe fn get_processes() -> Result<Vec<Process>, Error> {
    let h_snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
        Ok(handle) => handle,
        Err(_) => {
            return Err(Error::new(
                ErrorKind::Other,
                "Failed to create snapshot of the processes.",
            ))
        }
    };
    let mut proc_entry = PROCESSENTRY32 {
        dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };
    let mut result: Vec<Process> = Vec::new();
    let proc = Process32First(h_snapshot, &mut proc_entry);
    match proc.as_bool() {
        true => {
            result.push(parse_processentry32(&proc_entry));
            loop {
                let proc = Process32Next(h_snapshot, &mut proc_entry);
                match proc.as_bool() {
                    true => result.push(parse_processentry32(&proc_entry)),
                    _ => break,
                }
            }
        }
        _ => return Err(Error::new(ErrorKind::Other, "Failed to get first process.")),
    }
    Ok(result)
}

pub unsafe fn get_process(name: String) -> Option<Process> {
    match get_processes() {
        Ok(processes) => {
            for process in processes {
                if process.str_szExeFile == name {
                    return Some(process);
                }
            }
            None
        }
        Err(_) => None,
    }
}

pub unsafe fn get_process_module(pid: u32, mod_name: String) -> Result<ProcessModule, Error> {
    let h_snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) {
        Ok(handle) => handle,
        Err(_) => {
            return Err(Error::new(
                ErrorKind::Other,
                "Failed to create snapshot of the processes.",
            ))
        }
    };
    let mut mod_entry = MODULEENTRY32 {
        dwSize: std::mem::size_of::<MODULEENTRY32>() as u32,
        ..Default::default()
    };
    match Module32First(h_snapshot, &mut mod_entry).as_bool() {
        true => loop {
            if wchar_arr_to_string(&mod_entry.szModule) == mod_name {
                return Ok(parse_moduleentry32(&mod_entry));
            }
            Module32Next(h_snapshot, &mut mod_entry);
        },
        _ => return Err(Error::new(ErrorKind::Other, "Failed to get first module.")),
    }
}

fn parse_moduleentry32(mod_entry: &MODULEENTRY32) -> ProcessModule {
    ProcessModule {
        th32ModuleID: mod_entry.th32ModuleID,
        th32ProcessID: mod_entry.th32ProcessID,
        GlblcntUsage: mod_entry.GlblcntUsage,
        ProccntUsage: mod_entry.ProccntUsage,
        modBaseAddr: mod_entry.modBaseAddr,
        modBaseSize: mod_entry.modBaseSize,
        hModule: mod_entry.hModule,
        dwSize: mod_entry.dwSize,
        szModule: mod_entry.szModule,
        str_szModule: wchar_arr_to_string(&mod_entry.szModule),
        szExePath: mod_entry.szExePath,
        str_szExePath: wchar_arr_to_string(&mod_entry.szExePath),
    }
}

fn parse_processentry32(proc_entry: &PROCESSENTRY32) -> Process {
    Process {
        str_szExeFile: wchar_arr_to_string(&proc_entry.szExeFile),
        dwSize: proc_entry.dwSize,
        cntUsage: proc_entry.cntUsage,
        th32ProcessID: proc_entry.th32ProcessID,
        th32DefaultHeapID: proc_entry.th32DefaultHeapID,
        th32ModuleID: proc_entry.th32ModuleID,
        cntThreads: proc_entry.cntThreads,
        th32ParentProcessID: proc_entry.th32ParentProcessID,
        pcPriClassBase: proc_entry.pcPriClassBase,
        dwFlags: proc_entry.dwFlags,
        szExeFile: proc_entry.szExeFile,
    }
}

fn wchar_arr_to_string(arr: &[CHAR]) -> String {
    let mut result = String::new();
    for c in arr.iter() {
        if c.0 == 0 {
            break;
        }
        result.push(c.0 as u8 as char);
    }
    result
}
