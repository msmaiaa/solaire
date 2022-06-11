use std::io::{Error, ErrorKind};

use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;

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

fn wchar_arr_to_string(arr: &[CHAR; 260]) -> String {
    let mut result = String::new();
    for c in arr.iter() {
        if c.0 == 0 {
            break;
        }
        result.push(c.0 as u8 as char);
    }
    result
}
