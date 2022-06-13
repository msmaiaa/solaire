mod util;
use num::traits::ToPrimitive;
use std::ffi::c_void;
use std::ptr;
pub use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

use windows::Win32::Foundation::{CHAR, HANDLE, HINSTANCE};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32First, Module32Next, Process32First, Process32Next,
    MODULEENTRY32, PROCESSENTRY32, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};

custom_error::custom_error! {pub MemError
    ProcessSnapshotError = "Failed to create a snapshot of the processes.",
    FirstProcessError = "Failed to get the first process.",
        FirstModuleError = "Failed to get the first module of the process.",
        ReadMemError = "Failed to read memory.",
        WriteMemError = "Failed to write memory.",
}

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

pub fn get_processes() -> Result<Vec<Process>, MemError> {
    let h_snapshot;
    unsafe {
        match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(handle) => h_snapshot = handle,
            Err(_) => return Err(MemError::ProcessSnapshotError),
        };
    }
    let mut proc_entry = PROCESSENTRY32 {
        dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };
    let mut result: Vec<Process> = Vec::new();
    let proc;
    unsafe {
        proc = Process32First(h_snapshot, &mut proc_entry);
        match proc.as_bool() {
            true => {
                result.push(build_process(&proc_entry));
                loop {
                    let proc = Process32Next(h_snapshot, &mut proc_entry);
                    match proc.as_bool() {
                        true => result.push(build_process(&proc_entry)),
                        _ => break,
                    }
                }
            }
            _ => return Err(MemError::FirstProcessError),
        }
    }
    Ok(result)
}

pub fn get_process(name: String) -> Option<Process> {
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

pub fn get_process_module(pid: u32, mod_name: String) -> Result<ProcessModule, MemError> {
    let h_snapshot;
    unsafe {
        match CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) {
            Ok(handle) => h_snapshot = handle,
            Err(_) => return Err(MemError::ProcessSnapshotError),
        };
    }
    let mut mod_entry = MODULEENTRY32 {
        dwSize: std::mem::size_of::<MODULEENTRY32>() as u32,
        ..Default::default()
    };
    unsafe {
        match Module32First(h_snapshot, &mut mod_entry).as_bool() {
            true => loop {
                if util::wchar_arr_to_string(&mod_entry.szModule) == mod_name {
                    return Ok(build_process_module(&mod_entry));
                }
                Module32Next(h_snapshot, &mut mod_entry);
            },
            _ => return Err(MemError::FirstModuleError),
        }
    }
}

pub fn read_mem<T: ToPrimitive>(handle: HANDLE, addr: T) -> Result<T, MemError> {
    let mut buf: T = unsafe { std::mem::zeroed() };
    unsafe {
        match ReadProcessMemory(
            handle,
            addr.to_usize().unwrap() as *mut c_void,
            ptr::addr_of_mut!(buf) as *mut c_void,
            std::mem::size_of::<T>(),
            ptr::null_mut(),
        )
        .as_bool()
        {
            true => Ok(buf),
            _ => return Err(MemError::ReadMemError),
        }
    }
}

pub fn write_mem<T: Copy, K: ToPrimitive>(handle: HANDLE, addr: K, val: T) -> Result<(), MemError> {
    unsafe {
        match WriteProcessMemory(
            handle,
            addr.to_usize().unwrap() as *mut c_void,
            ptr::addr_of!(val) as *mut c_void,
            std::mem::size_of::<T>(),
            ptr::null_mut(),
        )
        .as_bool()
        {
            true => Ok(()),
            _ => return Err(MemError::WriteMemError),
        }
    }
}

fn build_process_module(mod_entry: &MODULEENTRY32) -> ProcessModule {
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
        str_szModule: util::wchar_arr_to_string(&mod_entry.szModule),
        szExePath: mod_entry.szExePath,
        str_szExePath: util::wchar_arr_to_string(&mod_entry.szExePath),
    }
}

fn build_process(proc_entry: &PROCESSENTRY32) -> Process {
    Process {
        str_szExeFile: util::wchar_arr_to_string(&proc_entry.szExeFile),
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
