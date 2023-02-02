use std::ffi::c_void;

use windows::Win32::Foundation::{CHAR, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};
use winsafe::co::{self, ERROR};
use winsafe::{prelude::kernel_Hprocesslist, HPROCESSLIST};

use crate::util::wchar_arr_to_string;

#[allow(non_camel_case_types)]
pub type UINTPTR_T = *mut c_void;

pub enum MemError {
    ProcessSnapshotError,
    FirstProcessError,
}

pub fn get_module_base_addr<S: Into<String>>(
    proc_id: u32,
    mod_name: S,
) -> Result<Option<UINTPTR_T>, ERROR> {
    let mod_name = mod_name.into();
    let hpl = HPROCESSLIST::CreateToolhelp32Snapshot(
        co::TH32CS::SNAPMODULE | co::TH32CS::SNAPMODULE32,
        Some(proc_id),
    )?;

    for _mod in hpl.iter_modules() {
        if let Ok(mod_entry) = _mod {
            if mod_entry.szModule() == mod_name {
                return Ok(Some(mod_entry.modBaseAddr));
            }
        }
    }
    Ok(None)
}

pub fn get_process_by_id(pid: u32) -> Result<Option<Process>, windows::core::Error> {
    get_process_list().map(|p| p.into_iter().find(|p| p.th32ProcessID == pid))
}

//  lazy but works for now
pub fn get_process_by_exec<S: Into<String>>(
    name: S,
) -> Result<Option<Process>, windows::core::Error> {
    let name = name.into();
    get_process_list().map(|p| p.into_iter().find(|p| p.str_szExeFile == name))
}

pub fn get_process_list() -> Result<Vec<Process>, windows::core::Error> {
    let mut processes = Vec::new();
    unsafe {
        let h_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;

        let mut proc_entry = PROCESSENTRY32::default();
        proc_entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        if !Process32First(h_snap, &mut proc_entry).as_bool() {
            return Ok(processes);
        }

        loop {
            processes.push(proc_entry.into());
            if !Process32Next(h_snap, &mut proc_entry).as_bool() {
                break;
            }
        }
    }
    Ok(processes)
}

#[allow(non_snake_case)]
#[derive(Debug, Clone)]
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

impl From<PROCESSENTRY32> for Process {
    fn from(proc_entry: PROCESSENTRY32) -> Self {
        Self {
            dwSize: proc_entry.dwSize,
            cntUsage: proc_entry.cntUsage,
            th32ProcessID: proc_entry.th32ProcessID,
            th32DefaultHeapID: proc_entry.th32DefaultHeapID as usize,
            th32ModuleID: proc_entry.th32ModuleID,
            cntThreads: proc_entry.cntThreads,
            th32ParentProcessID: proc_entry.th32ParentProcessID,
            pcPriClassBase: proc_entry.pcPriClassBase,
            dwFlags: proc_entry.dwFlags,
            szExeFile: proc_entry.szExeFile,
            str_szExeFile: wchar_arr_to_string(&proc_entry.szExeFile),
        }
    }
}

pub fn open_process(proc_id: u32) -> Result<HANDLE, windows::core::Error> {
    unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, proc_id) }
}
