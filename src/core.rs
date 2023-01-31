use std::ffi::c_void;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};
use winsafe::co::{self, ERROR};
use winsafe::{prelude::kernel_Hprocesslist, HPROCESSLIST};

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

pub fn get_process_by_id(_: u32) -> Result<PROCESSENTRY32, MemError> {
    unimplemented!();
}

pub fn open_process(proc_id: u32) -> Result<HANDLE, windows::core::Error> {
    unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, proc_id) }
}
