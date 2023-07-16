use crate::prelude::CHAR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32First, Module32Next, Process32First, Process32Next,
    MODULEENTRY32, PROCESSENTRY32, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS};

use crate::util::wchar_arr_to_string;

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

/// Iterator over all processes
#[derive(Debug)]
pub struct ProcessList {
    proc: PROCESSENTRY32,
    h_snap: HANDLE,
    first: bool,
}

impl ProcessList {
    pub fn new() -> Result<Self, windows::core::Error> {
        let mut proc = PROCESSENTRY32::default();
        proc.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
        let h_snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? };
        if !unsafe { Process32First(h_snap, &mut proc).as_bool() } {
            return Err(windows::core::Error::from_win32());
        }
        Ok(Self {
            proc,
            h_snap,
            first: true,
        })
    }
}

impl Iterator for ProcessList {
    type Item = Process;

    fn next(&mut self) -> Option<Self::Item> {
        if self.first {
            self.first = false;
        } else if !unsafe { Process32Next(self.h_snap, &mut self.proc).as_bool() } {
            return None;
        }
        Some(self.proc.into())
    }
}

impl Process {
    pub fn get_module<T: Into<String>>(
        &self,
        mod_name: T,
    ) -> Result<Option<MODULEENTRY32>, windows::core::Error> {
        let mod_name = mod_name.into();

        unsafe {
            let h_snap = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                self.th32ProcessID,
            )?;
            let mut mod_entry = MODULEENTRY32::default();
            mod_entry.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;

            if !Module32First(h_snap, &mut mod_entry).as_bool() {
                return Ok(None);
            }

            loop {
                if wchar_arr_to_string(&mod_entry.szModule) == mod_name {
                    return Ok(Some(mod_entry));
                }
                if !Module32Next(h_snap, &mut mod_entry).as_bool() {
                    break;
                }
            }
        }
        Ok(None)
    }

    pub fn module_base_addr<T: Into<String>>(
        &self,
        mod_name: T,
    ) -> Result<Option<*mut u8>, windows::core::Error> {
        self.get_module(mod_name).map(|m| m.map(|m| m.modBaseAddr))
    }

    pub fn open(
        &self,
        dwdesiredaccess: PROCESS_ACCESS_RIGHTS,
    ) -> Result<HANDLE, windows::core::Error> {
        unsafe { OpenProcess(dwdesiredaccess, false, self.th32ProcessID) }
    }

    pub fn from_pid(pid: u32) -> Result<Option<Process>, windows::core::Error> {
        Ok(ProcessList::new()?.find(|p| p.th32ProcessID == pid))
    }

    pub fn from_executable_name<S: Into<String>>(
        name: S,
    ) -> Result<Option<Process>, windows::core::Error> {
        let name = name.into();
        Ok(ProcessList::new()?.find(|p| p.str_szExeFile == name))
    }
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

#[cfg(target_os = "windows")]
#[cfg(test)]
mod test {
    use super::ProcessList;

    #[test]
    fn process_iterator_sanity_check() {
        let mut processes = vec![];
        for process in ProcessList::new().unwrap() {
            processes.push(process);
            break;
        }
        assert!(processes.len() > 0);
    }
}
