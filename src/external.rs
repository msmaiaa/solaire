use std::{ffi::c_void, mem::size_of, ptr::addr_of};

use windows::Win32::{
    Foundation::{GetLastError, HANDLE},
    System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
};
use winsafe::co::ERROR;

use crate::core::UINTPTR_T;

pub fn read_mem<T>(h_proc: HANDLE, address: usize) -> Result<T, ERROR> {
    let result: T = unsafe { std::mem::zeroed() };
    let ok;
    unsafe {
        ok = ReadProcessMemory(
            h_proc,
            address as *mut c_void,
            addr_of!(result) as *mut c_void,
            size_of::<T>(),
            None,
        );
    }
    return match ok.as_bool() {
        true => Ok(result),
        false => Err(unsafe { GetLastError().0.into() }),
    };
}

macro_rules! gen_multilevel_ptr {
    ($arch: ty, $label: ident) => {
        paste::paste! {
            pub fn [<get_multilevel_ptr_$label>](
                h_proc: HANDLE,
                starting_address: UINTPTR_T,
                offsets: Vec<$arch>,
            ) -> Result<UINTPTR_T, ERROR> {
                let mut addr = starting_address as $arch;

                for offset in offsets {
                        addr = [<read_mem_$arch>](h_proc, addr as usize)?;
                    addr = addr + offset;
                }
                Ok(addr as *mut c_void)
            }

        }
    };
}

gen_multilevel_ptr!(u32, x86);
gen_multilevel_ptr!(u64, x64);

/// gen_mem_read!(u32) expands to:
/// ```
/// pub fn read_mem_u32(h_proc: HANDLE, address: usize) -> Result<u32, ERROR> {
///     read_mem(h_proc, address);
/// }
/// ```
/// /// gen_mem_read!(cstring, std::ffi::CString) expands to:
/// ```
/// pub fn read_mem_cstring(h_proc: HANDLE, address: usize) -> Result<std::ffi::CString, ERROR> {
///     read_mem(h_proc, address);
/// }
/// ```

macro_rules! gen_mem_read {
    ($func_name: ident, $return_type: ty) => {
        paste::paste! {
            pub fn [<read_mem_$func_name>](h_proc: HANDLE, address: usize) -> Result<$return_type, ERROR> {
                read_mem(h_proc, address)
            }

        }
    };
    ($return_type: ty) => {
        paste::paste! {
            pub fn [<read_mem_$return_type>](h_proc: HANDLE, address: usize) -> Result<$return_type, ERROR> {
                read_mem(h_proc, address)
            }
        }
    };
}

gen_mem_read!(cstring, std::ffi::CString);
gen_mem_read!(u32);
gen_mem_read!(f32);
gen_mem_read!(u64);
gen_mem_read!(f64);

pub fn write_mem<T>(h_proc: HANDLE, address: UINTPTR_T, value: T) -> Result<(), ERROR> {
    let ok;
    unsafe {
        ok = WriteProcessMemory(
            h_proc,
            address,
            addr_of!(value) as *mut c_void,
            size_of::<T>(),
            None,
        );
    }
    return match ok.as_bool() {
        true => Ok(()),
        false => Err(unsafe { GetLastError().0.into() }),
    };
}