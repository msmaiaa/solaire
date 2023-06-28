use std::{ffi::c_void, mem::size_of, ptr::addr_of};

use windows::Win32::{
    Foundation::{GetLastError, HANDLE, WIN32_ERROR},
    System::{
        Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
        Memory::{VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS},
    },
};

pub fn read_mem<T>(h_proc: HANDLE, address: usize) -> Result<T, WIN32_ERROR> {
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
        false => Err(unsafe { GetLastError() }),
    };
}

macro_rules! gen_multilevel_ptr {
    ($_type: ty) => {
        paste::paste! {
            pub fn [<get_multilevel_ptr_$_type>](
                h_proc: HANDLE,
                starting_address: *mut c_void,
                offsets: Vec<$_type>,
            ) -> Result<*mut c_void, WIN32_ERROR> {
                let mut addr = starting_address as $_type;

                for offset in offsets {
                        addr = [<read_mem_$_type>](h_proc, addr as usize)?;
                    addr = addr + offset;
                }
                Ok(addr as *mut c_void)
            }

        }
    };
}

gen_multilevel_ptr!(u32);
gen_multilevel_ptr!(u64);

macro_rules! gen_mem_read {
    ($func_name: ident, $return_type: ty) => {
        paste::paste! {
            pub fn [<read_mem_$func_name>](h_proc: HANDLE, address: usize) -> Result<$return_type, WIN32_ERROR> {
                read_mem(h_proc, address)
            }

        }
    };
    ($return_type: ty) => {
        paste::paste! {
            pub fn [<read_mem_$return_type>](h_proc: HANDLE, address: usize) -> Result<$return_type, WIN32_ERROR> {
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

pub fn write_mem<T>(h_proc: HANDLE, address: *mut c_void, value: T) -> Result<(), WIN32_ERROR> {
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
        false => Err(unsafe { GetLastError() }),
    };
}

macro_rules! gen_patch {
    ($_type: ty) => {
        paste::paste! {
            pub fn [<patch_$_type>](dest: $_type, src: *const u8, size: usize, h_proc: HANDLE) {
                let mut old_protect = PAGE_PROTECTION_FLAGS::default();
                unsafe {
                    VirtualProtectEx(
                        h_proc,
                        dest as *mut c_void,
                        size,
                        PAGE_EXECUTE_READWRITE,
                        &mut old_protect,
                    );
                    WriteProcessMemory(
                        h_proc,
                        dest as *mut c_void,
                        src as *mut c_void,
                        size,
                        None,
                    );
                    VirtualProtectEx(
                        h_proc,
                        dest as *mut c_void,
                        size,
                        old_protect,
                        &mut old_protect,
                    );
                }
            }
        }
    };
}

gen_patch!(u64);
gen_patch!(u32);

pub fn nop_32(dest: u32, size: usize, h_proc: HANDLE) {
    let nop_array: *mut u8 = vec![0x90; size].as_mut_ptr();
    patch_u32(dest, nop_array, size, h_proc);
}

pub fn nop_64(dest: u64, size: usize, h_proc: HANDLE) {
    let nop_array: *mut u8 = vec![0x90; size].as_mut_ptr();
    patch_u64(dest, nop_array, size, h_proc);
}
