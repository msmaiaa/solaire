use winsafe::co::ERROR;

use crate::core::UINTPTR_T;

#[allow(unused_variables)]
pub fn find_multilevel_ptr_x64(
    starting_address: UINTPTR_T,
    offsets: Vec<u64>,
) -> Result<UINTPTR_T, ERROR> {
    unimplemented!();
}

#[allow(unused_variables)]
pub fn find_multilevel_ptr_x86(
    starting_address: UINTPTR_T,
    offsets: Vec<u32>,
) -> Result<UINTPTR_T, ERROR> {
    unimplemented!();
}
