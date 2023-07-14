use crate::prelude::CHAR;

pub fn wchar_arr_to_string(arr: &[CHAR]) -> String {
    let mut result = String::new();
    for c in arr.into_iter() {
        if *c == 0 {
            break;
        }
        result.push(*c as char);
    }
    result
}

pub fn u32_from_bytes(le_bytes: &[u8]) -> u32 {
    let result = u32::from_le_bytes(le_bytes[0..4].try_into().unwrap());
    result
}

pub fn u16_from_bytes(le_bytes: &[u8]) -> u16 {
    let result = u16::from_le_bytes(le_bytes[0..2].try_into().unwrap());
    result
}

pub fn i16_from_bytes(le_bytes: &[u8]) -> i16 {
    let result = i16::from_le_bytes(le_bytes[0..2].try_into().unwrap());
    result
}

pub fn u64_from_bytes(le_bytes: &[u8]) -> u64 {
    let result = u64::from_le_bytes(le_bytes[0..8].try_into().unwrap());
    result
}
