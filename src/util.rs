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
