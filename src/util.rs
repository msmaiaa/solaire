use windows::Win32::Foundation::CHAR;

pub fn wchar_arr_to_string(arr: &[CHAR]) -> String {
    let mut result = String::new();
    for c in arr.iter() {
        if c.0 == 0 {
            break;
        }
        result.push(c.0 as u8 as char);
    }
    result
}
