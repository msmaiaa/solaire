use solaire::r#static::{
    coff::parse_coff, cursor::Cursor, optional_header::parse_opt_header,
    section_table::parse_section_table,
};

fn main() {
    let file = std::fs::read("./sample_executable.exe").unwrap();
    let mut cursor = Cursor::new(file);

    let stub = cursor.read_str(2);
    cursor.skip(58);
    let stub_offset = cursor.read(1);
    cursor.skip((*stub_offset.first().unwrap() as usize - cursor.position) as usize);
    let pe_signature = cursor.read_str(2);
    cursor.skip(2);

    let coff_header = parse_coff(&mut cursor);
    let opt_header = parse_opt_header(&mut cursor);
    let sections = (0..coff_header.numbers_of_sections)
        .map(|_| parse_section_table(&mut cursor))
        .collect::<Vec<_>>();
    //println!("{:#x?}", coff_header);
    //println!("{:#x?}", opt_header);
    //println!("{:#x?}", sections);
    // println!(
    //     "Read {} bytes out of {}",
    //     cursor.position,
    //     cursor.data.len()
    // );
}
