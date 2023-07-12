use solaire::r#static::PortableExecutable;

fn main() {
    let pe = PortableExecutable::from_file("./sample_executable.exe");
    //println!("{:#x?}", coff_header);
    //println!("{:#x?}", opt_header);
    println!("{:#x?}", pe.sections);
}
