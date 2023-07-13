use solaire::r#static::PortableExecutable;

fn main() {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    let _pe = PortableExecutable::from_file("./sample_executable.exe");

    //println!("{:#x?}", pe.coff_header);
    //println!("{:#x?}", opt_header);
    //println!("{:#x?}", );
}
