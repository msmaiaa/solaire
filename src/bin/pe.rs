use solaire::pe::PortableExecutable;

fn main() {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    let pe = PortableExecutable::from_file(
        "F:\\SteamLibrary\\steamapps\\common\\Resident Evil 5\\re5dx9.exe",
    )
    .unwrap();
    //tracing::info!("PE: {:#x?}", pe.opt_header);
    tracing::info!("{:#x?}", pe.nt_headers);

    // for s in pe.get_import_table().unwrap().image_descriptors {
    //     tracing::info!("DLL: {}", s.name);
    //     tracing::info!("{:#x?}", s);
    //     for f in s.import_lookup_table.entries {
    //         println!("{} - {}", f.name(), f.func_ptr_address);
    //     }
    // }
}
