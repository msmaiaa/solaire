pub mod coff;
pub mod cursor;
pub mod optional_header;
pub mod section_table;

#[derive(Clone, Debug)]
pub struct PortableExecutable {
    pub pe_signature: u16,
    pub coff_header: coff::CoffHeader,
    pub opt_header: optional_header::OptionalHeader,
    pub sections: Vec<section_table::SectionTable>,
}

impl PortableExecutable {
    pub fn from_file(path: impl Into<String>) -> PortableExecutable {
        let file = std::fs::read(path.into()).unwrap();
        PortableExecutable::from(file)
    }

    fn parse(data: impl Into<Vec<u8>>) -> Self {
        let mut cursor = cursor::Cursor::new(data.into());

        let mz = cursor.read_u16();
        tracing::debug!("mz: {:#x?}", mz);

        let mut pe_signature = cursor.read_u16();
        while pe_signature != 0x4550 {
            pe_signature = cursor.read_u16();
        }
        tracing::info!("got the pe_signature: {:#x?}", pe_signature);

        //  skip the 2 null bytes
        cursor.skip(2);

        let coff_header = coff::parse_coff(&mut cursor);
        let opt_header = optional_header::parse_opt_header(&mut cursor);
        let sections = (0..coff_header.numbers_of_sections)
            .map(|_| section_table::parse_section_table(&mut cursor))
            .collect::<Vec<_>>();
        tracing::info!("coff_header: {:#x?}", coff_header);

        for section in &sections {
            tracing::info!(
                "section: {} - {:#x?}",
                section.name,
                section.coff_symbol_table(&cursor.data, coff_header.pointer_to_symbol_table)
            );
        }
        PortableExecutable {
            pe_signature,
            coff_header,
            opt_header,
            sections,
        }
    }
}

impl From<Vec<u8>> for PortableExecutable {
    fn from(data: Vec<u8>) -> Self {
        Self::parse(data)
    }
}

impl From<&[u8]> for PortableExecutable {
    fn from(data: &[u8]) -> Self {
        Self::parse(data)
    }
}

impl From<&str> for PortableExecutable {
    fn from(data: &str) -> Self {
        Self::parse(data)
    }
}

impl From<String> for PortableExecutable {
    fn from(data: String) -> Self {
        Self::parse(data)
    }
}
