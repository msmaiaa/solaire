use crate::r#static::section_table::parse_section_headers;

pub mod coff;
pub mod cursor;
pub mod optional_header;
pub mod section_table;

#[derive(Clone, Debug)]
pub struct PortableExecutable {
    pub pe_signature: u16,
    pub coff_header: coff::CoffHeader,
    pub opt_header: optional_header::OptionalHeader,
    pub section_headers: Vec<section_table::SectionHeader>,
}

impl PortableExecutable {
    pub fn from_file(path: impl Into<String>) -> PortableExecutable {
        let file = std::fs::read(path.into()).unwrap();
        PortableExecutable::from(file)
    }

    fn parse(data: impl Into<Vec<u8>>) -> Self {
        let mut cursor = cursor::Cursor::new(data.into());
        let memory = &cursor.data;

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

        //  FIXME: skip is optional, do i even check if it's there or not?
        let opt_header = optional_header::parse_opt_header(&mut cursor);
        tracing::info!("opt_header: {:#x?}", opt_header);
        let section_headers = parse_section_headers(&mut cursor, coff_header.number_of_sections);
        // tracing::info!("coff_header: {:#x?}", coff_header);

        for section in &section_headers {
            tracing::info!(
                "section: {:?} - virtual offset: {:#x?} - virtual size: {:#x?} - ptr_raw_data: {:#x?}",
                section.name,
                section.virtual_address,
                section.virtual_size,
                section.pointer_to_raw_data
            );
        }
        PortableExecutable {
            pe_signature,
            coff_header,
            opt_header,
            section_headers,
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
