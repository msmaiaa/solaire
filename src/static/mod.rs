pub mod coff;
pub mod cursor;
pub mod optional_header;
pub mod section_table;

#[derive(Clone, Debug)]
pub struct PortableExecutable {
    pub stub: u16,
    pub stub_offset: u8,
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

        let stub = cursor.read_u16();
        cursor.skip(58);
        let stub_offset = cursor.read(1);
        let stub_offset = *stub_offset.first().unwrap();
        cursor.skip((stub_offset as usize - cursor.position) as usize);
        let pe_signature = cursor.read_u16();
        cursor.skip(2);

        let coff_header = coff::parse_coff(&mut cursor);
        let opt_header = optional_header::parse_opt_header(&mut cursor);
        let sections = (0..coff_header.numbers_of_sections)
            .map(|_| section_table::parse_section_table(&mut cursor))
            .collect::<Vec<_>>();

        PortableExecutable {
            stub,
            stub_offset,
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
