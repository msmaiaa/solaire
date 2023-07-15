pub mod coff;
pub mod cursor;
pub mod optional_header;
pub mod section_table;
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct PortableExecutable {
    pub pe_signature: u16,
    pub coff_header: coff::CoffHeader,
    pub opt_header: optional_header::OptionalHeader,
    pub section_table: section_table::SectionTable,
}

#[derive(Error, Debug)]
pub enum PeError {
    #[error("Io Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Parse Error: {0}")]
    ParseError(String),
    #[error("Missing Section: {0}")]
    MissingSection(String),
}

//  TODO: parse the string tables
impl PortableExecutable {
    pub fn from_file(path: impl Into<String>) -> Result<PortableExecutable, PeError> {
        let file = std::fs::read(path.into())?;
        PortableExecutable::try_from(file)
    }

    fn parse(bytes: impl Into<Vec<u8>>) -> Result<Self, PeError> {
        let mut cursor = cursor::Cursor::new(bytes.into());
        let mz = cursor.read_u16();
        tracing::debug!("mz: {:#x?}", mz);

        let mut pe_signature = cursor.read_u16();
        let max_offset = cursor.bytes.len() - 2;
        while pe_signature != 0x4550 {
            if cursor.position >= max_offset {
                return Err(PeError::ParseError(
                    "Could not find the PE signature".to_string(),
                ));
            }
            pe_signature = cursor.read_u16();
        }

        tracing::debug!("got the pe_signature: {:#x?}", pe_signature);

        //  skip the 2 null bytes
        cursor.skip(2);

        let coff_header = coff::parse_coff(&mut cursor)?;

        //  FIXME: skip is optional, do i even check if it's there or not?
        let opt_header = optional_header::parse_opt_header(&mut cursor)?;
        let section_table =
            section_table::parse_section_headers(&mut cursor, coff_header.number_of_sections)?;

        tracing::info!("{:#x?}", opt_header);
        tracing::info!(
            "{}",
            section_table
                .get_import_table(&cursor.bytes, &opt_header.std_fields.magic)
                .unwrap()
        );
        Ok(PortableExecutable {
            pe_signature,
            coff_header,
            opt_header,
            section_table,
        })
    }
}

impl TryFrom<Vec<u8>> for PortableExecutable {
    type Error = PeError;
    fn try_from(data: Vec<u8>) -> Result<Self, PeError> {
        Self::parse(data)
    }
}

impl TryFrom<&[u8]> for PortableExecutable {
    type Error = PeError;
    fn try_from(data: &[u8]) -> Result<Self, PeError> {
        Self::parse(data)
    }
}

impl TryFrom<&str> for PortableExecutable {
    type Error = PeError;
    fn try_from(data: &str) -> Result<Self, PeError> {
        Self::parse(data)
    }
}

impl TryFrom<String> for PortableExecutable {
    type Error = PeError;
    fn try_from(data: String) -> Result<Self, PeError> {
        Self::parse(data)
    }
}
