pub mod cursor;
pub mod file_header;
pub mod import_table;
pub mod optional_header;
pub mod section_table;

use thiserror::Error;
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_DIRECTORY_ENTRY, IMAGE_DIRECTORY_ENTRY_IMPORT,
};

use self::{
    import_table::{get_import_table, ImportTable},
    optional_header::{ExecutableKind, ImageDataDirectory},
};

#[derive(Clone)]
pub struct PortableExecutable {
    pub nt_headers: NtHeaders,
    pub section_table: section_table::SectionTable,
    pub executable_type: ExecutableKind,
    bytes: Vec<u8>,
}

impl std::fmt::Debug for PortableExecutable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortableExecutable")
            .field("nt_headers", &self.nt_headers)
            .field("section_table", &self.section_table)
            .field("executable_type", &self.executable_type)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct NtHeaders {
    pub pe_signature: u16,
    pub file_header: file_header::FileHeader,
    pub opt_header: optional_header::OptionalHeader,
}

#[derive(Error, Debug)]
pub enum PeError {
    #[error("Io Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Parse Error: {0}")]
    ParseError(String),
    #[error("Missing Section: {0}")]
    MissingSection(String),
    #[error("Missing Table: {0}")]
    MissingTable(String),
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

        //  skip the 2 null bytes
        cursor.skip(2);

        let file_header = file_header::parse_file_header(&mut cursor)?;

        //  FIXME: skip is optional, do i even check if it's there or not?
        let opt_header = optional_header::parse_opt_header(&mut cursor)?;
        let magic = opt_header.std_fields.magic.clone();
        let section_table =
            section_table::parse_section_headers(&mut cursor, file_header.number_of_sections)?;

        let nt_headers = NtHeaders {
            pe_signature,
            file_header,
            opt_header,
        };
        Ok(PortableExecutable {
            nt_headers,
            executable_type: magic,
            section_table,
            bytes: cursor.bytes,
        })
    }

    pub fn get_import_table(&self) -> Result<ImportTable, PeError> {
        get_import_table(
            &self.section_table,
            &self.bytes,
            &self.executable_type,
            self.nt_headers.opt_header.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize]
                .clone(),
        )
    }

    pub fn get_image_directory(&self, entry: IMAGE_DIRECTORY_ENTRY) -> ImageDataDirectory {
        self.nt_headers.opt_header.data_directories[entry.0 as usize].clone()
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
