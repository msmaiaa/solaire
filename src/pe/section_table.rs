#![allow(non_camel_case_types)]

use super::{
    cursor::Cursor,
    optional_header::{ExecutableKind, ImageDataDirectory},
    PeError,
};
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct SectionTable {
    pub section_headers: Vec<SectionHeader>,
}

impl SectionTable {
    pub fn get_section_header(&self, name: &str) -> Option<&SectionHeader> {
        //  FIXME: correctly compare the names
        self.section_headers
            .iter()
            .find(|section| section.name.contains(name))
    }

    /// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-directory-table
    pub fn get_import_table(
        &self,
        bytes: &Vec<u8>,
        exec_kind: &ExecutableKind,
    ) -> Result<ImportTable, PeError> {
        let header = self
            .get_section_header(".idata")
            .ok_or(PeError::MissingSection(
                "Could not find the .idata section".to_string(),
            ))?;

        let mut cursor = Cursor::new(header.raw_data.clone());
        let mut image_descriptors = vec![];
        loop {
            let mut entry = ImageImportDescriptor {
                import_lookup_table_rva: cursor.read_u32(),
                timedate_stamp: cursor.read_u32(),
                forwarder_chain: cursor.read_u32(),
                name_rva: cursor.read_u32(),
                import_address_table_rva: cursor.read_u32(),
                name: "".to_string(),
                characteristics: 0,
                import_lookup_table: ImportLookupTable { entries: vec![] },
            };
            if entry.import_lookup_table_rva == 0
                && entry.name_rva == 0
                && entry.timedate_stamp == 0
                && entry.forwarder_chain == 0
                && entry.import_address_table_rva == 0
            {
                break;
            }

            //  fuck microsoft docs
            let get_name = || {
                let name_offset = entry.name_rva - header.virtual_address;
                let name_address = header.ptr_to_raw_data + name_offset;

                let mut name = vec![];
                let mut idx = 0;
                loop {
                    let byte = bytes[name_address as usize + idx];
                    if byte == 0 {
                        break;
                    }
                    name.push(byte);
                    idx += 1;
                }
                return name;
            };

            let get_characteristics = || {
                let characteristics_offset = entry.import_lookup_table_rva - header.virtual_address;
                let characteristics_address = header.ptr_to_raw_data + characteristics_offset;
                return characteristics_address;
            };

            //  https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-lookup-table
            let get_thunk_table = || {
                let thunk_offset = entry.import_address_table_rva - header.virtual_address;
                let starting_address = header.ptr_to_raw_data + thunk_offset;
                match exec_kind {
                    //  FIXME: i'm not done
                    ExecutableKind::PE32 => {
                        let mut cursor = Cursor::new(bytes[starting_address as usize..].to_vec());
                        let mut entries = vec![];
                        loop {
                            let data = cursor.read_u32();
                            if data == 0 {
                                break;
                            }
                            let msb = get_msb_u32(data);
                            entries.push(data);
                        }
                        return vec![];
                    }
                    ExecutableKind::PE32_PLUS => {
                        const BIT_MASK: u64 = 0x8000000000000000;
                        let mut cursor = Cursor::new(bytes[starting_address as usize..].to_vec());
                        let mut entries = vec![];
                        loop {
                            let data = cursor.read_u64();
                            if data == 0 {
                                break;
                            }
                            let msb = get_msb_u64(data);
                            let is_ordinal = (msb & BIT_MASK) != 0;
                            if is_ordinal {
                                //  FIXME: i'm not done
                                let result = data & !BIT_MASK;
                            } else {
                                let import_by_name_offset = data & 0x7FFFFFFF; // Mask out the MSB
                                let import_by_name_address = (import_by_name_offset
                                    - header.virtual_address as u64)
                                    + header.ptr_to_raw_data as u64;
                                let hint = u16::from_le_bytes([
                                    bytes[import_by_name_address as usize],
                                    bytes[import_by_name_address as usize + 1],
                                ]);

                                let function_name_bytes =
                                    &bytes[(import_by_name_address as usize + 2)..];

                                let mut func_bytes = vec![];
                                let mut idx = 0;
                                loop {
                                    let byte = function_name_bytes[idx];
                                    if byte == 0 {
                                        break;
                                    }
                                    func_bytes.push(byte);
                                    idx += 1;
                                }
                                entries.push(ImportLookupTableEntry {
                                    hint,
                                    is_ordinal,
                                    name: func_bytes,
                                })
                            };
                        }
                        return entries;
                    }
                }
            };
            entry.import_lookup_table.entries = get_thunk_table();
            entry.name = String::from_utf8(get_name()).unwrap();
            entry.characteristics = get_characteristics();
            image_descriptors.push(entry);
        }

        Ok(ImportTable { image_descriptors })
    }

    /// FIXME: i'm not done
    pub fn get_export_table_x64(&self) -> Result<Vec<ExportTableEntryX64>, PeError> {
        let header = self
            .get_section_header(".pdata")
            .ok_or(PeError::MissingSection(
                "Could not find the .pdata section".to_string(),
            ))?;
        let mut cursor = Cursor::new(header.raw_data.clone());
        let mut entries = vec![];
        loop {
            let entry = ExportTableEntryX64 {
                begin_address: cursor.read_u32(),
                end_address: cursor.read_u32(),
                unwind_info_address: cursor.read_u32(),
            };
            if entry.begin_address == 0 && entry.end_address == 0 && entry.unwind_info_address == 0
            {
                break;
            }
            entries.push(entry);
        }

        Ok(vec![])
    }
}

fn get_msb_u64(num: u64) -> u64 {
    (num >> 63) & 1
}

fn get_msb_u32(num: u32) -> u32 {
    (num >> 31) & 1
}

#[derive(Debug, Clone)]
pub struct ImportLookupTable {
    pub entries: Vec<ImportLookupTableEntry>,
}

#[derive(Debug, Clone)]
pub struct ImportLookupTableEntry {
    pub hint: u16,
    pub is_ordinal: bool,
    pub name: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ImportTable {
    pub image_descriptors: Vec<ImageImportDescriptor>,
}

impl std::fmt::Display for ImportTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for descriptor in &self.image_descriptors {
            writeln!(f, "name: {}", descriptor.name)?;
            writeln!(
                f,
                "import_lookup_table_rva: {:#x}",
                descriptor.import_lookup_table_rva
            )?;
            writeln!(f, "timedate_stamp: {:#x}", descriptor.timedate_stamp)?;
            writeln!(f, "forwarder_chain: {:#x}", descriptor.forwarder_chain)?;
            writeln!(f, "name_rva: {:#x}", descriptor.name_rva)?;
            writeln!(
                f,
                "import_address_table_rva: {:#x}",
                descriptor.import_address_table_rva
            )?;
            writeln!(f, "characteristics: {:#x}", descriptor.characteristics)?;
            writeln!(f, "import_lookup_table:")?;
            for entry in &descriptor.import_lookup_table.entries {
                writeln!(f, "\tis_ordinal: {}", entry.is_ordinal)?;
                writeln!(f, "\thint: {:#x}", entry.hint)?;
                writeln!(
                    f,
                    "\tname: {}",
                    String::from_utf8(entry.name.clone()).unwrap()
                )?;
                writeln!(f, "-------------------")?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ExportTableEntryX64 {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_info_address: u32,
}

#[derive(Debug, Clone)]
pub struct ImageImportDescriptor {
    pub import_lookup_table_rva: u32,
    pub timedate_stamp: u32,
    pub forwarder_chain: u32,
    pub name_rva: u32,
    pub import_address_table_rva: u32,

    ///  not in MS docs
    pub name: String,
    pub characteristics: u32, // FIXME: Need to parse to flags?,
    pub import_lookup_table: ImportLookupTable,
}

/// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
pub fn parse_section_header(cursor: &mut Cursor) -> Result<SectionHeader, PeError> {
    let mut result = SectionHeader {
        name: cursor.read_str(8).to_string(),
        virtual_size: cursor.read_u32(),
        virtual_address: cursor.read_u32(),
        size_of_raw_data: cursor.read_u32(),
        ptr_to_raw_data: cursor.read_u32(),
        ptr_to_relocations: cursor.read_u32(),
        ptr_to_linenumbers: cursor.read_u32(),
        number_of_relocations: cursor.read_u16(),
        number_of_linenumbers: cursor.read_u16(),
        characteristics: format!("0x{:x}", cursor.read_u32())
            .parse::<SectionFlags>()
            .map_err(|e| {
                PeError::ParseError(format!("Could not parse the section flags: {}", e))
            })?,
        raw_data: vec![],
    };
    result.raw_data = cursor.bytes[result.ptr_to_raw_data as usize
        ..result.ptr_to_raw_data as usize + result.size_of_raw_data as usize]
        .to_vec();
    Ok(result)
}

pub fn parse_section_headers(
    cursor: &mut Cursor,
    number_of_sections: u16,
) -> Result<SectionTable, PeError> {
    let section_headers = (0..number_of_sections)
        .map(|_| parse_section_header(cursor))
        .collect::<Result<Vec<SectionHeader>, PeError>>()?;
    Ok(SectionTable { section_headers })
}

/// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
#[derive(Debug, Clone)]
pub struct SectionHeader {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub ptr_to_raw_data: u32,
    pub ptr_to_relocations: u32,
    pub ptr_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: SectionFlags,

    ///  not in MS docs
    pub raw_data: Vec<u8>,
}

impl std::fmt::Display for SectionHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "\tname: {}", self.name)?;
        writeln!(f, "\tvirtual_size: {:#x}", self.virtual_size)?;
        writeln!(f, "\tvirtual_address: {:#x}", self.virtual_address)?;
        writeln!(f, "\tsize_of_raw_data: {:#x}", self.size_of_raw_data)?;
        writeln!(f, "\tptr_to_raw_data: {:#x}", self.ptr_to_raw_data)?;
        writeln!(f, "\tptr_to_relocations: {:#x}", self.ptr_to_relocations)?;
        writeln!(f, "\tptr_to_linenumbers: {:#x}", self.ptr_to_linenumbers)?;
        writeln!(f, "\tnumber_of_relocations: {}", self.number_of_relocations)?;
        writeln!(f, "\tnumber_of_linenumbers: {}", self.number_of_linenumbers)?;
        //writeln!(f, "\tcharacteristics: {:?}", self.characteristics)?;
        Ok(())
    }
}

impl SectionHeader {
    //  TODO: test this
    /// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-relocations-object-only
    pub fn coff_relocations<'a>(
        &self,
        memory: &'a Vec<u8>,
    ) -> Result<Vec<CoffRelocation>, PeError> {
        let mut cursor = Cursor::new(
            memory[self.ptr_to_relocations as usize
                ..self.ptr_to_relocations as usize + (self.number_of_relocations as usize * 10)]
                .into(),
        );
        (0..self.number_of_relocations)
            .map(|_| {
                Ok(CoffRelocation {
                    virtual_address: cursor.read_u32(),
                    symbol_table_index: cursor.read_u32(),
                    r#type: TypeIndicatorX64::try_from(cursor.read_u16())?,
                })
            })
            .collect()
    }

    //  https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-line-numbers-deprecated
    pub fn coff_line_numbers<'a>(&self, memory: &'a Vec<u8>) -> Vec<LineNumber> {
        let mut cursor = Cursor::new(
            memory[self.ptr_to_linenumbers as usize
                ..self.ptr_to_linenumbers as usize + (self.number_of_linenumbers as usize * 6)]
                .into(),
        );
        let mut line_nums = vec![];
        for _ in 0..self.number_of_linenumbers {
            line_nums.push(LineNumber {
                r#type: cursor.read_u32(),
                linenumber: cursor.read_u16(),
            });
        }
        line_nums
    }

    //  FIXME: i'm not done
    //  https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-symbol-table
    pub fn coff_symbol_table<'a>(
        &self,
        memory: &'a Vec<u8>,
        ptr_to_start: u32,
    ) -> Vec<SymbolTableRecord> {
        let mut cursor = Cursor::new(
            memory[ptr_to_start as usize
                ..ptr_to_start as usize + (self.number_of_relocations * 18) as usize]
                .into(),
        );

        let mut records = vec![];
        for _ in 0..self.number_of_relocations {
            let result = SymbolTableRecord::Standard(StandardSymbolRecord {
                name: SymbolName {
                    short_name: cursor.read_u32(),
                    zeroes: cursor.read_u16(),
                    offset: cursor.read_u16(),
                },
                value: cursor.read_u32(),
                section_number: SectionNumber::from(cursor.read_i16()),
                r#type: SymbolType::from(cursor.read_u16()),
                storage_class: StorageClass::from(cursor.read_u8()),
                number_of_aux_symbols: cursor.read_u8(),
            });
            records.push(result);
        }
        records
    }
}

#[derive(Debug, Clone)]
pub enum SymbolTableRecord {
    Standard(StandardSymbolRecord),
    Auxiliary(AuxiliarySymbolRecord),
}

/// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-symbol-table
#[derive(Debug, Clone)]
pub struct StandardSymbolRecord {
    pub name: SymbolName,
    pub value: u32,
    pub section_number: SectionNumber,
    pub r#type: SymbolType,
    pub storage_class: StorageClass,
    pub number_of_aux_symbols: u8,
}

impl StandardSymbolRecord {
    pub fn is_function_definition(&self) -> bool {
        let num: i16 = self.section_number.clone() as i16;
        self.storage_class == StorageClass::IMAGE_SYM_CLASS_EXTERNAL
            && self.r#type == SymbolType::FUNCTION
            && num > 0
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AuxiliarySymbolRecord {
    ///  https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#auxiliary-format-1-function-definitions
    FnDefinitions {
        tag_index: u32,
        total_size: u32,
        ptr_to_linenumber: u32,
        ptr_to_next_fn: u32,
        unused: u16,
    },
    /// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#auxiliary-format-2-bf-and-ef-symbols
    BfAndEf {
        unused: u32,
        linenumber: u16,
        unused2: [u8; 6],
        ptr_to_next_fn: u32,
        unused3: u16,
    },
    /// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#auxiliary-format-3-weak-externals
    /// TODO: change characteristics
    WeakExternals {
        tag_index: u32,
        characteristics: u32,
        unused: [u8; 10],
    },
    /// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#auxiliary-format-4-files
    Files { file_name: [u8; 18] },
    /// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#auxiliary-format-5-section-definitions
    SectionDefinitions {
        length: u32,
        number_of_relocations: u16,
        number_of_linenumbers: u16,
        checksum: u32,
        number: u16,
        selection: u8,
        unused: [u8; 3],
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SectionNumber {
    IMAGE_SYM_UNDEFINED,
    IMAGE_SYM_ABSOLUTE,
    IMAGE_SYM_DEBUG,
}

impl From<i16> for SectionNumber {
    fn from(value: i16) -> Self {
        match value {
            0 => SectionNumber::IMAGE_SYM_UNDEFINED,
            -1 => SectionNumber::IMAGE_SYM_ABSOLUTE,
            -2 => SectionNumber::IMAGE_SYM_DEBUG,
            _ => panic!("Invalid section number"),
        }
    }
}

/// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#storage-class
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum StorageClass {
    IMAGE_SYM_CLASS_END_OF_FUNCTION,
    IMAGE_SYM_CLASS_NULL,
    IMAGE_SYM_CLASS_AUTOMATIC,
    IMAGE_SYM_CLASS_EXTERNAL,
    IMAGE_SYM_CLASS_STATIC,
    IMAGE_SYM_CLASS_REGISTER,
    IMAGE_SYM_CLASS_EXTERNAL_DEF,
    IMAGE_SYM_CLASS_LABEL,
    IMAGE_SYM_CLASS_UNDEFINED_LABEL,
    IMAGE_SYM_CLASS_MEMBER_OF_STRUCT,
    IMAGE_SYM_CLASS_ARGUMENT,
    IMAGE_SYM_CLASS_STRUCT_TAG,
    IMAGE_SYM_CLASS_MEMBER_OF_UNION,
    IMAGE_SYM_CLASS_UNION_TAG,
    IMAGE_SYM_CLASS_TYPE_DEFINITION,
    IMAGE_SYM_CLASS_UNDEFINED_STATIC,
    IMAGE_SYM_CLASS_ENUM_TAG,
    IMAGE_SYM_CLASS_MEMBER_OF_ENUM,
    IMAGE_SYM_CLASS_REGISTER_PARAM,
    IMAGE_SYM_CLASS_BIT_FIELD,
    IMAGE_SYM_CLASS_BLOCK,
    IMAGE_SYM_CLASS_FUNCTION,
    IMAGE_SYM_CLASS_END_OF_STRUCT,
    IMAGE_SYM_CLASS_FILE,
    IMAGE_SYM_CLASS_SECTION,
    IMAGE_SYM_CLASS_WEAK_EXTERNAL,
    IMAGE_SYM_CLASS_CLR_TOKEN,
}

impl From<u8> for StorageClass {
    fn from(value: u8) -> Self {
        match value {
            0xFF => StorageClass::IMAGE_SYM_CLASS_END_OF_FUNCTION,
            0 => StorageClass::IMAGE_SYM_CLASS_NULL,
            1 => StorageClass::IMAGE_SYM_CLASS_AUTOMATIC,
            2 => StorageClass::IMAGE_SYM_CLASS_EXTERNAL,
            3 => StorageClass::IMAGE_SYM_CLASS_STATIC,
            4 => StorageClass::IMAGE_SYM_CLASS_REGISTER,
            5 => StorageClass::IMAGE_SYM_CLASS_EXTERNAL_DEF,
            6 => StorageClass::IMAGE_SYM_CLASS_LABEL,
            7 => StorageClass::IMAGE_SYM_CLASS_UNDEFINED_LABEL,
            8 => StorageClass::IMAGE_SYM_CLASS_MEMBER_OF_STRUCT,
            9 => StorageClass::IMAGE_SYM_CLASS_ARGUMENT,
            10 => StorageClass::IMAGE_SYM_CLASS_STRUCT_TAG,
            11 => StorageClass::IMAGE_SYM_CLASS_MEMBER_OF_UNION,
            12 => StorageClass::IMAGE_SYM_CLASS_UNION_TAG,
            13 => StorageClass::IMAGE_SYM_CLASS_TYPE_DEFINITION,
            14 => StorageClass::IMAGE_SYM_CLASS_UNDEFINED_STATIC,
            15 => StorageClass::IMAGE_SYM_CLASS_ENUM_TAG,
            16 => StorageClass::IMAGE_SYM_CLASS_MEMBER_OF_ENUM,
            17 => StorageClass::IMAGE_SYM_CLASS_REGISTER_PARAM,
            18 => StorageClass::IMAGE_SYM_CLASS_BIT_FIELD,
            100 => StorageClass::IMAGE_SYM_CLASS_BLOCK,
            101 => StorageClass::IMAGE_SYM_CLASS_FUNCTION,
            102 => StorageClass::IMAGE_SYM_CLASS_END_OF_STRUCT,
            103 => StorageClass::IMAGE_SYM_CLASS_FILE,
            104 => StorageClass::IMAGE_SYM_CLASS_SECTION,
            105 => StorageClass::IMAGE_SYM_CLASS_WEAK_EXTERNAL,
            107 => StorageClass::IMAGE_SYM_CLASS_CLR_TOKEN,
            _ => panic!("Invalid storage class"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SymbolName {
    pub short_name: u32,
    pub zeroes: u16,
    pub offset: u16,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SymbolType {
    IMAGE_SYM_TYPE_NULL,
    IMAGE_SYM_TYPE_VOID,
    IMAGE_SYM_TYPE_CHAR,
    IMAGE_SYM_TYPE_SHORT,
    IMAGE_SYM_TYPE_INT,
    IMAGE_SYM_TYPE_LONG,
    IMAGE_SYM_TYPE_FLOAT,
    IMAGE_SYM_TYPE_DOUBLE,
    IMAGE_SYM_TYPE_STRUCT,
    IMAGE_SYM_TYPE_UNION,
    IMAGE_SYM_TYPE_ENUM,
    IMAGE_SYM_TYPE_MOE,
    IMAGE_SYM_TYPE_BYTE,
    IMAGE_SYM_TYPE_WORD,
    IMAGE_SYM_TYPE_UINT,
    IMAGE_SYM_TYPE_DWORD,
    IMAGE_SYM_TYPE_PCODE,
    FUNCTION,
}

impl From<u16> for SymbolType {
    fn from(value: u16) -> Self {
        match value {
            0 => SymbolType::IMAGE_SYM_TYPE_NULL,
            1 => SymbolType::IMAGE_SYM_TYPE_VOID,
            2 => SymbolType::IMAGE_SYM_TYPE_CHAR,
            3 => SymbolType::IMAGE_SYM_TYPE_SHORT,
            4 => SymbolType::IMAGE_SYM_TYPE_INT,
            5 => SymbolType::IMAGE_SYM_TYPE_LONG,
            6 => SymbolType::IMAGE_SYM_TYPE_FLOAT,
            7 => SymbolType::IMAGE_SYM_TYPE_DOUBLE,
            8 => SymbolType::IMAGE_SYM_TYPE_STRUCT,
            9 => SymbolType::IMAGE_SYM_TYPE_UNION,
            10 => SymbolType::IMAGE_SYM_TYPE_ENUM,
            11 => SymbolType::IMAGE_SYM_TYPE_MOE,
            12 => SymbolType::IMAGE_SYM_TYPE_BYTE,
            13 => SymbolType::IMAGE_SYM_TYPE_WORD,
            14 => SymbolType::IMAGE_SYM_TYPE_UINT,
            15 => SymbolType::IMAGE_SYM_TYPE_DWORD,
            0x20 => SymbolType::FUNCTION,
            _ => panic!("Invalid symbol type"),
        }
    }
}

//  FIXME: type is a union of two 4-byte fields
#[derive(Debug, Clone)]
pub struct LineNumber {
    pub r#type: u32,
    pub linenumber: u16,
}

/// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-relocations-object-only
#[derive(Debug, Clone)]
pub struct CoffRelocation {
    pub virtual_address: u32,
    pub symbol_table_index: u32,
    pub r#type: TypeIndicatorX64,
}

//  TODO: support other archs
/// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#x64-processors
#[derive(Debug, Clone)]
pub enum TypeIndicatorX64 {
    IMAGE_REL_AMD64_ABSOLUTE,
    IMAGE_REL_AMD64_ADDR64,
    IMAGE_REL_AMD64_ADDR32,
    IMAGE_REL_AMD64_ADDR32NB,
    IMAGE_REL_AMD64_REL32,
    IMAGE_REL_AMD64_REL32_1,
    IMAGE_REL_AMD64_REL32_2,
    IMAGE_REL_AMD64_REL32_3,
    IMAGE_REL_AMD64_REL32_4,
    IMAGE_REL_AMD64_REL32_5,
    IMAGE_REL_AMD64_SECTION,
    IMAGE_REL_AMD64_SECREL,
    IMAGE_REL_AMD64_SECREL7,
    IMAGE_REL_AMD64_TOKEN,
    IMAGE_REL_AMD64_SREL32,
    IMAGE_REL_AMD64_PAIR,
    IMAGE_REL_AMD64_SSPAN32,
}

impl TryFrom<u16> for TypeIndicatorX64 {
    type Error = PeError;

    fn try_from(value: u16) -> Result<Self, PeError> {
        match value {
            0x0000 => Ok(TypeIndicatorX64::IMAGE_REL_AMD64_ABSOLUTE),
            0x0001 => Ok(TypeIndicatorX64::IMAGE_REL_AMD64_ADDR64),
            0x0002 => Ok(TypeIndicatorX64::IMAGE_REL_AMD64_ADDR32),
            0x0003 => Ok(TypeIndicatorX64::IMAGE_REL_AMD64_ADDR32NB),
            0x0004 => Ok(TypeIndicatorX64::IMAGE_REL_AMD64_REL32),
            0x0005 => Ok(TypeIndicatorX64::IMAGE_REL_AMD64_REL32_1),
            0x0006 => Ok(TypeIndicatorX64::IMAGE_REL_AMD64_REL32_2),
            0x0007 => Ok(TypeIndicatorX64::IMAGE_REL_AMD64_REL32_3),
            0x0008 => Ok(TypeIndicatorX64::IMAGE_REL_AMD64_REL32_4),
            0x0009 => Ok(TypeIndicatorX64::IMAGE_REL_AMD64_REL32_5),
            0x000A => Ok(TypeIndicatorX64::IMAGE_REL_AMD64_SECTION),
            0x000B => Ok(TypeIndicatorX64::IMAGE_REL_AMD64_SECREL),
            0x000C => Ok(TypeIndicatorX64::IMAGE_REL_AMD64_SECREL7),
            0x000D => Ok(TypeIndicatorX64::IMAGE_REL_AMD64_TOKEN),
            0x000E => Ok(TypeIndicatorX64::IMAGE_REL_AMD64_SREL32),
            0x000F => Ok(TypeIndicatorX64::IMAGE_REL_AMD64_PAIR),
            0x0010 => Ok(TypeIndicatorX64::IMAGE_REL_AMD64_SSPAN32),
            _ => Err(PeError::ParseError(format!(
                "Invalid type indicator: {:#x?}",
                value
            ))),
        }
    }
}

bitflags::bitflags! {
    /// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct SectionFlags: u32 {
        const RESERVED0 = 0x0000;
        const RESERVED1 = 0x0001;
        const RESERVED2 = 0x0002;
        const RESERVED3 = 0x0004;
        const IMAGE_SCN_TYPE_NO_PAD = 0x0008;
        const RESERVED4 = 0x0010;
        const IMAGE_SCN_CNT_CODE = 0x0020;
        const IMAGE_SCN_CNT_INITIALIZED_DATA = 0x0040;
        const IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x0080;
        const IMAGE_SCN_LNK_OTHER = 0x0100;
        const IMAGE_SCN_LNK_INFO = 0x0200;
        const RESERVED5 = 0x0400;
        const IMAGE_SCN_LNK_REMOVE = 0x0800;
        const IMAGE_SCN_LNK_COMDAT = 0x1000;
        const IMAGE_SCN_GPREL = 0x8000;
        const IMAGE_SCN_MEM_PURGEABLE = 0x2000;
        const IMAGE_SCN_MEM_16BIT = 0x2000;
        const IMAGE_SCN_MEM_LOCKED = 0x4000;
        const IMAGE_SCN_MEM_PRELOAD = 0x1000000;
        const IMAGE_SCN_ALIGN_1BYTES = 0x00100000;
        const IMAGE_SCN_ALIGN_2BYTES = 0x00200000;
        const IMAGE_SCN_ALIGN_4BYTES = 0x00300000;
        const IMAGE_SCN_ALIGN_8BYTES = 0x00400000;
        const IMAGE_SCN_ALIGN_16BYTES = 0x00500000;
        const IMAGE_SCN_ALIGN_32BYTES = 0x00600000;
        const IMAGE_SCN_ALIGN_64BYTES = 0x00700000;
        const IMAGE_SCN_ALIGN_128BYTES = 0x00800000;
        const IMAGE_SCN_ALIGN_256BYTES = 0x00900000;
        const IMAGE_SCN_ALIGN_512BYTES = 0x00A00000;
        const IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000;
        const IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000;
        const IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000;
        const IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000;
        const IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000;
        const IMAGE_SCN_MEM_DISCARDABLE = 0x02000000;
        const IMAGE_SCN_MEM_NOT_CACHED = 0x04000000;
        const IMAGE_SCN_MEM_NOT_PAGED = 0x08000000;
        const IMAGE_SCN_MEM_SHARED = 0x10000000;
        const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
        const IMAGE_SCN_MEM_READ = 0x40000000;
        const IMAGE_SCN_MEM_WRITE = 0x80000000;
    }
}

impl FromStr for SectionFlags {
    type Err = bitflags::parser::ParseError;

    fn from_str(flags: &str) -> Result<Self, Self::Err> {
        bitflags::parser::from_str(flags)
    }
}
