#![allow(non_camel_case_types)]

use super::cursor::Cursor;
use std::str::FromStr;

/// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
pub fn parse_section_table(cursor: &mut Cursor) -> SectionTable {
    SectionTable {
        name: cursor.read_str(8).to_string(),
        virtual_size: cursor.read_u32(),
        virtual_address: cursor.read_u32(),
        size_of_raw_data: cursor.read_u32(),
        pointer_to_raw_data: cursor.read_u32(),
        pointer_to_relocations: cursor.read_u32(),
        pointer_to_linenumbers: cursor.read_u32(),
        number_of_relocations: cursor.read_u16(),
        number_of_linenumbers: cursor.read_u16(),
        characteristics: format!("0x{:x}", cursor.read_u32())
            .parse::<SectionFlags>()
            .unwrap(),
    }
}

/// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
#[derive(Debug, Clone)]
pub struct SectionTable {
    name: String,
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: SectionFlags,
}

impl SectionTable {
    pub fn get_raw_data<'a>(&self, memory: &'a Vec<u8>) -> &'a [u8] {
        let start = self.pointer_to_raw_data as usize;
        let end = start + self.size_of_raw_data as usize;
        &memory[start..end]
    }

    //  TODO: test this
    /// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-relocations-object-only
    pub fn get_coff_relocations<'a>(&self, memory: &'a Vec<u8>) -> Vec<CoffRelocation> {
        let mut start = self.pointer_to_relocations as usize;
        let end = start + (self.number_of_relocations as usize * 10);
        let mut relocations = vec![];
        loop {
            if start >= end {
                break;
            }
            if memory[start] == 0 && memory[start + 1] == 0 {
                break;
            }
            let relocation = CoffRelocation {
                virtual_address: u32::from_le_bytes([
                    memory[start],
                    memory[start + 1],
                    memory[start + 2],
                    memory[start + 3],
                ]),
                symbol_table_index: u32::from_le_bytes([
                    memory[start + 4],
                    memory[start + 5],
                    memory[start + 6],
                    memory[start + 7],
                ]),
                r#type: TypeIndicatorX64::try_from(u16::from_le_bytes([
                    memory[start + 8],
                    memory[start + 9],
                ]))
                .expect("Invalid relocation type"),
            };
            relocations.push(relocation);
            start += 10;
        }
        relocations
    }
}

/// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-relocations-object-only
#[derive(Debug, Clone)]
pub struct CoffRelocation {
    virtual_address: u32,
    symbol_table_index: u32,
    r#type: TypeIndicatorX64,
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
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
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
            _ => Err(()),
        }
    }
}

bitflags::bitflags! {
    /// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct SectionFlags: u32 {
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
