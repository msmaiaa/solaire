use super::cursor::Cursor;
use std::str::FromStr;

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

bitflags::bitflags! {
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
