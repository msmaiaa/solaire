#![allow(non_camel_case_types)]

use std::str::FromStr;

use super::cursor::Cursor;

pub fn parse_coff(cursor: &mut Cursor) -> CoffHeader {
    let header = CoffHeader {
        machine: Machine::try_from(cursor.read_u16()).expect("Invalid machine type"),
        numbers_of_sections: cursor.read_u16(),
        time_date_stamp: cursor.read_u32(),
        pointer_to_symbol_table: cursor.read_u32(),
        number_of_symbols: cursor.read_u32(),
        size_of_optional_header: cursor.read_u16(),
        characteristics: format!("0x{:x}", cursor.read_u16())
            .parse::<Characteristic>()
            .unwrap(),
    };
    header
}

#[derive(Debug, Clone)]
pub struct CoffHeader {
    pub machine: Machine,
    pub numbers_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: Characteristic,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Machine {
    IMAGE_FILE_MACHINE_UNKNOWN,
    IMAGE_FILE_MACHINE_ALPHA,
    IMAGE_FILE_MACHINE_ALPHA64,
    IMAGE_FILE_MACHINE_AM33,
    IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_ARM,
    IMAGE_FILE_MACHINE_ARM64,
    IMAGE_FILE_MACHINE_ARMNT,
    IMAGE_FILE_MACHINE_EBC,
    IMAGE_FILE_MACHINE_I386,
    IMAGE_FILE_MACHINE_IA64,
    IMAGE_FILE_MACHINE_LOONGARCH32,
    IMAGE_FILE_MACHINE_LOONGARCH64,
    IMAGE_FILE_MACHINE_M32R,
    IMAGE_FILE_MACHINE_MIPS16,
    IMAGE_FILE_MACHINE_MIPSFPU,
    IMAGE_FILE_MACHINE_MIPSFPU16,
    IMAGE_FILE_MACHINE_POWERPC,
    IMAGE_FILE_MACHINE_POWERPCFP,
    IMAGE_FILE_MACHINE_R4000,
    IMAGE_FILE_MACHINE_RISCV32,
    IMAGE_FILE_MACHINE_RISCV64,
    IMAGE_FILE_MACHINE_RISCV128,
    IMAGE_FILE_MACHINE_SH3,
    IMAGE_FILE_MACHINE_SH3DSP,
    IMAGE_FILE_MACHINE_SH4,
    IMAGE_FILE_MACHINE_SH5,
    IMAGE_FILE_MACHINE_THUMB,
    IMAGE_FILE_MACHINE_WCEMIPSV2,
}

impl Default for Machine {
    fn default() -> Self {
        Self::IMAGE_FILE_MACHINE_UNKNOWN
    }
}

impl TryFrom<u16> for Machine {
    type Error = ();
    fn try_from(val: u16) -> Result<Self, ()> {
        match val {
            0x0 => Ok(Self::IMAGE_FILE_MACHINE_UNKNOWN),
            0x184 => Ok(Self::IMAGE_FILE_MACHINE_ALPHA),
            0x284 => Ok(Self::IMAGE_FILE_MACHINE_ALPHA64),
            0x1d3 => Ok(Self::IMAGE_FILE_MACHINE_AM33),
            0x8664 => Ok(Self::IMAGE_FILE_MACHINE_AMD64),
            0x1c0 => Ok(Self::IMAGE_FILE_MACHINE_ARM),
            0xaa64 => Ok(Self::IMAGE_FILE_MACHINE_ARM64),
            0x1c4 => Ok(Self::IMAGE_FILE_MACHINE_ARMNT),
            0xebc => Ok(Self::IMAGE_FILE_MACHINE_EBC),
            0x14c => Ok(Self::IMAGE_FILE_MACHINE_I386),
            0x200 => Ok(Self::IMAGE_FILE_MACHINE_IA64),
            0x6232 => Ok(Self::IMAGE_FILE_MACHINE_LOONGARCH32),
            0x6264 => Ok(Self::IMAGE_FILE_MACHINE_LOONGARCH64),
            0x9041 => Ok(Self::IMAGE_FILE_MACHINE_M32R),
            0x266 => Ok(Self::IMAGE_FILE_MACHINE_MIPS16),
            0x366 => Ok(Self::IMAGE_FILE_MACHINE_MIPSFPU),
            0x466 => Ok(Self::IMAGE_FILE_MACHINE_MIPSFPU16),
            0x1f0 => Ok(Self::IMAGE_FILE_MACHINE_POWERPC),
            0x1f1 => Ok(Self::IMAGE_FILE_MACHINE_POWERPCFP),
            0x166 => Ok(Self::IMAGE_FILE_MACHINE_R4000),
            0x5032 => Ok(Self::IMAGE_FILE_MACHINE_RISCV32),
            0x5064 => Ok(Self::IMAGE_FILE_MACHINE_RISCV64),
            0x5128 => Ok(Self::IMAGE_FILE_MACHINE_RISCV128),
            0x1a2 => Ok(Self::IMAGE_FILE_MACHINE_SH3),
            0x1a3 => Ok(Self::IMAGE_FILE_MACHINE_SH3DSP),
            0x1a6 => Ok(Self::IMAGE_FILE_MACHINE_SH4),
            0x1a8 => Ok(Self::IMAGE_FILE_MACHINE_SH5),
            0x1c2 => Ok(Self::IMAGE_FILE_MACHINE_THUMB),
            0x169 => Ok(Self::IMAGE_FILE_MACHINE_WCEMIPSV2),
            _ => Err(()),
        }
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct Characteristic: u16 {
        const IMAGE_FILE_RELOCS_STRIPPED = 0x0001;
        const IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
        const IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004;
        const IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008;
        const IMAGE_FILE_AGGRESSIVE_WS_TRIM = 0x0010;
        const IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020;
        const IMAGE_FILE_BYTES_REVERSED_LO = 0x0080;
        const IMAGE_FILE_32BIT_MACHINE = 0x0100;
        const IMAGE_FILE_DEBUG_STRIPPED = 0x0200;
        const IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400;
        const IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800;
        const IMAGE_FILE_SYSTEM = 0x1000;
        const IMAGE_FILE_DLL = 0x2000;
        const IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000;
        const IMAGE_FILE_BYTES_REVERSED_HI = 0x8000;
    }
}

impl FromStr for Characteristic {
    type Err = bitflags::parser::ParseError;

    fn from_str(flags: &str) -> Result<Self, Self::Err> {
        bitflags::parser::from_str(flags)
    }
}

impl Default for Characteristic {
    fn default() -> Self {
        Self::IMAGE_FILE_EXECUTABLE_IMAGE
    }
}
