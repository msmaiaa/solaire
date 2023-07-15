#![allow(non_camel_case_types)]

use std::str::FromStr;

use super::{cursor::Cursor, PeError};

pub fn parse_opt_header(cursor: &mut Cursor) -> Result<OptionalHeader, PeError> {
    use ExecutableKind::{PE32, PE32_PLUS};
    let magic = ExecutableKind::try_from(cursor.read_u16())?;
    let major_minor = &cursor.read(2);
    let std_fields = StandardFields {
        major_linker_version: major_minor[0],
        minor_linker_version: major_minor[1],
        size_of_code: cursor.read_u32(),
        size_of_initialized_data: cursor.read_u32(),
        size_of_uninitialized_data: cursor.read_u32(),
        address_of_entry_point: cursor.read_u32(),
        base_of_code: cursor.read_u32(),
        base_of_data: match magic {
            PE32 => Some(cursor.read_u32()),
            PE32_PLUS => None,
        },
        magic,
    };

    let win_specific_fields = WindowsSpecificFields {
        image_base: match std_fields.magic {
            PE32 => ImageBase::PE32(cursor.read_u32()),
            PE32_PLUS => ImageBase::PE32_PLUS(cursor.read_u64()),
        },
        section_alignment: cursor.read_u32(),
        file_alignment: cursor.read_u32(),
        major_os_version: cursor.read_u16(),
        minor_os_version: cursor.read_u16(),
        major_image_version: cursor.read_u16(),
        minor_image_version: cursor.read_u16(),
        major_subsystem_version: cursor.read_u16(),
        minor_subsystem_version: cursor.read_u16(),
        win32_version_value: cursor.read_u32(),
        size_of_image: cursor.read_u32(),
        size_of_headers: cursor.read_u32(),
        checksum: cursor.read_u32(),
        subsystem: WindowsSubsystem::try_from(cursor.read_u16())?,

        dll_characteristics: format!("0x{:x}", cursor.read_u16())
            .parse::<DllCharacteristics>()
            .map_err(|e| {
                PeError::ParseError(format!(
                    "Could not parse the Optional Header's DLL characteristics: {}",
                    e
                ))
            })?,
        size_of_stack_reserve: match std_fields.magic {
            PE32 => SizeOfStackReserve::PE32(cursor.read_u32()),
            PE32_PLUS => SizeOfStackReserve::PE32_PLUS(cursor.read_u64()),
        },
        size_of_stack_commit: match std_fields.magic {
            PE32 => SizeOfStackCommit::PE32(cursor.read_u32()),
            PE32_PLUS => SizeOfStackCommit::PE32_PLUS(cursor.read_u64()),
        },
        size_of_heap_reserve: match std_fields.magic {
            PE32 => SizeOfHeapReserve::PE32(cursor.read_u32()),
            PE32_PLUS => SizeOfHeapReserve::PE32_PLUS(cursor.read_u64()),
        },
        size_of_heap_commit: match std_fields.magic {
            PE32 => SizeOfHeapCommit::PE32(cursor.read_u32()),
            PE32_PLUS => SizeOfHeapCommit::PE32_PLUS(cursor.read_u64()),
        },
        loader_flags: cursor.read_u32(),
        number_of_rva_and_sizes: cursor.read_u32(),
    };

    macro_rules! image_data_dir {
        ($tag: expr) => {
            ImageDataDirectory {
                virtual_address: cursor.read_u32(),
                size: cursor.read_u32(),
                tag: $tag,
            }
        };
    }

    let data_directories = vec![
        image_data_dir!(String::from("export_table")),
        image_data_dir!(String::from("import_table")),
        image_data_dir!(String::from("resource_table")),
        image_data_dir!(String::from("exception_table")),
        image_data_dir!(String::from("certificate_table")),
        image_data_dir!(String::from("base_relocation_table")),
        image_data_dir!(String::from("debug")),
        image_data_dir!(String::from("architecture")),
        image_data_dir!(String::from("global_ptr")),
        image_data_dir!(String::from("tls_table")),
        image_data_dir!(String::from("load_config_table")),
        image_data_dir!(String::from("bound_import")),
        image_data_dir!(String::from("import_address_table")),
        image_data_dir!(String::from("delay_import_descriptor")),
        image_data_dir!(String::from("clr_runtime_header")),
        image_data_dir!(String::from("reserved")),
    ];

    Ok(OptionalHeader {
        std_fields,
        win_specific_fields,
        data_directories,
    })
}

#[derive(Debug, Clone)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
    pub tag: String,
}

/// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-windows-specific-fields-image-only
#[derive(Debug, Clone)]
pub struct WindowsSpecificFields {
    pub image_base: ImageBase,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: WindowsSubsystem,
    pub dll_characteristics: DllCharacteristics,
    pub size_of_stack_reserve: SizeOfStackReserve,
    pub size_of_stack_commit: SizeOfStackCommit,
    pub size_of_heap_reserve: SizeOfHeapReserve,
    pub size_of_heap_commit: SizeOfHeapCommit,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

/// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#windows-subsystem
#[derive(Debug, Clone)]
pub enum WindowsSubsystem {
    UNKNOWN,
    NATIVE,
    WINDOWS_GUI,
    WINDOWS_CUI,
    POSIX_CUI,
    NATIVE_WINDOWS,
    WINDOWS_CE_GUI,
    EFI_APPLICATION,
    EFI_BOOT_SERVICE_DRIVER,
    EFI_RUNTIME_DRIVER,
    EFI_ROM,
    XBOX,
    WINDOWS_BOOT_APPLICATION,
}

impl TryFrom<u16> for WindowsSubsystem {
    type Error = PeError;
    fn try_from(value: u16) -> Result<Self, PeError> {
        let result = match value {
            0 => WindowsSubsystem::UNKNOWN,
            1 => WindowsSubsystem::NATIVE,
            2 => WindowsSubsystem::WINDOWS_GUI,
            3 => WindowsSubsystem::WINDOWS_CUI,
            7 => WindowsSubsystem::POSIX_CUI,
            8 => WindowsSubsystem::NATIVE_WINDOWS,
            9 => WindowsSubsystem::WINDOWS_CE_GUI,
            10 => WindowsSubsystem::EFI_APPLICATION,
            11 => WindowsSubsystem::EFI_BOOT_SERVICE_DRIVER,
            12 => WindowsSubsystem::EFI_RUNTIME_DRIVER,
            13 => WindowsSubsystem::EFI_ROM,
            14 => WindowsSubsystem::XBOX,
            16 => WindowsSubsystem::WINDOWS_BOOT_APPLICATION,
            _ => {
                return Err(PeError::ParseError(format!(
                    "Tried to parse an invalid Windows Subsystem: {value}"
                )))
            }
        };
        Ok(result)
    }
}

#[derive(Debug, Clone)]
pub enum ImageBase {
    PE32(u32),
    PE32_PLUS(u64),
}

#[derive(Debug, Clone)]
pub enum SizeOfStackReserve {
    PE32(u32),
    PE32_PLUS(u64),
}

#[derive(Debug, Clone)]
pub enum SizeOfStackCommit {
    PE32(u32),
    PE32_PLUS(u64),
}

#[derive(Debug, Clone)]
pub enum SizeOfHeapReserve {
    PE32(u32),
    PE32_PLUS(u64),
}

#[derive(Debug, Clone)]
pub enum SizeOfHeapCommit {
    PE32(u32),
    PE32_PLUS(u64),
}

/// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-standard-fields-image-only
#[derive(Debug, Clone)]
pub struct StandardFields {
    pub magic: ExecutableKind,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: Option<u32>,
}

/// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only
#[derive(Debug, Clone)]
pub struct OptionalHeader {
    pub std_fields: StandardFields,
    pub win_specific_fields: WindowsSpecificFields,
    pub data_directories: Vec<ImageDataDirectory>,
}

#[derive(Debug, Clone)]
pub struct PortableExecutable {
    pub executable_kind: ExecutableKind,
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct DllCharacteristics: u16 {
        const RESERVED1 = 0x0001;
        const RESERVED2 = 0x0002;
        const RESERVED3 = 0x0004;
        const RESERVED4 = 0x0008;
        const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020;
        const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040;
        const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080;
        const IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100;
        const IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200;
        const IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400;
        const IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800;
        const IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000;
        const IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000;
        const IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000;
        const IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000;
    }
}

impl FromStr for DllCharacteristics {
    type Err = bitflags::parser::ParseError;

    fn from_str(flags: &str) -> Result<Self, Self::Err> {
        bitflags::parser::from_str(flags)
    }
}

#[derive(Debug, Clone)]
pub enum ExecutableKind {
    PE32,
    PE32_PLUS,
}

impl TryFrom<u16> for ExecutableKind {
    type Error = PeError;
    fn try_from(val: u16) -> Result<Self, PeError> {
        match val {
            0x10b => Ok(Self::PE32),
            0x20b => Ok(Self::PE32_PLUS),
            _ => Err(PeError::ParseError(format!(
                "Tried to parse an invalid ExecutableKind: {:#x?}",
                val
            ))),
        }
    }
}

impl Default for ExecutableKind {
    fn default() -> Self {
        Self::PE32
    }
}
