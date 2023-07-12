#![allow(non_camel_case_types)]

use std::str::FromStr;

use super::cursor::Cursor;

pub fn parse_opt_header(cursor: &mut Cursor) -> OptionalHeader {
    use ExecutableKind::{PE32, PE32_PLUS};
    let magic = ExecutableKind::from(cursor.read_u16());
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
        subsystem: WindowsSubsystem::from(cursor.read_u16()),

        dll_characteristics: format!("0x{:x}", cursor.read_u16())
            .parse::<DllCharacteristics>()
            .unwrap(),
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
        () => {
            ImageDataDirectory {
                virtual_address: cursor.read_u32(),
                size: cursor.read_u32(),
            }
        };
    }

    let data_directories = DataDirectories {
        export_table: image_data_dir!(),
        import_table: image_data_dir!(),
        resource_table: image_data_dir!(),
        exception_table: image_data_dir!(),
        certificate_table: image_data_dir!(),
        base_relocation_table: image_data_dir!(),
        debug: image_data_dir!(),
        architecture: image_data_dir!(),
        global_ptr: image_data_dir!(),
        tls_table: image_data_dir!(),
        load_config_table: image_data_dir!(),
        bound_import: image_data_dir!(),
        import_address_table: image_data_dir!(),
        delay_import_descriptor: image_data_dir!(),
        clr_runtime_header: image_data_dir!(),
        reserved: image_data_dir!(),
    };

    OptionalHeader {
        std_fields,
        win_specific_fields,
        data_directories,
    }
}

/// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only
#[derive(Debug)]
struct DataDirectories {
    export_table: ImageDataDirectory,
    import_table: ImageDataDirectory,
    resource_table: ImageDataDirectory,
    exception_table: ImageDataDirectory,
    certificate_table: ImageDataDirectory,
    base_relocation_table: ImageDataDirectory,
    debug: ImageDataDirectory,
    architecture: ImageDataDirectory,
    global_ptr: ImageDataDirectory,
    tls_table: ImageDataDirectory,
    load_config_table: ImageDataDirectory,
    bound_import: ImageDataDirectory,
    import_address_table: ImageDataDirectory,
    delay_import_descriptor: ImageDataDirectory,
    clr_runtime_header: ImageDataDirectory,
    reserved: ImageDataDirectory,
}

#[derive(Debug)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

/// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-windows-specific-fields-image-only
#[derive(Debug)]
struct WindowsSpecificFields {
    image_base: ImageBase,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: WindowsSubsystem,
    dll_characteristics: DllCharacteristics,
    size_of_stack_reserve: SizeOfStackReserve,
    size_of_stack_commit: SizeOfStackCommit,
    size_of_heap_reserve: SizeOfHeapReserve,
    size_of_heap_commit: SizeOfHeapCommit,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
}

#[derive(Debug)]
enum WindowsSubsystem {
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

impl From<u16> for WindowsSubsystem {
    fn from(value: u16) -> Self {
        match value {
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
            _ => WindowsSubsystem::UNKNOWN,
        }
    }
}

#[derive(Debug)]
enum ImageBase {
    PE32(u32),
    PE32_PLUS(u64),
}

#[derive(Debug)]
enum SizeOfStackReserve {
    PE32(u32),
    PE32_PLUS(u64),
}

#[derive(Debug)]
enum SizeOfStackCommit {
    PE32(u32),
    PE32_PLUS(u64),
}

#[derive(Debug)]
enum SizeOfHeapReserve {
    PE32(u32),
    PE32_PLUS(u64),
}

#[derive(Debug)]
enum SizeOfHeapCommit {
    PE32(u32),
    PE32_PLUS(u64),
}

/// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-standard-fields-image-only
#[derive(Debug)]
struct StandardFields {
    magic: ExecutableKind,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    base_of_data: Option<u32>,
}

/// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only
#[derive(Debug)]
pub struct OptionalHeader {
    std_fields: StandardFields,
    win_specific_fields: WindowsSpecificFields,
    data_directories: DataDirectories,
}

#[derive(Debug)]
struct PortableExecutable {
    executable_kind: ExecutableKind,
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct DllCharacteristics: u16 {
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

#[derive(Debug)]
enum ExecutableKind {
    PE32,
    PE32_PLUS,
}

impl From<u16> for ExecutableKind {
    fn from(val: u16) -> Self {
        match val {
            0x10b => Self::PE32,
            0x20b => Self::PE32_PLUS,
            _ => Self::PE32,
        }
    }
}

impl Default for ExecutableKind {
    fn default() -> Self {
        Self::PE32
    }
}
