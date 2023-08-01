use crate::util::{get_msb_u32, get_msb_u64, read_u8_until_null, u32_from_bytes};

use super::{
    cursor::Cursor,
    optional_header::{ExecutableKind, ImageDataDirectory},
    section_table::SectionTable,
    PeError,
};

const ORDINAL_FLAG_X64: u64 = 0x8000000000000000;
const ORDINAL_FLAG_X86: u32 = 0x80000000;

fn rva2foa(rva: u32, section_table: &SectionTable) -> u32 {
    for section in &section_table.section_headers {
        if rva >= section.virtual_address
            && rva <= section.virtual_address + section.size_of_raw_data
        {
            return section.ptr_to_raw_data + (rva - section.virtual_address);
        }
    }
    0
}

/// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-directory-table
pub fn get_import_table(
    section_table: &SectionTable,
    bytes: &Vec<u8>,
    exec_kind: &ExecutableKind,
    import_table_dir: ImageDataDirectory,
) -> Result<ImportTable, PeError> {
    let ul_import_foa = rva2foa(import_table_dir.virtual_address, section_table);

    let mut cursor = Cursor::new(
        bytes[ul_import_foa as usize..ul_import_foa as usize + import_table_dir.size as usize]
            .to_vec(),
    );
    let mut image_descriptors = vec![];
    loop {
        let mut entry = ImageImportDescriptor {
            import_lookup_table_rva: cursor.read_u32(),
            timedate_stamp: cursor.read_u32(),
            forwarder_chain: cursor.read_u32(),
            name_rva: cursor.read_u32(),
            first_thunk: cursor.read_u32(),

            name: "".to_string(),
            characteristics: 0,
            import_lookup_table: ImportLookupTable { entries: vec![] },
        };
        if entry.import_lookup_table_rva == 0
            && entry.name_rva == 0
            && entry.timedate_stamp == 0
            && entry.forwarder_chain == 0
            && entry.first_thunk == 0
        {
            break;
        }

        let get_name = || {
            let name_offset = rva2foa(entry.name_rva, section_table);
            read_u8_until_null(name_offset as usize, &bytes)
        };

        let get_characteristics = || {
            let characteristics_offset = rva2foa(entry.import_lookup_table_rva, section_table);
            return characteristics_offset;
        };

        // FIXME: fix padding parsing
        // Hint/Name Table
        let get_lookup_table = || {
            let starting_address: u32 = rva2foa(entry.first_thunk, section_table);
            let mut cursor = Cursor::new(bytes[starting_address as usize..].to_vec());
            let mut entries = vec![];
            let mut entries_idx = 0;
            match exec_kind {
                ExecutableKind::PE32 => {
                    loop {
                        let data = cursor.read_u32();
                        if data == 0 {
                            break;
                        }
                        let msb = get_msb_u32(data);
                        let is_ordinal = (msb & ORDINAL_FLAG_X86) != 0;
                        if is_ordinal {
                            unimplemented!();
                        }
                        let import_by_name_offset = data & 0x7FFFFFFF; // Mask out the MSB'

                        let import_by_name_address = rva2foa(import_by_name_offset, section_table);
                        let hint = u16::from_le_bytes([
                            bytes[import_by_name_address as usize],
                            bytes[import_by_name_address as usize + 1],
                        ]);

                        let func_name_bytes =
                            read_u8_until_null(import_by_name_address as usize + 2, bytes).to_vec();

                        //let fn_list_addr = rva2foa(entry.first_thunk, section_table) as usize;

                        entries.push(ImportLookupTableEntry {
                            is_ordinal,
                            hint,
                            name: func_name_bytes,
                            func_ptr_address: FuncAddress::X86(
                                entry.first_thunk as u32
                                    + (std::mem::size_of::<u32>() * entries_idx) as u32,
                            ),
                        });
                        entries_idx += 1;
                    }
                }
                ExecutableKind::PE32_PLUS => {
                    loop {
                        let data = cursor.read_u64();
                        if data == 0 {
                            break;
                        }
                        let msb = get_msb_u64(data);
                        let is_ordinal = (msb & ORDINAL_FLAG_X64) != 0;
                        if is_ordinal {
                            unimplemented!();
                        }
                        let import_by_name_offset = data & 0x7FFFFFFF; // Mask out the MSB'

                        let import_by_name_address =
                            rva2foa(import_by_name_offset as u32, section_table);
                        let hint = u16::from_le_bytes([
                            bytes[import_by_name_address as usize],
                            bytes[import_by_name_address as usize + 1],
                        ]);

                        let func_name_bytes =
                            read_u8_until_null(import_by_name_address as usize + 2, bytes).to_vec();

                        //let fn_list_addr = rva2foa(entry.first_thunk, section_table) as usize;

                        entries.push(ImportLookupTableEntry {
                            hint,
                            is_ordinal,
                            name: func_name_bytes,
                            func_ptr_address: FuncAddress::X64(
                                entry.first_thunk as u64
                                    + (std::mem::size_of::<u64>() * entries_idx) as u64,
                            ),
                        });
                        entries_idx += 1;
                    }
                }
            }
            return entries;
        };

        entry.import_lookup_table.entries = get_lookup_table();
        entry.name = String::from_utf8(get_name().to_vec()).unwrap();

        // FIXME: parse characteristics
        entry.characteristics = get_characteristics();
        image_descriptors.push(entry);
    }
    Ok(ImportTable { image_descriptors })
}

#[derive(Debug, Clone)]
pub struct ImportTable {
    pub image_descriptors: Vec<ImageImportDescriptor>,
}

/// A Dll
#[derive(Debug, Clone)]
pub struct ImageImportDescriptor {
    /// Import Lookup Table RVA
    pub import_lookup_table_rva: u32,
    pub timedate_stamp: u32,
    pub forwarder_chain: u32,
    /// DLL Name RVA
    pub name_rva: u32,
    /// Import Address Table RVA
    pub first_thunk: u32,

    ///  not in MS docs
    pub name: String,
    pub characteristics: u32, // FIXME: Need to parse to flags?,
    /// Import Lookup Table (aka Import Name Table in IDA Pro)
    pub import_lookup_table: ImportLookupTable,
}

#[derive(Debug, Clone)]
pub struct ImportLookupTable {
    pub entries: Vec<ImportLookupTableEntry>,
}

//  TODO: refactor this, do we really need all these fields?
#[derive(Debug, Clone)]
pub struct ImportLookupTableEntry {
    pub hint: u16,
    pub is_ordinal: bool,
    pub name: Vec<u8>,
    /// module base address + func ptr address = ptr to the function!
    pub func_ptr_address: FuncAddress,
}

impl ImportLookupTableEntry {
    pub fn name(&self) -> String {
        String::from_utf8(self.name.clone()).unwrap_or("[NAMELESS]".to_string())
    }
}

#[derive(Debug, Clone)]
pub enum FuncAddress {
    X64(u64),
    X86(u32),
}

impl std::fmt::Display for FuncAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FuncAddress::X64(addr) => write!(f, "{:#x}", addr),
            FuncAddress::X86(addr) => write!(f, "{:#x}", addr),
        }
    }
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
            writeln!(f, "first_thunk: {:#x}", descriptor.first_thunk)?;
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
                writeln!(f, "\tfunc_ptr_address: {:#x?}", entry.func_ptr_address)?;
                writeln!(f, "-------------------")?;
            }
        }
        Ok(())
    }
}
