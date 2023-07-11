use std::{ffi::c_void, time::Duration};

use clap::{Parser, Subcommand};
use memoryrs::{external::*, process::*};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use windows::Win32::Foundation::CloseHandle;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Option<CliCommands>,
}

#[derive(Subcommand)]
enum CliCommands {
    ///  Assault Cube
    Ac,
}

fn test_ac_x86(p: Process) {
    let addr_local_player = 0x10f4f4;
    let current_weapon_ammo_offsets = vec![0x374, 0x14, 0x0];
    let recoil_fn_addr = 0x63786;

    let h_proc = p.open().unwrap();

    let module_base_addr = p.module_base_addr("ac_client.exe").unwrap().unwrap();
    tracing::info!("module_base_addr: {:?}", module_base_addr);

    let addr_local_player_ptr = module_base_addr as u32 + addr_local_player;
    tracing::info!("local player pointer address: {:x?}", addr_local_player_ptr);

    let ammo_addr = get_multilevel_ptr_u32(
        h_proc,
        addr_local_player_ptr as *mut c_void,
        current_weapon_ammo_offsets,
    )
    .unwrap();
    tracing::info!("ammo_addr: {:?}", ammo_addr);

    let ammo_amount = read_mem_u32(h_proc, ammo_addr as usize).unwrap();
    tracing::info!("ammo_amount: {:?}", ammo_amount);

    let new_ammo = 6969;
    tracing::info!("writing {} to the current weapon ammo address", new_ammo);
    write_mem(h_proc, ammo_addr, new_ammo).unwrap();

    tracing::info!(
        "new ammo amount: {:?}",
        read_mem_u32(h_proc, ammo_addr as usize).unwrap()
    );

    nop_32(module_base_addr as u32 + recoil_fn_addr, 10, h_proc);
    tracing::info!("nopped recoil, waiting 5 seconds to restore");

    std::thread::sleep(Duration::from_secs(5));

    let mut original_bytes: [u8; 10] = [0x50, 0x8d, 0x4c, 0x24, 0x1c, 0x51, 0x8b, 0xce, 0xff, 0xd2];
    patch_u32(
        module_base_addr as u32 + recoil_fn_addr,
        original_bytes.as_mut_ptr(),
        10,
        h_proc,
    );
    unsafe {
        CloseHandle(h_proc);
    }
}

fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let cli = Cli::parse();

    if let Some(cmd) = cli.command {
        match cmd {
            CliCommands::Ac => {
                let p = Process::from_executable_name("ac_client.exe")
                    .expect("Error on get_process_by_exec")
                    .expect("Couldn't find ac_client.exe process");
                test_ac_x86(p);
            }
        }
    }
}
