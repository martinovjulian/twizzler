use std::fs::File;
use std::fs;
use std::io::{self, Write};
use std::str::FromStr;

use clap::{Parser, Subcommand, ValueEnum};
use twizzler::{
    marker::{BaseType, StoreCopy},
    object::{Object, ObjectBuilder, RawObject, TypedObject},
    tx::TxObject,
};
use twizzler_abi::{
    object::{ObjID, Protections},
    syscall::{BackingType, LifetimeType, ObjectCreate},
};
use twizzler_rt_abi::object::MapFlags;
use twizzler_security::{
    sec_ctx::{
        map::{CtxMapItemType, SecCtxMap},
        SecCtx,
    },
    Cap, SigningKey, SigningScheme,
};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
#[command(args_conflicts_with_subcommands = true)]
pub enum Commands {
    Read {
        #[arg(short, long, value_parser)]
        id: String,
    },
    /// Search various aspects within the service.
    Write {
        #[arg(short, long, value_parser)]
        id: String,
    },
}



fn main() {
    use twizzler::object::{Object, ObjectBuilder};

    let static_obj: Object<SecCtxMap> =
    Object::<SecCtxMap>::map(0xDEADBEEF.into(), MapFlags::READ).unwrap();

    let tx_static = static_obj.tx().unwrap();


    let metadata_ptr = tx_static.lea(0, size_of::<(&ObjectHandle, usize)>()).unwrap();


    let (dynamic_obj_handle, dynamic_write_offset): (&ObjectHandle, usize) =
        unsafe { *metadata_ptr.cast::<(&ObjectHandle, usize)>() };

    println!("Retrieved metadata - Dynamic Object Handle: {:?}, Write Offset: {}", dynamic_obj_handle, dynamic_write_offset);


    let read_ptr = read_tx.lea(dynamic_write_offset, size_of::<Cap>()).unwrap();
    let persisted_cap: Cap = unsafe { *read_ptr.cast::<Cap>() };


    println!("Persisted Capability: {:?}", persisted_cap);
}
