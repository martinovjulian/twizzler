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

    // let mut objIdValue = "22a2764562a36d66b02053b42765cd"; //this needs to be grabbed dynamically from filestacktest
    // let newObjIdValue = u128::from_str_radix(objIdValue, 16).unwrap();
    
    // let actualObjId = ObjID::from(newObjIdValue);
    let actualObjId: ObjID = 0xDEADBEEF.into();

    let uobj = Object::<SecCtxMap>::map(actualObjId, MapFlags::READ | MapFlags::WRITE).unwrap();

    let read_tx = uobj.tx().unwrap();

    let write_offset = 0x224; //this needs to be grabbed dynamically from filestacktest

    let read_ptr = read_tx.lea(write_offset as usize, size_of::<Cap>()).unwrap();

    let persisted_cap: Cap = unsafe { *read_ptr.cast::<Cap>() };

    println!("Persisted Capability: {:?}", persisted_cap);
}
