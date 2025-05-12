use std::fs::File;
use std::fs;
use std::io::{self, Write};
use twizzler_rt_abi::object::ObjectHandle;
use twizzler_abi::syscall::ObjectCreateFlags;
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

    let uobj = ObjectBuilder::default()
        .build(SecCtxMap::default())
        .unwrap();

    let sec_ctx = SecCtx::default();

    let target = 0x123.into();
    let accessor = 0x321.into();
    let prots = Protections::all();
    let target_priv_key =
        SigningKey::from_slice(&rand_32(), SigningScheme::Ed25519).expect("should work");

    let cap = Cap::new(
        target,
        accessor,
        prots,
        target_priv_key,
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
    )
    .unwrap();

    sec_ctx.add_cap(cap);


    let write_offset = SecCtxMap::insert(&uobj, cap.target, CtxMapItemType::Cap);

    let tx = uobj.clone().tx().unwrap();

    let ptr = tx.lea_mut(write_offset as usize, size_of::<Cap>()).unwrap();

    unsafe {
        let mut in_ctx_cap = *ptr.cast::<Cap>();
        in_ctx_cap = cap;
    }

    tx.commit().unwrap();

    println!("Capability stored. Object handle: {:?}", uobj.handle());
    println!("Write Offset = {:?}", write_offset);

    let static_id: ObjID = 0xDEADBEEF.into();

    let obj_create = ObjectCreate {
        kuid: static_id,
        bt: BackingType::Normal,
        lt: LifetimeType::Volatile, 
        flags: ObjectCreateFlags::empty(),
    };

    let static_obj = ObjectBuilder::new(obj_create)
        .build(SecCtxMap::default())
        .unwrap();
    
    let tx_static = static_obj.clone().tx().unwrap();
    let static_ptr = tx_static.lea_mut(0, std::mem::size_of::<(&ObjectHandle, usize)>()).unwrap();


    unsafe {
        *static_ptr.cast::<(&ObjectHandle, usize)>() = (uobj.handle(), write_offset.try_into().unwrap());
    }

    tx_static.commit().unwrap();

    println!("Static Object Id: {:?}", static_obj.id());

}


pub fn rand_32() -> [u8; 32] {
    let mut dest = [0 as u8; 32];
    getrandom::getrandom(&mut dest).unwrap();
    dest
}


