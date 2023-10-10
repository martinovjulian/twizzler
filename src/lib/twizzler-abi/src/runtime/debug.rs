//! Null implementation of the debug runtime.

use twizzler_runtime_api::{DebugRuntime, Library, LibraryId, MapFlags};

use crate::object::{InternalObject, ObjID, Protections, NULLPAGE_SIZE};

use super::{
    MinimalRuntime, __twz_get_runtime,
    load_elf::{ElfObject, PhdrType},
};

static mut EXEC_ID: ObjID = ObjID::new(0);

pub fn set_execid(id: ObjID) {
    unsafe { EXEC_ID = id }
}

fn get_execid() -> ObjID {
    unsafe { EXEC_ID }
}

impl DebugRuntime for MinimalRuntime {
    fn get_library(
        &self,
        _id: twizzler_runtime_api::LibraryId,
    ) -> Option<twizzler_runtime_api::Library> {
        let mapping = __twz_get_runtime()
            .map_object(get_execid().as_u128(), MapFlags::READ)
            .ok()?;
        Some(Library {
            range: (unsafe { mapping.start.add(NULLPAGE_SIZE) }, mapping.meta),
            mapping,
        })
    }

    fn get_exeid(&self) -> Option<twizzler_runtime_api::LibraryId> {
        Some(LibraryId(0))
    }

    fn get_library_segment(
        &self,
        lib: &twizzler_runtime_api::Library,
        seg: usize,
    ) -> Option<twizzler_runtime_api::AddrRange> {
        let exe = InternalObject::map(lib.mapping.id.into(), Protections::READ)?;
        let elf = ElfObject::from_obj(&exe)?;

        elf.phdrs()
            .filter(|p| p.phdr_type() == PhdrType::Load)
            .map(|p| twizzler_runtime_api::AddrRange {
                start: p.vaddr as usize,
                len: p.memsz as usize,
            })
            .nth(seg)
    }

    fn get_full_mapping(
        &self,
        lib: &twizzler_runtime_api::Library,
    ) -> Option<twizzler_runtime_api::ObjectHandle> {
        Some(lib.mapping.clone())
    }
}
