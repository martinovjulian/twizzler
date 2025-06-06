use alloc::vec::Vec;

use inflight::InflightManager;
use request::ReqKind;
use twizzler_abi::object::{ObjID, NULLPAGE_SIZE};

use crate::{
    memory::{MemoryRegion, MemoryRegionKind},
    mutex::Mutex,
    obj::{LookupFlags, ObjectRef, PageNumber},
    once::Once,
    syscall::sync::finish_blocking,
    thread::current_thread_ref,
};

mod inflight;
mod queues;
mod request;

pub use queues::init_pager_queue;
pub use request::Request;

static PAGER_MEMORY: Once<Vec<MemoryRegion>> = Once::new();

const MAX_RESERVE_KERNEL: usize = 1024 * 1024 * 1024; // 1G

pub fn pager_select_memory_regions(regions: &[MemoryRegion]) -> Vec<MemoryRegion> {
    let mut fa_regions = Vec::new();
    let mut pager_regions = Vec::new();
    let total = regions.iter().fold(0, |acc, val| {
        if val.kind == MemoryRegionKind::UsableRam {
            acc + val.length
        } else {
            acc
        }
    });
    let mut reserved = 0;
    for reg in regions {
        if matches!(reg.kind, MemoryRegionKind::UsableRam) {
            // TODO: don't just pick one, and don't just pick the first one.
            if reserved >= MAX_RESERVE_KERNEL {
                pager_regions.push(*reg);
            } else if reg.length > NULLPAGE_SIZE * 2 {
                let (first, second) = (*reg).split(reg.length / 2).unwrap();
                reserved += first.length;
                fa_regions.push(first);
                pager_regions.push(second);
            } else {
                reserved += reg.length;
                fa_regions.push(*reg);
            }
        }
    }
    let total_pager = pager_regions.iter().fold(0, |acc, val| {
        if val.kind == MemoryRegionKind::UsableRam {
            acc + val.length
        } else {
            acc
        }
    });
    let total_kernel = fa_regions.iter().fold(0, |acc, val| {
        if val.kind == MemoryRegionKind::UsableRam {
            acc + val.length
        } else {
            acc
        }
    });
    logln!(
        "[kernel::pager] split memory: {} MB pager / {} MB kernel",
        total_pager / (1024 * 1024),
        total_kernel / (1024 * 1024)
    );
    assert_eq!(total, total_pager + total_kernel);
    PAGER_MEMORY.call_once(|| pager_regions);
    fa_regions
}

lazy_static::lazy_static! {
    static ref INFLIGHT_MGR: Mutex<InflightManager> = Mutex::new(InflightManager::new());
}

pub fn lookup_object_and_wait(id: ObjID) -> Option<ObjectRef> {
    loop {
        match crate::obj::lookup_object(id, LookupFlags::empty()) {
            crate::obj::LookupResult::Found(arc) => return Some(arc),
            crate::obj::LookupResult::WasDeleted => return None,
            _ => {}
        }

        let mut mgr = INFLIGHT_MGR.lock();
        if !mgr.is_ready() {
            return None;
        }
        let inflight = mgr.add_request(ReqKind::new_info(id));
        drop(mgr);
        if let Some(pager_req) = inflight.pager_req() {
            queues::submit_pager_request(pager_req);
        }

        let mut mgr = INFLIGHT_MGR.lock();
        let thread = current_thread_ref().unwrap();
        if let Some(guard) = mgr.setup_wait(&inflight, &thread) {
            drop(mgr);
            finish_blocking(guard);
        };
    }
}

pub fn get_page_and_wait(id: ObjID, page: PageNumber) {
    let mut mgr = INFLIGHT_MGR.lock();
    if !mgr.is_ready() {
        return;
    }
    let inflight = mgr.add_request(ReqKind::new_page_data(id, page.num(), 1));
    drop(mgr);
    if let Some(pager_req) = inflight.pager_req() {
        queues::submit_pager_request(pager_req);
    }

    let mut mgr = INFLIGHT_MGR.lock();
    let thread = current_thread_ref().unwrap();
    if let Some(guard) = mgr.setup_wait(&inflight, &thread) {
        drop(mgr);
        finish_blocking(guard);
    };
}

fn cmd_object(req: ReqKind) {
    let mut mgr = INFLIGHT_MGR.lock();
    if !mgr.is_ready() {
        return;
    }
    let inflight = mgr.add_request(req);
    drop(mgr);
    if let Some(pager_req) = inflight.pager_req() {
        queues::submit_pager_request(pager_req);
    }

    let mut mgr = INFLIGHT_MGR.lock();
    let thread = current_thread_ref().unwrap();
    if let Some(guard) = mgr.setup_wait(&inflight, &thread) {
        drop(mgr);
        finish_blocking(guard);
    };
}

pub fn sync_object(id: ObjID) {
    cmd_object(ReqKind::new_sync(id));
}

pub fn del_object(id: ObjID) {
    cmd_object(ReqKind::new_del(id));
}

pub fn create_object(id: ObjID) {
    cmd_object(ReqKind::new_create(id));
}

pub fn ensure_in_core(obj: &ObjectRef, start: PageNumber, len: usize) {
    if !obj.use_pager() {
        return;
    }
    for i in 0..len {
        let page = start.offset(i);
        get_page_and_wait(obj.id(), page);
    }
}

pub fn get_object_page(obj: &ObjectRef, pn: PageNumber) {
    ensure_in_core(obj, pn, 1);
}
