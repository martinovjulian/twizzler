use twizzler_rt_abi::object::ObjID;

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub struct RequestFromKernel {
    cmd: KernelCommand,
}

impl RequestFromKernel {
    pub fn new(cmd: KernelCommand) -> Self {
        Self { cmd }
    }

    pub fn cmd(&self) -> KernelCommand {
        self.cmd
    }
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub enum KernelCommand {
    EchoReq,
    PageDataReq(ObjID, ObjectRange),
    ObjectInfoReq(ObjID),
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub struct CompletionToKernel {
    data: KernelCompletionData,
}

impl CompletionToKernel {
    pub fn new(data: KernelCompletionData) -> Self {
        Self { data }
    }

    pub fn data(&self) -> KernelCompletionData {
        self.data
    }
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub enum KernelCompletionData {
    EchoResp,
    PageDataCompletion(PhysRange),
    ObjectInfoCompletion(ObjectInfo),
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub struct RequestFromPager {
    cmd: PagerRequest,
}

impl RequestFromPager {
    pub fn new(cmd: PagerRequest) -> Self {
        Self { cmd }
    }

    pub fn cmd(&self) -> PagerRequest {
        self.cmd
    }
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub enum PagerRequest {
    EchoReq,
    TestReq,
    Ready,
    CopyUserPhys {
        target_object: ObjID,
        offset: usize,
        len: usize,
        phys: PhysRange,
        write_phys: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub struct CompletionToPager {
    data: PagerCompletionData,
}

impl CompletionToPager {
    pub fn new(data: PagerCompletionData) -> Self {
        Self { data }
    }

    pub fn data(&self) -> PagerCompletionData {
        self.data
    }
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub enum PagerCompletionData {
    Okay,
    Error,
    EchoResp,
    TestResp,
    DramPages(PhysRange),
}

pub struct PageDataReq {
    objID: ObjID,
    object_range: ObjectRange,
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub struct ObjectInfo {
    pub obj_id: ObjID,
}

impl ObjectInfo {
    pub fn new(obj_id: ObjID) -> Self {
        Self { obj_id }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub struct PhysRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub struct ObjectRange {
    pub start: u64,
    pub end: u64,
}

impl PhysRange {
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    pub fn len(&self) -> usize {
        (self.end - self.start) as usize
    }
}

impl ObjectRange {
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }
}
