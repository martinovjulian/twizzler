//! Management of global context.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use petgraph::stable_graph::StableDiGraph;
use tracing::{debug, trace};

use crate::{
    compartment::{Compartment, CompartmentRef},
    library::{CtorInfo, InitState, Library, LibraryLoader, LibraryRef},
    symbol::{LookupFlags, RelocatedSymbol},
    tls::TlsRegion,
    DynlinkError, ECollector,
};

#[derive(Default)]
pub(crate) struct ContextInner {
    // Simple unique ID generation.
    id_counter: u128,
    id_stack: Vec<u128>,

    // Track all the compartment names.
    compartment_names: HashMap<String, CompartmentRef>,

    // We care about both names and dependency ordering for libraries.
    pub(crate) library_names: HashMap<String, LibraryRef>,
    pub(crate) library_deps: StableDiGraph<LibraryRef, ()>,

    pub(crate) static_ctors: Vec<CtorInfo>,
}

#[allow(dead_code)]
impl ContextInner {
    fn get_fresh_id(&mut self) -> u128 {
        if let Some(old) = self.id_stack.pop() {
            old
        } else {
            self.id_counter += 1;
            self.id_counter
        }
    }

    /// Visit libraries in a post-order DFS traversal, starting from a number of roots. Note that
    /// because multiple roots may be specified, this means that nodes may be visited `O(|roots|)`
    /// times (|roots| is the number of roots yielded by the iterator).
    pub fn with_dfs_postorder<I>(&self, roots: I, mut f: impl FnMut(&LibraryRef))
    where
        I: IntoIterator<Item = LibraryRef>,
    {
        for root in roots.into_iter() {
            let mut visit =
                petgraph::visit::DfsPostOrder::new(&self.library_deps, root.idx.get().unwrap());
            while let Some(node) = visit.next(&self.library_deps) {
                let dep = &self.library_deps[node];
                f(dep)
            }
        }
    }

    /// Insert a library without specifying dependencies.
    pub(crate) fn insert_lib_predeps(&mut self, lib: LibraryRef) {
        self.library_names.insert(lib.name.clone(), lib.clone());
        lib.idx.set(Some(self.library_deps.add_node(lib.clone())));
    }

    /// Add all dependency edges for a library.
    pub(crate) fn set_lib_deps(
        &mut self,
        lib: &LibraryRef,
        deps: impl IntoIterator<Item = LibraryRef>,
    ) {
        for dep in deps.into_iter() {
            self.library_deps
                .add_edge(lib.idx.get().unwrap(), dep.idx.get().unwrap(), ());
        }
    }

    pub(crate) fn lookup_symbol(
        &self,
        start: &LibraryRef,
        name: &str,
        lookup_flags: LookupFlags,
    ) -> Result<RelocatedSymbol, DynlinkError> {
        // First try looking up within ourselves.
        if !lookup_flags.contains(LookupFlags::SKIP_SELF) {
            if let Ok(sym) = start.lookup_symbol(name) {
                return Ok(sym);
            }
        }

        // Next, try all of our transitive dependencies.
        if !lookup_flags.contains(LookupFlags::SKIP_DEPS) {
            if let Some(sym) = self
                .library_deps
                .neighbors_directed(start.idx.get().unwrap(), petgraph::Direction::Outgoing)
                .find_map(|depidx| {
                    let dep = &self.library_deps[depidx];
                    if depidx != start.idx.get().unwrap() {
                        self.lookup_symbol(dep, name, lookup_flags).ok()
                    } else {
                        None
                    }
                })
            {
                return Ok(sym);
            }
        }

        // Fall back to global search.
        if !lookup_flags.contains(LookupFlags::SKIP_GLOBAL) {
            trace!("falling back to global search for {}", name);
            self.lookup_symbol_global(name)
        } else {
            Err(DynlinkError::NotFound {
                name: name.to_string(),
            })
        }
    }

    pub(crate) fn lookup_symbol_global(&self, name: &str) -> Result<RelocatedSymbol, DynlinkError> {
        for idx in self.library_deps.node_indices() {
            let dep = &self.library_deps[idx];
            if let Ok(sym) = dep.lookup_symbol(name) {
                return Ok(sym);
            }
        }
        Err(DynlinkError::NotFound {
            name: name.to_string(),
        })
    }

    fn build_ctors<I>(&mut self, roots: I) -> Result<&[CtorInfo], DynlinkError>
    where
        I: IntoIterator<Item = LibraryRef>,
    {
        let mut ctors = vec![];
        self.with_dfs_postorder(roots, |lib| {
            if lib.try_set_init_state(InitState::Uninit, InitState::StaticUninit) {
                ctors.push(lib.get_ctor_info())
            }
        });
        let mut ctors = ctors.into_iter().ecollect::<Vec<_>>()?;
        self.static_ctors.append(&mut ctors);
        Ok(&self.static_ctors)
    }

    pub(crate) fn build_runtime_info<I>(
        &mut self,
        roots: I,
        tls: TlsRegion,
    ) -> Result<RuntimeInitInfo, DynlinkError>
    where
        I: IntoIterator<Item = LibraryRef>,
    {
        let ctors = {
            let ctors = self.build_ctors(roots)?;
            (ctors.as_ptr(), ctors.len())
        };
        Ok(RuntimeInitInfo::new(ctors.0, ctors.1, tls))
    }
}

#[derive(Default)]
pub struct Context {
    inner: Mutex<ContextInner>,
}

#[allow(dead_code)]
impl Context {
    pub(crate) fn with_inner_mut<R>(
        &self,
        f: impl FnOnce(&mut ContextInner) -> R,
    ) -> Result<R, DynlinkError> {
        Ok(f(&mut *self.inner.lock()?))
    }

    pub(crate) fn with_inner<R>(
        &self,
        f: impl FnOnce(&ContextInner) -> R,
    ) -> Result<R, DynlinkError> {
        Ok(f(&*self.inner.lock()?))
    }

    /// Create a new compartment with a given name.
    pub fn add_compartment(&self, name: impl ToString) -> Result<CompartmentRef, DynlinkError> {
        let name = name.to_string();
        let mut inner = self.inner.lock()?;
        if inner.compartment_names.contains_key(&name) {
            return Err(DynlinkError::AlreadyExists { name });
        }
        let id = inner.get_fresh_id();
        let compartment = Arc::new(Compartment::new(name.clone(), id));
        inner.compartment_names.insert(name, compartment.clone());

        Ok(compartment)
    }

    /// Lookup a given symbol within the context.
    pub fn lookup_symbol(
        &self,
        start: &LibraryRef,
        name: &str,
        lookup_flags: LookupFlags,
    ) -> Result<RelocatedSymbol, DynlinkError> {
        self.inner.lock()?.lookup_symbol(start, name, lookup_flags)
    }

    /// Get initial runtime information for bootstrapping.
    pub fn build_runtime_info<I>(
        &self,
        roots: I,
        tls: TlsRegion,
    ) -> Result<RuntimeInitInfo, DynlinkError>
    where
        I: IntoIterator<Item = LibraryRef>,
    {
        self.inner.lock()?.build_runtime_info(roots, tls)
    }

    /// Add an unloaded library to the context (and load it)
    pub fn add_library(
        &self,
        compartment: &CompartmentRef,
        lib: Library,
        loader: &mut impl LibraryLoader,
    ) -> Result<LibraryRef, DynlinkError> {
        let mut inner = self.inner.lock()?;

        compartment.load_library(lib, &mut inner, loader)
    }

    /// Iterate through all libraries and process relocations for any libraries that haven't yet been relocated.
    pub fn relocate_all(
        &self,
        roots: impl IntoIterator<Item = LibraryRef>,
    ) -> Result<Vec<LibraryRef>, DynlinkError> {
        let inner = self.inner.lock()?;

        roots
            .into_iter()
            .map(|root| {
                debug!("relocate_all: relocation root: {}", root);
                root.relocate(&inner).map(|_| root)
            })
            .ecollect()
    }
}

#[repr(C)]
pub struct RuntimeInitInfo {
    ctor_info_array: *const CtorInfo,
    ctor_info_array_len: usize,

    pub tls_region: TlsRegion,
}
impl RuntimeInitInfo {
    pub(crate) fn new(
        ctor_info_array: *const CtorInfo,
        ctor_info_array_len: usize,
        tls_region: TlsRegion,
    ) -> Self {
        Self {
            ctor_info_array,
            ctor_info_array_len,
            tls_region,
        }
    }

    pub fn ctor_infos(&self) -> &[CtorInfo] {
        unsafe { core::slice::from_raw_parts(self.ctor_info_array, self.ctor_info_array_len) }
    }
}
