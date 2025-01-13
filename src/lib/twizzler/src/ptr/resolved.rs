use std::{
    marker::PhantomData,
    mem::ManuallyDrop,
    ops::{Deref, DerefMut, Index, IndexMut},
};

use twizzler_rt_abi::object::ObjectHandle;

use super::GlobalPtr;
use crate::object::RawObject;

pub struct Ref<'obj, T> {
    ptr: *const T,
    handle: *const ObjectHandle,
    owned: bool,
    _pd: PhantomData<&'obj T>,
}

impl<'obj, T> Ref<'obj, T> {
    pub fn raw(&self) -> *const T {
        self.ptr
    }

    pub fn offset(&self) -> u64 {
        self.handle().ptr_local(self.ptr.cast()).unwrap() as u64
    }

    pub fn handle(&self) -> &ObjectHandle {
        unsafe { self.handle.as_ref().unwrap_unchecked() }
    }

    pub unsafe fn from_raw_parts(ptr: *const T, handle: *const ObjectHandle) -> Self {
        Self {
            ptr,
            handle,
            owned: false,
            _pd: PhantomData,
        }
    }

    pub unsafe fn cast<U>(self) -> Ref<'obj, U> {
        let this = ManuallyDrop::new(self);
        Ref {
            ptr: this.ptr.cast(),
            handle: this.handle,
            owned: this.owned,
            _pd: PhantomData,
        }
    }

    pub unsafe fn mutable(self) -> RefMut<'obj, T> {
        RefMut::from_raw_parts(self.ptr as *mut T, self.handle)
    }

    pub fn global(&self) -> GlobalPtr<T> {
        GlobalPtr::new(self.handle().id(), self.offset())
    }

    pub fn owned<'b>(&self) -> Ref<'b, T> {
        Ref {
            ptr: self.ptr,
            owned: true,
            handle: Box::into_raw(Box::new(self.handle().clone())),
            _pd: PhantomData,
        }
    }

    pub fn from_handle(handle: ObjectHandle, ptr: *const T) -> Self {
        Self {
            ptr,
            owned: true,
            handle: Box::into_raw(Box::new(handle)),
            _pd: PhantomData,
        }
    }
}

impl<'obj, T> Deref for Ref<'obj, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { self.ptr.as_ref().unwrap_unchecked() }
    }
}

impl<'a, T> From<Ref<'a, T>> for GlobalPtr<T> {
    fn from(value: Ref<'a, T>) -> Self {
        GlobalPtr::new(value.handle().id(), value.offset())
    }
}

impl<'a, T> Drop for Ref<'a, T> {
    fn drop(&mut self) {
        if self.owned {
            let _boxed = unsafe { Box::from_raw(self.handle as *mut ObjectHandle) };
        }
    }
}

pub struct RefMut<'obj, T> {
    ptr: *mut T,
    handle: *const ObjectHandle,
    _pd: PhantomData<&'obj mut T>,
}

impl<'obj, T> RefMut<'obj, T> {
    pub fn raw(&self) -> *mut T {
        self.ptr
    }

    pub unsafe fn from_raw_parts(ptr: *mut T, handle: *const ObjectHandle) -> Self {
        Self {
            ptr,
            handle,
            _pd: PhantomData,
        }
    }

    pub unsafe fn cast<U>(self) -> RefMut<'obj, U> {
        RefMut {
            ptr: self.ptr.cast(),
            handle: self.handle,
            _pd: PhantomData,
        }
    }

    pub fn handle(&self) -> &ObjectHandle {
        unsafe { self.handle.as_ref().unwrap_unchecked() }
    }

    pub fn offset(&self) -> u64 {
        self.handle().ptr_local(self.ptr.cast()).unwrap() as u64
    }

    pub fn global(&self) -> GlobalPtr<T> {
        GlobalPtr::new(self.handle().id(), self.offset())
    }
}

impl<'obj, T> Deref for RefMut<'obj, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { self.ptr.as_ref().unwrap_unchecked() }
    }
}

impl<'obj, T> DerefMut for RefMut<'obj, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.ptr.as_mut().unwrap_unchecked() }
    }
}

impl<'a, T> From<RefMut<'a, T>> for GlobalPtr<T> {
    fn from(value: RefMut<'a, T>) -> Self {
        GlobalPtr::new(value.handle().id(), value.offset())
    }
}

pub struct RefSlice<'a, T> {
    ptr: Ref<'a, T>,
    len: usize,
}

impl<'a, T> RefSlice<'a, T> {
    pub unsafe fn from_ref(ptr: Ref<'a, T>, len: usize) -> Self {
        Self { ptr, len }
    }

    pub fn as_slice(&self) -> &[T] {
        let raw_ptr = self.ptr.raw();
        unsafe { core::slice::from_raw_parts(raw_ptr, self.len) }
    }

    pub fn get(&self, idx: usize) -> Option<Ref<'a, T>> {
        let ptr = self.as_slice().get(idx)?;
        Some(unsafe { Ref::from_raw_parts(ptr, self.ptr.handle) })
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

impl<'a, T> Index<usize> for RefSlice<'a, T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        let slice = self.as_slice();
        &slice[index]
    }
}

pub struct RefSliceMut<'a, T> {
    ptr: RefMut<'a, T>,
    len: usize,
}

impl<'a, T> RefSliceMut<'a, T> {
    pub unsafe fn from_ref(ptr: RefMut<'a, T>, len: usize) -> Self {
        Self { ptr, len }
    }

    pub fn as_slice(&self) -> &[T] {
        let raw_ptr = self.ptr.raw();
        unsafe { core::slice::from_raw_parts(raw_ptr, self.len) }
    }

    pub fn as_slice_mut(&mut self) -> &mut [T] {
        let raw_ptr = self.ptr.raw();
        unsafe { core::slice::from_raw_parts_mut(raw_ptr, self.len) }
    }

    pub fn get(&self, idx: usize) -> Option<Ref<'a, T>> {
        let ptr = self.as_slice().get(idx)?;
        Some(unsafe { Ref::from_raw_parts(ptr, self.ptr.handle) })
    }

    pub fn get_mut(&mut self, idx: usize) -> Option<RefMut<'_, T>> {
        let ptr = self.as_slice_mut().get_mut(idx)?;
        Some(unsafe { RefMut::from_raw_parts(ptr, self.ptr.handle) })
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

impl<'a, T> Index<usize> for RefSliceMut<'a, T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        let slice = self.as_slice();
        &slice[index]
    }
}

impl<'a, T> IndexMut<usize> for RefSliceMut<'a, T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        let slice = self.as_slice_mut();
        &mut slice[index]
    }
}
