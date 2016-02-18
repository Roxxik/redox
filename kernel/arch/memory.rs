// TODO: Doc the rest

use core::{cmp, intrinsics, mem};
use core::ops::{Index, IndexMut};
use core::ptr::{ self, Unique };

use super::paging::{ PAGE_END_PHYS, PAGE_END, PAGE_SIZE, KERNEL_BASE };

// physical memorymap at kernel startup:
//0x000000 - 0x0004FF free
//0x000500 - 0x004FFF memory map
//0x005000 - 0x007BFF free
//0x007C00 - ???????? bootloader/interrupt table/GDT
//???????? - 0x06FFFF free
//0x070000 - 0x072FFF boot page tables, mapping the 1st GiB to the 4th
//0x073000 - 0x07FFFF free
//0x080000 - 0x0FFFFF reserved, EBDA and video memory
//0x100000 - ???????? the kernel
//???????? - 0xEFFFFF free
//0xF00000 - ???????? not sure what is here, read memory map

/// A wrapper around raw pointers
pub struct Memory<T> {
    pub ptr: *mut T,
}

impl<T> Memory<T> {
    /// Create an empty
    pub fn new(count: usize) -> Option<Self> {
        let alloc = unsafe { alloc(count * mem::size_of::<T>()) };
        if alloc > 0 {
            Some(Memory { ptr: alloc as *mut T })
        } else {
            None
        }
    }

    pub fn new_align(count: usize, align: usize) -> Option<Self> {
        let alloc = unsafe { alloc_aligned(count * mem::size_of::<T>(), align) };
        if alloc > 0 {
            Some(Memory { ptr: alloc as *mut T })
        } else {
            None
        }
    }

    /// Renew the memory
    pub fn renew(&mut self, count: usize) -> bool {
        let address = unsafe { realloc(self.ptr as usize, count * mem::size_of::<T>()) };
        if address > 0 {
            self.ptr = address as *mut T;
            true
        } else {
            false
        }
    }

    /// Get the size in bytes
    pub fn size(&self) -> usize {
        unsafe { alloc_size(self.ptr as usize) }
    }

    /// Get the length in T elements
    pub fn length(&self) -> usize {
        unsafe { alloc_size(self.ptr as usize) / mem::size_of::<T>() }
    }

    /// Get the address
    pub unsafe fn address(&self) -> usize {
        self.ptr as usize
    }

    /// Read the memory
    pub unsafe fn read(&self, i: usize) -> T {
        ptr::read(self.ptr.offset(i as isize))
    }

    /// Load the memory
    pub unsafe fn load(&self, i: usize) -> T {
        intrinsics::atomic_singlethreadfence();
        ptr::read(self.ptr.offset(i as isize))
    }

    /// Overwrite the memory
    pub unsafe fn write(&mut self, i: usize, value: T) {
        ptr::write(self.ptr.offset(i as isize), value);
    }

    /// Store the memory
    pub unsafe fn store(&mut self, i: usize, value: T) {
        intrinsics::atomic_singlethreadfence();
        ptr::write(self.ptr.offset(i as isize), value)
    }

    /// Convert into a raw pointer
    pub unsafe fn into_raw(mut self) -> *mut T {
        let ptr = self.ptr;
        self.ptr = 0 as *mut T;
        ptr
    }
}

impl<T> Drop for Memory<T> {
    fn drop(&mut self) {
        if self.ptr as usize > 0 {
            unsafe { unalloc(self.ptr as usize) };
        }
    }
}

impl<T> Index<usize> for Memory<T> {
    type Output = T;

    fn index<'a>(&'a self, _index: usize) -> &'a T {
        unsafe { &*self.ptr.offset(_index as isize) }
    }
}

impl<T> IndexMut<usize> for Memory<T> {
    fn index_mut<'a>(&'a mut self, _index: usize) -> &'a mut T {
        unsafe { &mut *self.ptr.offset(_index as isize) }
    }
}

/// A memory map entry
#[repr(packed)]
#[derive(Copy, Clone)]
struct Cluster {
    address: usize,
}

impl Cluster {
    const SIZE: usize = 4;


    pub fn empty() -> Cluster {
        Cluster { address: 0 }
    }

    pub fn unusable() -> Cluster {
        Cluster { address: 0xFFFFFFFF }
    }
}

// a simple block allocation map and page frame allocator
#[repr(packed)]
struct Clusters {
    clusters: [Cluster; 1024 * 1024/*TODO  should be `Clusters::LENGTH` but rustc complains*/],
}

impl Clusters {
    pub const ADDRESS: usize = ((PAGE_END - 1) | 0x1FFFFF) + 1;
    pub const LENGTH: usize = 1024 * 1024;
    pub const SIZE: usize = Clusters::SIZE * Cluster::SIZE;
    pub const END: usize = Clusters::ADDRESS + Clusters::SIZE * Cluster::SIZE;

    pub unsafe fn clusters() -> Unique<Clusters> {
        Unique::new(Clusters::ADDRESS as *mut _)
    }

    pub unsafe fn get(&self, idx: usize) -> Option<&Cluster> {
        if idx < Clusters::LENGTH {
            Some(&self.clusters[idx])
        } else {
            None
        }
    }

    pub unsafe fn get_mut(&mut self, idx: usize) -> Option<&mut Cluster> {
        if idx < Clusters::LENGTH {
            Some(&mut self.clusters[idx])
        } else {
            None
        }
    }

    pub fn index_to_address(idx: usize) -> usize {
        idx << 12
    }

    pub fn address_to_index(address: usize) -> usize {
        address >> 12
    }

    pub unsafe fn init() {
        #[repr(packed)]
        struct MemoryMap {
            map: [MemoryMapEntry; (0x5000 - 0x500) / 24/*TODO hould be `MemoryMap::LENGTH`, but rustc complains*/]
        }

        impl MemoryMap {
            const ADDRESS: usize = KERNEL_BASE + 0x500;
            const END: usize = KERNEL_BASE + 0x5000;
            const SIZE: usize = MemoryMap::END - MemoryMap::ADDRESS;
            const LENGTH: usize = MemoryMap::SIZE / MemoryMapEntry::SIZE;
        }

        /// A memory map entry
        #[repr(packed)]
        struct MemoryMapEntry {
            base: u64,
            len: u64,
            class: u32,
            acpi: u32,
        }

        impl MemoryMapEntry {
            const SIZE: usize = 24;  // mem::sizeof::<MemoryMap>()
        }

        let mut c = Clusters::clusters();
        let mut c = c.get_mut();
        c.clear();

        //read memory map
        // TODO: Optimize this loop
        let mmap = &*(MemoryMap::ADDRESS as *const MemoryMap);
        for entry in mmap.map.iter() {
            if entry.len > 0 && entry.class == 1 {
                for cluster in 0..Clusters::LENGTH {
                    let address = Clusters::index_to_address(cluster);
                    if address as u64 >= entry.base &&
                       (address as u64 + PAGE_SIZE as u64) <= (entry.base + entry.len) {
                        c.clusters[cluster] = Cluster::empty();
                    }
                }
            }
        }

        //reserve clusters used by Kernel, Bootloader, Pagetables and Clusters
        //these values need to be a multiple of Cluster::SIZE
        //TODO we could reserve way less, if we knew where exactly all those things start and end...
        let reserved = [
            (0x7000, 0x100000/*TODO this should be the end of the bootloader*/),
            (0x100000, PAGE_END_PHYS /*TODO there is some free space between the kernel and the pages...*/),
            (Clusters::ADDRESS, Clusters::END)
        ];

        for &(start, end) in reserved.iter() {
            for i in (start / Cluster::SIZE)..(end / Cluster::SIZE) {
                c.clusters[i] = Cluster::unusable();
            }
        }
    }

    unsafe fn clear(&mut self) {
        self.clusters = [Cluster::unusable(); 1024 * 1024 /*TODO @see `struct MEmoryMap` above*/];
    }
}

const CLUSTER_COUNT: usize = 1024 * 1024;
const CLUSTER_ADDRESS: usize = KERNEL_BASE + 0x400000;
const CLUSTER_SIZE: usize = 4096;

/// Get the data (address) of a given cluster
pub unsafe fn cluster(number: usize) -> usize {
    if number < CLUSTER_COUNT {
        ptr::read((CLUSTER_ADDRESS + number * mem::size_of::<usize>()) as *const usize)
    } else {
        0
    }
}

/// Set the address of a cluster
pub unsafe fn set_cluster(number: usize, address: usize) {
    if number < CLUSTER_COUNT {
        ptr::write((CLUSTER_ADDRESS + number * mem::size_of::<usize>()) as *mut usize,
                   address);
    }
}

/// Convert an adress to the cluster number
pub unsafe fn address_to_cluster(address: usize) -> usize {
    if address >= CLUSTER_ADDRESS + CLUSTER_COUNT * mem::size_of::<usize>() {
        (address - CLUSTER_ADDRESS - CLUSTER_COUNT * mem::size_of::<usize>()) / CLUSTER_SIZE
    } else {
        0
    }
}

pub unsafe fn cluster_to_address(number: usize) -> usize {
    CLUSTER_ADDRESS + CLUSTER_COUNT * mem::size_of::<usize>() + number * CLUSTER_SIZE
}

/// Initialize clusters
pub unsafe fn cluster_init() {
    #[repr(packed)]
    struct MemoryMapEntry {
        base: u64,
        len: u64,
        class: u32,
        acpi: u32,
    }
    const MEMORY_MAP: *const MemoryMapEntry = 0x500 as *const _;
    // First, set all clusters to the not present value
    for cluster in 0..CLUSTER_COUNT {
        set_cluster(cluster, 0xFFFFFFFF);
    }

    // Next, set all valid clusters to the free value
    // TODO: Optimize this function
    for i in 0..((0x5000 - 0x500) / mem::size_of::<MemoryMapEntry>()) {
        let entry = &*MEMORY_MAP.offset(i as isize);
        if entry.len > 0 && entry.class == 1 {
            for cluster in 0..CLUSTER_COUNT {
                let address = cluster_to_address(cluster);
                if address as u64 >= entry.base &&
                   (address as u64 + CLUSTER_SIZE as u64) <= (entry.base + entry.len) {
                    set_cluster(cluster, 0);
                }
            }
        }
    }
}

/// Allocate memory
pub unsafe fn alloc(size: usize) -> usize {
    if size > 0 {
        let mut number = 0;
        let mut count = 0;

        for i in 0..CLUSTER_COUNT {
            if cluster(i) == 0 {
                if count == 0 {
                    number = i;
                }
                count += 1;
                if count * CLUSTER_SIZE > size {
                    break;
                }
            } else {
                count = 0;
            }
        }
        if count * CLUSTER_SIZE > size {
            let address = cluster_to_address(number);

            ::memset(address as *mut u8, 0, count * CLUSTER_SIZE);

            for i in number..number + count {
                set_cluster(i, address);
            }
            return address;
        }
    }

    0
}

pub unsafe fn alloc_aligned(size: usize, align: usize) -> usize {
    if size > 0 {
        let mut number = 0;
        let mut count = 0;

        for i in 0..CLUSTER_COUNT {
            if cluster(i) == 0 && (count > 0 || cluster_to_address(i) % align == 0) {
                if count == 0 {
                    number = i;
                }
                count += 1;
                if count * CLUSTER_SIZE > size {
                    break;
                }
            } else {
                count = 0;
            }
        }
        if count * CLUSTER_SIZE > size {
            let address = cluster_to_address(number);

            ::memset(address as *mut u8, 0, count * CLUSTER_SIZE);

            for i in number..number + count {
                set_cluster(i, address);
            }
            return address;
        }
    }

    0
}

pub unsafe fn alloc_type<T>() -> *mut T {
    alloc(mem::size_of::<T>()) as *mut T
}

pub unsafe fn alloc_size(ptr: usize) -> usize {
    let mut size = 0;

    if ptr > 0 {
        for i in address_to_cluster(ptr)..CLUSTER_COUNT {
            if cluster(i) == ptr {
                size += CLUSTER_SIZE;
            } else {
                break;
            }
        }
    }

    size
}

pub unsafe fn unalloc(ptr: usize) {
    if ptr > 0 {
        for i in address_to_cluster(ptr)..CLUSTER_COUNT {
            if cluster(i) == ptr {
                set_cluster(i, 0);
            } else {
                break;
            }
        }
    }
}

pub unsafe fn unalloc_type<T>(ptr: *mut T) {
    unalloc(ptr as usize);
}

pub unsafe fn realloc(ptr: usize, size: usize) -> usize {
    let mut ret = 0;

    if size == 0 {
        if ptr > 0 {
            unalloc(ptr);
        }
    } else {
        let old_size = alloc_size(ptr);
        if size <= old_size {
            ret = ptr;
        } else {
            ret = alloc(size);
            if ptr > 0 {
                if ret > 0 {
                    let copy_size = cmp::min(old_size, size);

                    ::memmove(ret as *mut u8, ptr as *const u8, copy_size);
                }
                unalloc(ptr);
            }
        }
    }

    ret
}

pub unsafe fn realloc_inplace(ptr: usize, size: usize) -> usize {
    let old_size = alloc_size(ptr);
    if size <= old_size {
        size
    } else {
        old_size
    }
}

pub fn memory_used() -> usize {
    let mut ret = 0;

    unsafe {
        for i in 0..CLUSTER_COUNT {
            if cluster(i) != 0 && cluster(i) != 0xFFFFFFFF {
                ret += CLUSTER_SIZE;
            }
        }
    }

    ret
}

pub fn memory_free() -> usize {
    let mut ret = 0;

    unsafe {
        for i in 0..CLUSTER_COUNT {
            if cluster(i) == 0 {
                ret += CLUSTER_SIZE;
            }
        }
    }

    ret
}
