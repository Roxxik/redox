use core::ptr::{ self, Unique };
use core::marker::PhantomData;
use core::ops::{ Index, IndexMut, Deref, DerefMut };

// PAGE_DIRECTORY:
// 1024 dwords pointing to page tables
// PAGE_TABLES:
// 1024 * 1024 dwords pointing to pages
// PAGE_END:
//

//Page flags
pub const PF_PRESENT: usize = 1;
pub const PF_WRITE: usize = 1 << 1;
pub const PF_USER: usize = 1 << 2;
pub const PF_WRITE_THROUGH: usize = 1 << 3;
pub const PF_CACHE_DISABLE: usize = 1 << 4;
pub const PF_ACCESSED: usize = 1 << 5;
pub const PF_DIRTY: usize = 1 << 6;
pub const PF_SIZE: usize = 1 << 7;
pub const PF_GLOBAL: usize = 1 << 8;
//Extra flags (Redox specific)
pub const PF_ALLOC: usize = 1 << 9;
pub const PF_EXEC: usize = 1 << 10;
pub const PF_STACK: usize = 1 << 11;

pub const PF_ALL: usize =  0xFFF;
pub const PF_NONE: usize = 0xFFFFF000;
//---  old stuff above



#[derive(Copy, Clone)]
pub struct VAddr(usize);

impl VAddr {
    pub const SIZE: usize = /*sizeof(usize)*/ 4;
    const PDP_OFF: usize = 0x0; //TODO look this up

    pub fn pdp_entry(&self) -> usize {
        self.0 >> Self::PDP_OFF
    }
}

impl Deref for VAddr {
    type Target = usize;
    fn deref(&self) -> &usize {
        &self.0
    }
}

impl DerefMut for VAddr {
    fn deref_mut(&mut self) -> &mut usize {
        &mut self.0
    }
}


#[derive(Copy, Clone)]
pub struct PAddr(u64);

impl Deref for PAddr {
    type Target = u64;
    fn deref(&self) -> &u64 {
        &self.0
    }
}

impl DerefMut for PAddr {
    fn deref_mut(&mut self) -> &mut u64 {
        &mut self.0
    }
}

pub unsafe fn invalidate_tlb_page(vaddr: VAddr) {
    asm!("invlpg [$0]"
        :
        : "r"(vaddr)
        : "memory"
        : "intel", "volatile");
}

pub unsafe fn load_cr3(cr3: usize) {
    asm!("mov cr3, $0"
        :
        : "r"(cr3)
        : "memory"
        : "intel", "volatile");
}

pub unsafe fn reload_tlb() {
    let _a: usize;
    asm!("mov $0, cr3
          mov cr3, $0"
        : "=r"(_a)
        :
        : "memory"
        : "intel", "volatile");
}

#[inline(always)]
pub unsafe fn bochs_break() {
    asm!("xchg bx, bx" :::: "intel", "volatile");
}

pub struct CR3 {
    cr3: usize,
    table: PhantomData<Unique<PageTable<PDP>>>,
}

//TODO think about:
// either use PahntomData<&'a T> ot PhantomData<T>
//the former indicates NO Ownership
//the later inidcates Ownership

impl CR3 {
    const PDP: usize = 0xFFFFFFE0;
    const PWT: usize = 0x8;
    const PCD: usize = 0x10;

    pub fn get_page_write_through(&self) -> bool {
        self.cr3 & CR3::PWT != 0
    }

    pub fn set_page_write_through(&mut self, flag: bool) {
        if flag {
            self.cr3 |= CR3::PWT;
        } else {
            self.cr3 &= !CR3::PWT;
        }
    }

    pub fn get_page_cache_disable(&self) -> bool {
        self.cr3 & CR3::PCD != 0
    }


    pub fn set_page_cache_disable(&mut self, flag: bool) {
        if flag {
            self.cr3 |= CR3::PCD;
        } else {
            self.cr3 &= !CR3::PCD;
        }
    }

    pub fn get_pdp_base_address(&self) -> PAddr {
        PAddr((self.cr3 & CR3::PDP) as u64)
    }

    //CR3 can only hold a 32-bit offset to the PDP-Base,
    pub fn set_pdp_base_address(&mut self, pdp_base: usize) {
        self.cr3 &= !CR3::PDP;
        self.cr3 |= pdp_base;
    }

    pub unsafe fn load(&self) {
        load_cr3(self.cr3);
    }
}

//TODO reconsider this traits
impl From<Unique<PageTable<PDP>>> for CR3 {
    fn from(pdp: Unique<PageTable<PDP>>) -> CR3 {
        CR3 { cr3: *pdp as usize, table: PhantomData }
    }
}

impl Into<Unique<PageTable<PDP>>> for CR3 {
    fn into(self) -> Unique<PageTable<PDP>> {
        unsafe { Unique::new(self.get_pdp_base_address().0 as *mut _) }
    }
}

// TODO impl Drop for CR3, to drop the accompayning PDP
// TODO think about Drop in the whole page hirarchy



pub const KERNEL_BASE: usize = 0xC0000000;
pub const PAGE_SIZE: usize = 4096;

//the page directory pointer used by kernel processes (kidle / kevent...)
const PAGE_DIRECTORY_POINTER_PHYS: usize = 0x200000;
const PAGE_DIRECTORY_POINTER: usize = KERNEL_BASE + PAGE_DIRECTORY_POINTER_PHYS;

//the page directory containing ALL kernel pages
const PAGE_DIRECTORY_PHYS: usize = PAGE_DIRECTORY_POINTER_PHYS + PAGE_SIZE;
const PAGE_DIRECTORY: usize = KERNEL_BASE + PAGE_DIRECTORY_PHYS;

//the initial statically allocated page table, all later pagetables are dynamically allocated
//this one needs to be mapped ALL the time for the Mapper to work correctly
//the Mapper maps all the other pagetables, when they are needed
const INIT_PT_PHYS: usize = PAGE_DIRECTORY_PHYS + PAGE_SIZE;
const INIT_PT: usize = KERNEL_BASE + INIT_PT_PHYS;

const DYN_MAPPING: usize = INIT_PT + PAGE_SIZE;

const PAGE_END_PHYS: usize = INIT_PT_PHYS + PAGE_SIZE;
pub const PAGE_END: usize = DYN_MAPPING + PAGE_SIZE;
// initial virtual memory will be: (add 0xC0000000 to everything)
// !!! this assumes the kernel image is smaller then 1MiB !!!
// 0x000000 - 0x1FFFFF kernel code, will be mapped smaller after the PMM is set up
// 0x200000 - 0x202FFF page tables
// 0x203000 - 0x203FFF dynamic mapping page(used by the Mapper)
// 0x204000 - ???????? The clusters

// map all relevant kernel structures, including the kernel PD and the Mapper PT
// the last GiB(one PD) of virtual addresses is reserved for the kernel
pub unsafe fn paging_init() {
    bochs_break();
    //enable the kernel mapping
    let mut pdp = Unique::new(PAGE_DIRECTORY_POINTER as *mut PageTable<PDP>);
    let mut pdp = pdp.get_mut();
    pdp.clear();
    bochs_break();

    pdp[3] = PageTableEntry::new(PAGE_DIRECTORY_PHYS as u64 | PDP::PRESENT);

    let mut pd = Unique::new(PAGE_DIRECTORY as *mut PageTable<PD>);
    let mut pd = pd.get_mut();
    pd.clear();
    bochs_break();

    //kernel, don't map global since this is only temporary
    pd[0] = PageTableEntry::new(PD::LARGE_PAGE | PD::PRESENT);
    //pt
    pd[1] = PageTableEntry::new(INIT_PT_PHYS as u64 | PD::PRESENT);
    //clusters
    pd[2] = PageTableEntry::new(0x400000 | PD::LARGE_PAGE | PD::GLOBAL | PD::PRESENT);
    pd[3] = PageTableEntry::new(0x600000 | PD::LARGE_PAGE | PD::GLOBAL | PD::PRESENT);

    let mut pt = Unique::new(INIT_PT as *mut PageTable<PT>);
    let mut pt = pt.get_mut();
    pt.clear();
    bochs_break();

    //map page tables
    pt[0] = PageTableEntry::new(PAGE_DIRECTORY_POINTER_PHYS as u64 | PT::GLOBAL | PT::PRESENT);
    pt[1] = PageTableEntry::new(PAGE_DIRECTORY_PHYS as u64         | PT::GLOBAL | PT::PRESENT);
    pt[2] = PageTableEntry::new(INIT_PT_PHYS as u64                | PT::GLOBAL | PT::PRESENT);
    //reserve for dynamic mappings (see paging::Mapper)
    pt[3] = PageTableEntry::new(PT::REDOX_KERNEL_RESERVED);


    bochs_break();
    load_cr3(PAGE_DIRECTORY_POINTER_PHYS);
}

//this is only valid after paging::paging_init
//FIXME if rust gains the ability to use unsafe in statics, make this a static
pub unsafe fn kernel_pd() -> Unique<PageTable<PD>> {
    Unique::new(PAGE_DIRECTORY as *mut _)
}

//replace by generic version, if dependant consts are a thing in Rust
const PAGE_TABLE_LENGTH: usize = 512;

pub struct PageTable<P> {
    entries: [PageTableEntry<P>; PAGE_TABLE_LENGTH]
}

impl<P: PageTableType> PageTable<P> {
    // only usable after the kernel allocator is set up!
    //pub unsafe fn alloc() -> Unique<PageTable<P>> {
    //    let pt = Unique::new(memory::alloc_type());
    //    pt.get_mut().clear();
    //    pt
    //}

    pub unsafe fn clear(&mut self) {
        self.entries = [PageTableEntry::empty(); PAGE_TABLE_LENGTH];
        //this runs faster, but is not very generic.... rework this into memset or something...
        //asm!("rep stosd"
        //    :
        //    : "{edi}"(self as *mut _ as usize), "{ecx}"(PAGE_TABLE_LENGTH / 4), "{eax}"(0)
        //    : "memory"
        //    : "intel", "volatile");
    }
}

impl<P: Sized> Index<usize> for PageTable<P> {
    type Output = PageTableEntry<P>;
    fn index(&self, index: usize) -> &PageTableEntry<P> {
        &self.entries[index]
    }
}

impl<P: Sized> IndexMut<usize> for PageTable<P> {
    fn index_mut(&mut self, index: usize) -> &mut PageTableEntry<P> {
        &mut self.entries[index]
    }
}

pub trait PageTableType: Copy {
    const LENGTH: usize;
    const NONE:                  u64 = 0x000FFFFFFFFFF000;
    const PRESENT:               u64 = 1 << 0;
    const PAGE_WRITE_THROUGH:    u64 = 1 << 3;
    const PAGE_CACHE_DISABLE:    u64 = 1 << 4;
    const REDOX_KERNEL_RESERVED: u64 = 1 << 9;  // this virtual address is reserved for the kernel
    const AVAILABLE2:            u64 = 1 << 10; // currently unused
    const AVAILABLE3:            u64 = 1 << 11; // currently unused
}

#[derive(Copy, Clone)]
pub struct PDP;
#[derive(Copy, Clone)]
pub struct PD;
#[derive(Copy, Clone)]
pub struct PT;

impl PageTableType for PDP {
    const LENGTH: usize = 4;
}
impl PageTableType for PD {
    const LENGTH: usize = 512;
}
impl PageTableType for PT {
    const LENGTH: usize = 512;
}

impl PD {
    const LARGE_PAGE: u64 = 1 << 7;
    const GLOBAL:     u64 = 1 << 8;
}

impl PT {
    const GLOBAL:     u64 = 1 << 8;
}

#[derive(Copy, Clone)]
pub struct PageTableEntry<P> {
    entry: u64,
    ty: PhantomData<P>,
}

impl<P: PageTableType> PageTableEntry<P> {

    pub fn empty() -> PageTableEntry<P> {
        PageTableEntry::new(0)
    }

    pub fn new(entry: u64) -> PageTableEntry<P> {
        PageTableEntry {
            entry: entry,
            ty: PhantomData,
        }
    }

    //pub fn get_present(&self) -> bool {
    //    self.entry & PageTableEntry::<P>::PRESENT != 0
    //}

    //pub fn set_present(&mut self, flag: bool) {
    //    if flag {
    //        self.entry |= PageTableType::PRESENT;
    //    } else {
    //        self.entry &= !PageTableType::PRESENT;
    //    }
    //}
}

static mut mapper: Mapper = Mapper { paddr: None };

//maps a predefined address to a given physical address
//this is a singleton, instancing it twice leads to random overwriting of page mappings
//this is only ever to be used within the Virtual Memory Manager
//TODO guard the mapping page and the pagetable by a Mutex and make sure this struct is only created once
pub struct Mapper {
    //the currently mapped physical address
    paddr: Option<PAddr>,
}

impl Mapper {
    const VADDR: VAddr = VAddr(DYN_MAPPING);

    pub fn new() -> Self {
        Mapper {
            paddr: None,
        }
    }

    pub fn is_mapped(&self) -> bool {
        self.paddr.is_some()
    }

    pub fn get_paddr(&self) -> Option<PAddr> {
        self.paddr
    }

    pub unsafe fn map(&mut self, paddr: PAddr) -> Option<VAddr> {
        let paddr = paddr.0 & PT::NONE; // clear unneeded bits
        if self.is_mapped() {
            //TODO consider alternative: unmap here, this might flush someone's page if not properly sync'd
            None
        } else {
            //map the page
            let mut pt = Unique::new(INIT_PT as *mut PageTable<PT>);
            let mut pt = pt.get_mut();
            pt[2] = PageTableEntry::new(paddr | PT::PRESENT);


            self.paddr = Some(PAddr(paddr));
            Some(Self::VADDR)
        }
    }

    //TODO check that no one is using the mapped page anymore... see TODO at Mapper
    pub unsafe fn unmap(&mut self) {
        //unmap page
        let mut pt = Unique::new(INIT_PT as *mut PageTable<PT>);
        let mut pt = pt.get_mut();
        pt[2] = PageTableEntry::new(PT::REDOX_KERNEL_RESERVED);
        //invalidate the TLB
        invalidate_tlb_page(Self::VADDR);
        self.paddr = None;
    }
}


pub struct VMM {
    cr3: CR3,
    flags: usize,
}

impl VMM {
    /// Create a new Mapper for x86
    /// # Safety
    /// - Allocates and initializes a new page directory
    /// - *Will fail if memory allocation fails*
    //pub unsafe fn new(flags: usize) -> VMM {
    //    let pdp = PageTable::alloc();
    //    VMM {
    //        cr3: CR3::from(pdp),
    //        flags: flags,
    //    }
    //}

    /// Use this Mapper for memory operations
    /// # Safety
    /// - Sets CR3 to the page directory location, ensuring that flags are removed
    /// - *Will fail if memory allocation failed in Pager::new()*
    pub unsafe fn enable(&self) {
        self.cr3.load();
    }

    //TODO rethink ths function
    /// Map a virtual address to a physical address
    /// # Safety
    /// - Calls PageDirectory::map() using a raw pointer
    /// - *Will fail if memory allocation failed in Pager::new()*
    pub unsafe fn map(&mut self, _vaddr: VAddr, _paddr: PAddr) -> bool {
        //let pdpe = self.cr3[vaddr.pdp_entry()];
        //if !pdpe.get_present() {
        //    pdpe.set_table_address(PageTable::alloc());
        //}
        //let pde = pdpe[vaddr.pde_entry()]; // this fails if the table is not mapped
        //if !pde.get_present() {
        //    pde.set_table_address(PageTable::alloc());
        //}
        //let pte = pde[vaddr.pt_entry()];
        //if pte.get_present() {
        //    return false;
        //} else {
        //    pte.set_physical_page_address(paddr);
        //    return true;
        //}
        false
    }

    /// Unmap a virtual address
    /// # Safety
    /// - Calls PageDirectory::unmap() using a raw pointer
    /// - *Will fail if memory allocation failed in Pager::new()*
    pub unsafe fn unmap(&mut self, _vaddr: VAddr) {
        //self.cr3.into()[vaddr.pdp_entry()].unmap(vaddr, paddr);
    }
}


pub const PAGE_TABLE_SIZE: usize = 1024;
pub const PAGE_ENTRY_SIZE: usize = 4;
//pub const PAGE_SIZE: usize = 4096;

pub const PAGE_TABLES: usize = PAGE_DIRECTORY + PAGE_TABLE_SIZE * PAGE_ENTRY_SIZE;

/// A memory page
pub struct Page {
    /// The virtual address
    virtual_address: usize,
}

impl Page {
    /// Initialize the memory page
    pub unsafe fn init() {
        for table_i in 0..PAGE_TABLE_SIZE {
            ptr::write((PAGE_DIRECTORY + table_i * PAGE_ENTRY_SIZE) as *mut u32,
                       // TODO: Use more restrictive flags
                       (PAGE_TABLES + table_i * PAGE_TABLE_SIZE * PAGE_ENTRY_SIZE) as u32 |
                       1 << 2 | 1 << 1 | 1); //Allow userspace, read/write, present

            for entry_i in 0..PAGE_TABLE_SIZE {
                Page::new((table_i * PAGE_TABLE_SIZE + entry_i) * PAGE_SIZE).map_identity();
            }
        }

        asm!("mov cr3, $0
            mov $0, cr0
            or $0, $1
            mov cr0, $0"
            :
            : "r"(PAGE_DIRECTORY), "r"(0x80000000 as usize)
            : "memory"
            : "intel", "volatile");
    }

    /// Create a new memory page from a virtual address
    pub fn new(virtual_address: usize) -> Self {
        Page { virtual_address: virtual_address }
    }

    /// Get the entry address
    fn entry_address(&self) -> usize {
        let page = self.virtual_address / PAGE_SIZE;
        let table = page / PAGE_TABLE_SIZE;
        let entry = page % PAGE_TABLE_SIZE;

        PAGE_TABLES + (table * PAGE_TABLE_SIZE + entry) * PAGE_ENTRY_SIZE
    }

    /// Flush the memory page
    unsafe fn flush(&self) {
        asm!("invlpg [$0]"
            :
            : "{eax}"(self.virtual_address)
            : "memory"
            : "intel", "volatile");
    }

    /// Get the current physical address
    pub fn phys_addr(&self) -> usize {
        unsafe { (ptr::read(self.entry_address() as *mut usize) & PF_NONE) as usize }
    }

    /// Get the current virtual address
    pub fn virt_addr(&self) -> usize {
        self.virtual_address & PF_NONE
    }

    /// Map the memory page to a given physical memory address
    pub unsafe fn map(&mut self, physical_address: usize) {
        ptr::write(self.entry_address() as *mut usize,
                   (physical_address & PF_NONE) | PF_PRESENT);
        self.flush();
    }

    /// Map the memory page to a given physical memory address, and allow userspace read access
    pub unsafe fn map_user_read(&mut self, physical_address: usize) {
        ptr::write(self.entry_address() as *mut usize,
                   (physical_address & PF_NONE) | PF_USER | PF_PRESENT);
        self.flush();
    }

    /// Map the memory page to a given physical memory address, and allow userspace read/write access
    pub unsafe fn map_user_write(&mut self, physical_address: usize) {
        ptr::write(self.entry_address() as *mut usize,
                   (physical_address & PF_NONE) | PF_USER | PF_WRITE | PF_PRESENT);
        self.flush();
    }

    /// Map to the virtual address
    pub unsafe fn map_identity(&mut self) {
        let physical_address = self.virtual_address;
        self.map(physical_address);
    }

    /// Unmap the memory page
    pub unsafe fn unmap(&mut self) {
        ptr::write(self.entry_address() as *mut usize, 0);
        self.flush();
    }
}
