#[cfg(any(
    windows,
    target_os = "linux",
    target_vendor = "apple",
    all(target_arch = "aarch64", target_os = "android")
))]
use std::{collections::BTreeMap, ffi::c_void};

use backtrace::Backtrace;
use frida_gum::{PageProtection, RangeDetails};
use hashbrown::HashMap;
use libafl::bolts::cli::FuzzerOptions;
#[cfg(any(
    windows,
    target_os = "linux",
    target_vendor = "apple",
    all(target_arch = "aarch64", target_os = "android")
))]
use mmap_rs::{MemoryAreas, MmapMut, MmapOptions, UnsafeMmapFlags};
use rangemap::RangeSet;
use serde::{Deserialize, Serialize};

use crate::asan::errors::{AsanError, AsanErrors};

/// An allocator wrapper with binary-only address sanitization
#[derive(Debug)]
pub struct Allocator {
    /// The fuzzer options
    #[allow(dead_code)]
    options: FuzzerOptions,
    /// The page size
    page_size: usize,
    /// The shadow offsets
    shadow_offset: usize,
    /// The shadow bit
    shadow_bit: usize,
    /// The preallocated shadow mapping
    pre_allocated_shadow: Option<MmapMut>,
    /// All tracked allocations
    allocations: HashMap<usize, AllocationMetadata>,
    /// All mappings:
    mappings: HashMap<usize, MmapMut>,
    /// The shadow memory pages
    shadow_pages: RangeSet<usize>,
    /// A list of allocations
    allocation_queue: BTreeMap<usize, Vec<AllocationMetadata>>,
    /// The size of the largest allocation
    largest_allocation: usize,
    /// The total size of all allocations combined
    total_allocation_size: usize,
    /// The base address of the shadow memory
    base_mapping_addr: usize,
    /// The current mapping address
    current_mapping_addr: usize,
}

macro_rules! map_to_shadow {
    ($self:expr, $address:expr) => {
        $self.shadow_offset + (($address >> 3) & ((1 << ($self.shadow_bit + 1)) - 1))
    };
}

/// Metadata for an allocation
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AllocationMetadata {
    /// The start address for the allocation
    pub address: usize,
    /// The size of the allocation
    pub size: usize,
    /// The actual allocated size, including metadata
    pub actual_size: usize,
    /// A backtrace to the allocation location
    pub allocation_site_backtrace: Option<Backtrace>,
    /// A backtrace to the location where this memory has been released
    pub release_site_backtrace: Option<Backtrace>,
    /// If the allocation has been freed
    pub freed: bool,
    /// If the allocation was done with a size of 0
    pub is_malloc_zero: bool,
}

impl Allocator {
    /// Creates a new [`Allocator`] (not supported on this platform!)
    #[cfg(not(any(
        windows,
        target_os = "linux",
        target_vendor = "apple",
        all(target_arch = "aarch64", target_os = "android")
    )))]
    #[must_use]
    pub fn new(_: FuzzerOptions) -> Self {
        todo!("Shadow region not yet supported for this platform!");
    }

    /// Creates a new [`Allocator`]
    #[cfg(any(
        windows,
        target_os = "linux",
        target_vendor = "apple",
        all(target_arch = "aarch64", target_os = "android")
    ))]
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn new(options: FuzzerOptions) -> Self {
        let page_size = MmapOptions::page_size();
        // probe to find a usable shadow bit:
        let mut shadow_bit: usize = 0;

        let mut occupied_ranges: Vec<(usize, usize)> = vec![];
        // max(userspace address) this is usually 0x8_0000_0000_0000 - 1 on x64 linux.
        let mut userspace_max: usize = 0;

        // Enumerate memory ranges that are already occupied.
        for area in MemoryAreas::open(None).unwrap() {
            let base: usize = 2;
            let start = area.as_ref().unwrap().start();
            let end = area.unwrap().end();

            // log::trace!("occupied range: {:x} - {:x}", start, end);
            occupied_ranges.push((start, end));

            #[cfg(all(unix, target_arch = "x86_64"))]
            if end <= base.pow(48) && end > userspace_max {
                userspace_max = end;
            }
            #[cfg(all(not(unix), target_arch = "x86_64"))]
            if (end >> 3) <= base.pow(44) && (end >> 3) > userspace_max {
                userspace_max = end >> 3;
            }

            #[cfg(target_arch = "aarch64")]
            if end <= base.pow(52) && end > userspace_max {
                userspace_max = end;
            }
        }

        let mut maxbit = 0;
        for power in 1..64 {
            let base: usize = 2;
            if base.pow(power) > userspace_max {
                maxbit = power;
                break;
            }
        }
        log::trace!("userspace_max: {:x}, maxbit: {:x}", userspace_max, maxbit);

        let mut pre_allocated_shadow = None;
        {
            for try_shadow_bit in &[maxbit, maxbit - 4, maxbit - 3, maxbit - 2] {
                let addr: usize = 1 << try_shadow_bit;
                let shadow_start = addr;
                let shadow_end = addr + addr + addr;

                // check if the proposed shadow bit overlaps with occupied ranges.
                for (start, end) in &occupied_ranges {
                    if (shadow_start <= *end) && (*start <= shadow_end) {
                        // log::trace!("{:x} {:x}, {:x} {:x}",shadow_start,shadow_end,start,end);
                        log::warn!("shadow_bit {try_shadow_bit:x} is not suitable");
                        break;
                    }
                }

                if let Ok(mapping) = unsafe {
                    MmapOptions::new(1 << (*try_shadow_bit))
                        .unwrap()
                        .with_address(addr)
                        .with_unsafe_flags(UnsafeMmapFlags::DONT_COMMIT)
                        .map_mut()
                } {
                    shadow_bit = (*try_shadow_bit).try_into().unwrap();
                    log::warn!("shadow_bit {shadow_bit:x} is suitable");
                    pre_allocated_shadow = Some(mapping);
                    break;
                };
            }
        }

        Self {
            options,
            page_size,
            pre_allocated_shadow,
            shadow_offset: 1 << shadow_bit,
            shadow_bit,
            allocations: HashMap::new(),
            mappings: HashMap::new(),
            shadow_pages: RangeSet::new(),
            allocation_queue: BTreeMap::new(),
            largest_allocation: 0,
            total_allocation_size: 0,
            base_mapping_addr: (1 << shadow_bit) + (1 << shadow_bit),
            current_mapping_addr: (1 << shadow_bit) + (1 << shadow_bit),
        }
    }

    /// Retreive the shadow bit used by this allocator.
    #[must_use]
    pub fn shadow_bit(&self) -> u32 {
        self.shadow_bit as u32
    }

    #[inline]
    #[must_use]
    fn round_up_to_page(&self, size: usize) -> usize {
        ((size + self.page_size) / self.page_size) * self.page_size
    }

    #[inline]
    #[must_use]
    fn round_down_to_page(&self, value: usize) -> usize {
        (value / self.page_size) * self.page_size
    }

    fn find_smallest_fit(&mut self, size: usize) -> Option<AllocationMetadata> {
        for (current_size, list) in &mut self.allocation_queue {
            if *current_size >= size {
                if let Some(metadata) = list.pop() {
                    return Some(metadata);
                }
            }
        }
        None
    }

    /// Allocate a new allocation of the given size.
    #[must_use]
    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn alloc(&mut self, size: usize, _alignment: usize) -> *mut c_void {
        log::trace!("ALLOC({size:x})");

        let mut is_malloc_zero = false;
        let size = if size == 0 {
            // log::warn!("zero-sized allocation!");
            is_malloc_zero = true;
            16
        } else {
            size
        };
        if size > self.options.max_allocation {
            #[allow(clippy::manual_assert)]
            if self.options.max_allocation_panics {
                panic!("ASAN: Allocation is too large: 0x{size:x}");
            }

            return std::ptr::null_mut();
        }
        let rounded_up_size = self.round_up_to_page(size) + 2 * self.page_size;

        if self.total_allocation_size + rounded_up_size > self.options.max_total_allocation {
            return std::ptr::null_mut();
        }
        self.total_allocation_size += rounded_up_size;

        let metadata = if let Some(mut metadata) = self.find_smallest_fit(rounded_up_size) {
            //log::trace!("reusing allocation at {:x}, (actual mapping starts at {:x}) size {:x}", metadata.address, metadata.address - self.page_size, size);
            metadata.is_malloc_zero = is_malloc_zero;
            metadata.size = size;
            if self.options.allocation_backtraces {
                metadata.allocation_site_backtrace = Some(Backtrace::new_unresolved());
            }
            metadata
        } else {
            log::trace!("{:x}, {:x}", self.current_mapping_addr, rounded_up_size);
            let mapping = match MmapOptions::new(rounded_up_size)
                .unwrap()
                .with_address(self.current_mapping_addr)
                .map_mut()
            {
                Ok(mapping) => mapping,
                Err(err) => {
                    log::error!(
                        "An error occurred while mapping memory: {err:?} {:x}",
                        self.current_mapping_addr
                    );
                    return std::ptr::null_mut();
                }
            };
            self.current_mapping_addr += ((rounded_up_size
                + MmapOptions::allocation_granularity())
                / MmapOptions::allocation_granularity())
                * MmapOptions::allocation_granularity();

            self.map_shadow_for_region(
                mapping.as_ptr() as usize,
                mapping.as_ptr().add(mapping.size()) as usize,
                false,
            );
            let address = mapping.as_ptr() as usize;
            self.mappings.insert(address, mapping);

            let mut metadata = AllocationMetadata {
                address,
                size,
                actual_size: rounded_up_size,
                ..AllocationMetadata::default()
            };
            if self.options.allocation_backtraces {
                metadata.allocation_site_backtrace = Some(Backtrace::new_unresolved());
            }

            metadata
        };

        self.largest_allocation = std::cmp::max(self.largest_allocation, metadata.actual_size);
        // unpoison the shadow memory for the allocation itself
        Self::unpoison(
            map_to_shadow!(self, metadata.address + self.page_size),
            size,
        );
        let address = (metadata.address + self.page_size) as *mut c_void;

        self.allocations.insert(address as usize, metadata);
        // log::trace!("serving address: {:?}, size: {:x}", address, size);
        address
    }

    /// Releases the allocation at the given address.
    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn release(&mut self, ptr: *mut c_void) {
        //log::trace!("freeing address: {:?}", ptr);
        let Some(metadata) = self.allocations.get_mut(&(ptr as usize)) else {
            if !ptr.is_null() {
                 AsanErrors::get_mut()
                    .report_error(AsanError::UnallocatedFree((ptr as usize, Backtrace::new())), None);
          }
             return;
       };

        if metadata.freed {
            AsanErrors::get_mut().report_error(
                AsanError::DoubleFree((ptr as usize, metadata.clone(), Backtrace::new())),
                None,
            );
        }
        let shadow_mapping_start = map_to_shadow!(self, ptr as usize);

        metadata.freed = true;
        if self.options.allocation_backtraces {
            metadata.release_site_backtrace = Some(Backtrace::new_unresolved());
        }

        // poison the shadow memory for the allocation
        Self::poison(shadow_mapping_start, metadata.size);
    }

    /// Finds the metadata for the allocation at the given address.
    pub fn find_metadata(
        &mut self,
        ptr: usize,
        hint_base: usize,
    ) -> Option<&mut AllocationMetadata> {
        let mut metadatas: Vec<&mut AllocationMetadata> = self.allocations.values_mut().collect();
        metadatas.sort_by(|a, b| a.address.cmp(&b.address));
        let mut offset_to_closest = i64::max_value();
        let mut closest = None;
        for metadata in metadatas {
            let new_offset = if hint_base == metadata.address {
                (ptr as i64 - metadata.address as i64).abs()
            } else {
                std::cmp::min(
                    offset_to_closest,
                    (ptr as i64 - metadata.address as i64).abs(),
                )
            };
            if new_offset < offset_to_closest {
                offset_to_closest = new_offset;
                closest = Some(metadata);
            }
        }
        closest
    }

    /// Resets the allocator contents
    pub fn reset(&mut self) {
        let mut tmp_allocations = Vec::new();
        for (address, mut allocation) in self.allocations.drain() {
            if !allocation.freed {
                tmp_allocations.push(allocation);
                continue;
            }
            // First poison the memory.
            Self::poison(map_to_shadow!(self, address), allocation.size);

            // Reset the allocaiton metadata object
            allocation.size = 0;
            allocation.freed = false;
            allocation.allocation_site_backtrace = None;
            allocation.release_site_backtrace = None;

            // Move the allocation from the allocations to the to-be-allocated queues
            self.allocation_queue
                .entry(allocation.actual_size)
                .or_default()
                .push(allocation);
        }

        for allocation in tmp_allocations {
            self.allocations
                .insert(allocation.address + self.page_size, allocation);
        }

        self.total_allocation_size = 0;
    }

    /// Gets the usable size of the allocation, by allocated pointer
    pub fn get_usable_size(&self, ptr: *mut c_void) -> usize {
        match self.allocations.get(&(ptr as usize)) {
            Some(metadata) => metadata.size,
            None => {
                panic!(
                    "Attempted to get_usable_size on a pointer ({ptr:?}) which was not allocated!"
                );
            }
        }
    }

    fn unpoison(start: usize, size: usize) {
        // log::trace!("unpoisoning {:x} for {:x}", start, size / 8 + 1);
        unsafe {
            // log::trace!("memset: {:?}", start as *mut c_void);
            std::slice::from_raw_parts_mut(start as *mut u8, size / 8).fill(0xff);

            let remainder = size % 8;
            if remainder > 0 {
                // log::trace!("remainder: {:x}, offset: {:x}", remainder, start + size / 8);
                ((start + size / 8) as *mut u8).write(0xff << (8 - remainder));
            }
        }
    }

    /// Poisonn an area in memory
    pub fn poison(start: usize, size: usize) {
        // log::trace!("poisoning {:x} for {:x}", start, size / 8 + 1);
        unsafe {
            // log::trace!("memset: {:?}", start as *mut c_void);
            std::slice::from_raw_parts_mut(start as *mut u8, size / 8).fill(0x0);

            let remainder = size % 8;
            if remainder > 0 {
                // log::trace!("remainder: {:x}, offset: {:x}", remainder, start + size / 8);
                ((start + size / 8) as *mut u8).write(0x00);
            }
        }
    }

    /// Map shadow memory for a region, and optionally unpoison it
    pub fn map_shadow_for_region(
        &mut self,
        start: usize,
        end: usize,
        unpoison: bool,
    ) -> (usize, usize) {
        // log::trace!("start: {:x}, end {:x}, size {:x}", start, end, end - start);

        let shadow_mapping_start = map_to_shadow!(self, start);

        if end - start == 0 {
            return (shadow_mapping_start, 0);
        }

        let shadow_start = self.round_down_to_page(shadow_mapping_start);
        if self.pre_allocated_shadow.is_none() {
            let shadow_end =
                self.round_up_to_page((end - start) / 8) + self.page_size + shadow_start;
            for range in self.shadow_pages.gaps(&(shadow_start..shadow_end)) {
                let mapping = MmapOptions::new(range.end - range.start - 1)
                    .unwrap()
                    .with_address(range.start)
                    .map_mut()
                    .expect("An error occurred while mapping shadow memory");
                self.mappings.insert(range.start, mapping);
            }

            self.shadow_pages.insert(shadow_start..shadow_end);
        } else {
            let mapping = self.pre_allocated_shadow.as_mut().unwrap();
            let adjusted_start = shadow_start - mapping.as_ptr() as usize;
            mapping
                .commit(adjusted_start..(adjusted_start + (end - start)))
                .expect("Failed to commit shadow memory");
        }

        // log::trace!(
        //     "shadow_mapping_start: {:x}, shadow_size: {:x}",
        //     shadow_mapping_start,
        //     (end - start) / 8
        // );
        if unpoison {
            Self::unpoison(shadow_mapping_start, end - start);
        }

        (shadow_mapping_start, (end - start) / 8)
    }

    /// Maps the address to a shadow address
    #[inline]
    #[must_use]
    pub fn map_to_shadow(&self, start: usize) -> usize {
        map_to_shadow!(self, start)
    }

    /// Checks whether the given address up till size is valid unpoisoned shadow memory.
    #[inline]
    #[must_use]
    pub fn check_shadow(&self, address: *const c_void, size: usize) -> bool {
        if size == 0 {
            return true;
        }
        let address = address as usize;
        let mut shadow_size = size / 8;

        let mut shadow_addr = map_to_shadow!(self, address);

        if address & 0x7 > 0 {
            if unsafe { (shadow_addr as *mut u8).read() } & (address & 7) as u8
                != (address & 7) as u8
            {
                return false;
            }
            shadow_addr += 1;
            shadow_size -= 1;
        }

        let buf = unsafe { std::slice::from_raw_parts_mut(shadow_addr as *mut u8, shadow_size) };

        let (prefix, aligned, suffix) = unsafe { buf.align_to::<u128>() };

        if prefix.iter().all(|&x| x == 0xff)
            && suffix.iter().all(|&x| x == 0xff)
            && aligned
                .iter()
                .all(|&x| x == 0xffffffffffffffffffffffffffffffffu128)
        {
            let shadow_remainder = (size % 8) as u8;
            if shadow_remainder > 0 {
                (unsafe { ((shadow_addr + shadow_size) as *mut u8).read() } & shadow_remainder)
                    == shadow_remainder
            } else {
                true
            }
        } else {
            false
        }
    }
    /// Checks if the currennt address is one of ours
    #[inline]
    pub fn is_managed(&self, ptr: *mut c_void) -> bool {
        //self.allocations.contains_key(&(ptr as usize))
        self.base_mapping_addr <= ptr as usize && (ptr as usize) < self.current_mapping_addr
    }

    /// Checks if any of the allocations has not been freed
    pub fn check_for_leaks(&self) {
        for metadata in self.allocations.values() {
            if !metadata.freed {
                AsanErrors::get_mut()
                    .report_error(AsanError::Leak((metadata.address, metadata.clone())), None);
            }
        }
    }

    /// Unpoison all the memory that is currently mapped with read/write permissions.
    pub fn unpoison_all_existing_memory(&mut self) {
        RangeDetails::enumerate_with_prot(PageProtection::NoAccess, &mut |range: &RangeDetails| {
            if range.protection() as u32 & PageProtection::ReadWrite as u32 != 0 {
                let start = range.memory_range().base_address().0 as usize;
                let end = start + range.memory_range().size();
                if self.pre_allocated_shadow.is_some() && start == 1 << self.shadow_bit {
                    return true;
                }
                self.map_shadow_for_region(start, end, true);
            }
            true
        });
    }
}
