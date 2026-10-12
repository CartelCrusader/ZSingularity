#import "DonatedHeap.h"
#import "RamDonor.h"
#import "Engine.h"
#import "ZTweakLog.h"

#import <dlfcn.h>
#import <limits.h>
#import <malloc/malloc.h>
#import <errno.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <os/lock.h>
#import <stdatomic.h>
#import <stdlib.h>
#import <string.h>
#import <sys/mman.h>

static NSString * const kZSRamBypassSection = @"ramBypass";
static NSString * const kZSRamBypassEnabledKey = @"enabled";
static NSString * const kZSRamBypassHudKey = @"hud";

#define ZS_MALLOC_ALLOCATION_MAGIC 0x5A534D414C4C4F43ull
#define ZS_MALLOC_SLAB_MAGIC 0x5A53534C41424D47ull
#define ZS_MALLOC_SMALL_CLASS_COUNT 4096
#define ZS_MALLOC_KIND_LARGE 1u
#define ZS_MALLOC_KIND_SMALL 2u

typedef struct __attribute__((aligned(16))) {
    uint64_t magic;
    uint32_t requestedSize;
    uint32_t capacity;
    uint32_t allocationSize;
    uint32_t ownerOffset;
    uint32_t kind;
    uint32_t classIndex;
} ZSMallocAllocationHeader;

typedef struct ZSMallocSlab {
    uint64_t magic;
    uint32_t classIndex;
    uint32_t blockSize;
    uint32_t totalBlocks;
    uint32_t freeBlocks;
    uintptr_t freeList;
    struct ZSMallocSlab *next;
    uint64_t reserved;
} ZSMallocSlab;

#ifndef VM_FLAGS_OVERWRITE
#define VM_FLAGS_OVERWRITE 0x4000
#endif

static const uint64_t kZSDonatedTargetBytes = 3ull * 1024ull * 1024ull * 1024ull;
static const uint64_t kZSDonatedMinimumBytes = 256ull * 1024ull * 1024ull;
static const uint64_t kZSDonatedMinAllocation = 256ull * 1024ull;
static const uint64_t kZSDonatedLogStride = 256ull * 1024ull * 1024ull;

#define ZS_POOL_MAX_FREE 8192

typedef struct {
    uint64_t offset;
    uint64_t size;
} ZSPoolRange;

static struct {
    os_unfair_lock lock;
    uintptr_t base;
    uint64_t size;
    uint64_t cleanOffset;
    uint64_t used;
    uint32_t freeCount;
    ZSPoolRange free[ZS_POOL_MAX_FREE];
} g_pool;

static _Atomic(uint8_t) g_poolReady;
static _Atomic(uint8_t) g_mallocAllocationEnabled;
static _Atomic(uint8_t) g_mallocZoneRegistered;
static os_unfair_lock g_mallocZoneLock = OS_UNFAIR_LOCK_INIT;
static ZSMallocSlab *g_mallocSlabs[ZS_MALLOC_SMALL_CLASS_COUNT];
static malloc_zone_t g_mallocZone;
static malloc_introspection_t g_mallocIntrospection;
static _Atomic(uint64_t) g_mallocBlocksInUse;
static _Atomic(uint64_t) g_mallocBytesInUse;
static _Atomic(uint64_t) g_mallocPeakBytesInUse;
static _Atomic(uint64_t) g_mallocBytesAllocated;
static _Atomic(uint64_t) g_servedCount;
static _Atomic(uint64_t) g_fallbackCount;
static _Atomic(uint8_t) g_freeOverflowLogged;
static _Atomic(uint64_t) g_mmapCalls;
static _Atomic(uint64_t) g_largeCalls;
static _Atomic(uint64_t) g_rejectedCalls;
static _Atomic(uint32_t) g_rejectLogged;
static _Atomic(uint64_t) g_vmLargeCalls;
static _Atomic(uint64_t) g_reserveCalls;

static void *(*g_origMmap)(void *, size_t, int, int, int, off_t);
static int (*g_origMunmap)(void *, size_t);
static void *(*g_origMalloc)(size_t);
static void *(*g_origCalloc)(size_t, size_t);
static void *(*g_origRealloc)(void *, size_t);
static void (*g_origFree)(void *);
static size_t (*g_origMallocSize)(const void *);
static void *(*g_origValloc)(size_t);
static int (*g_origPosixMemalign)(void **, size_t, size_t);
static void *(*g_origAlignedAlloc)(size_t, size_t);
static void *(*g_origMemalign)(size_t, size_t);
static void *(*g_origMallocTypeMalloc)(size_t, uintptr_t);
static void *(*g_origMallocTypeCalloc)(size_t, size_t, uintptr_t);
static void *(*g_origMallocTypeRealloc)(void *, size_t, uintptr_t);
static void *(*g_origMallocTypeMemalign)(size_t, size_t, uintptr_t);
static kern_return_t (*g_origVmAllocate)(vm_map_t, vm_address_t *, vm_size_t, int);
static kern_return_t (*g_origMachVmAllocate)(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);
static kern_return_t (*g_origVmDeallocate)(vm_map_t, vm_address_t, vm_size_t);
static kern_return_t (*g_origMachVmDeallocate)(vm_map_t, mach_vm_address_t, mach_vm_size_t);

static void *g_selfBase;
static char g_bundlePrefix[PATH_MAX];
static size_t g_bundlePrefixLength;

static void zs_malloc_zone_register(void);

BOOL zs_ram_bypass_enabled(void)
{
    id stored = zs_settings_section(kZSRamBypassSection)[kZSRamBypassEnabledKey];

    return [stored respondsToSelector:@selector(boolValue)] ? [stored boolValue] : NO;
}

BOOL zs_ram_bypass_available(void)
{
    return ZSRamDonor.donorBundleIdentifier.length > 0;
}

BOOL zs_ram_hud_enabled(void)
{
    id stored = zs_settings_section(kZSRamBypassSection)[kZSRamBypassHudKey];

    return [stored respondsToSelector:@selector(boolValue)] ? [stored boolValue] : NO;
}

void zs_set_ram_hud_enabled(BOOL enabled)
{
    NSMutableDictionary *section = [zs_settings_section(kZSRamBypassSection) mutableCopy] ?: [NSMutableDictionary new];
    section[kZSRamBypassHudKey] = @(enabled);
    zs_write_settings_section(kZSRamBypassSection, section);
}

void zs_set_donated_heap_enabled(BOOL enabled)
{
    atomic_store_explicit(&g_mallocAllocationEnabled, 0, memory_order_release);
    NSMutableDictionary *section = [zs_settings_section(kZSRamBypassSection) mutableCopy] ?: [NSMutableDictionary new];
    section[kZSRamBypassEnabledKey] = @(enabled);
    zs_write_settings_section(kZSRamBypassSection, section);
}

void zs_ram_bypass_get_stats(RamBypassStats *outStats)
{
    if (!outStats)
    {
        return;
    }

    memset(outStats, 0, sizeof(*outStats));

    if (!atomic_load_explicit(&g_poolReady, memory_order_acquire))
    {
        outStats->fallbackAllocations = atomic_load(&g_fallbackCount);
        return;
    }

    os_unfair_lock_lock(&g_pool.lock);
    outStats->active = YES;
    outStats->poolBytes = g_pool.size;
    outStats->usedBytes = g_pool.used;
    os_unfair_lock_unlock(&g_pool.lock);

    outStats->servedAllocations = atomic_load(&g_servedCount);
    outStats->fallbackAllocations = atomic_load(&g_fallbackCount);
}

static _Atomic(uint64_t) g_donatedUsedCache;
static _Atomic(uint8_t) g_donatedUsedRefreshing;

static uint64_t zs_donated_used_cached(void)
{
    if (!atomic_exchange_explicit(&g_donatedUsedRefreshing, 1, memory_order_acq_rel))
    {
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            atomic_store_explicit(&g_donatedUsedCache, [ZSRamDonor.shared donatedBytes], memory_order_release);
            atomic_store_explicit(&g_donatedUsedRefreshing, 0, memory_order_release);
        });
    }

    return atomic_load_explicit(&g_donatedUsedCache, memory_order_acquire);
}

void zs_ram_hud_get_snapshot(RamHudSnapshot *outSnapshot)
{
    if (!outSnapshot)
    {
        return;
    }

    memset(outSnapshot, 0, sizeof(*outSnapshot));

    task_vm_info_data_t info;
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;

    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count) == KERN_SUCCESS)
    {
        outSnapshot->appBytes = info.phys_footprint;
    }

    RamBypassStats stats;
    zs_ram_bypass_get_stats(&stats);

    outSnapshot->donatedBytes = stats.active ? stats.poolBytes : 0;
    outSnapshot->donatedUsedBytes = stats.active ? zs_donated_used_cached() : 0;
    outSnapshot->totalBytes = outSnapshot->appBytes + outSnapshot->donatedUsedBytes;
}

static inline uint64_t zs_round_page(uint64_t value)
{
    const uint64_t mask = (uint64_t)vm_page_size - 1;

    return (value + mask) & ~mask;
}

static inline BOOL zs_pool_contains(const void *address, uint64_t length)
{
    if (!atomic_load_explicit(&g_poolReady, memory_order_acquire))
    {
        return NO;
    }

    const uintptr_t start = (uintptr_t)address;

    return start >= g_pool.base && start + length <= g_pool.base + g_pool.size && start + length >= start;
}

static void zs_pool_log_async(uint64_t used)
{
    const uint64_t served = atomic_load(&g_servedCount);
    const uint64_t fallback = atomic_load(&g_fallbackCount);

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        ZLog(@"[RamBypass] %llu MB of %llu MB in use, %llu allocations served, %llu large allocations fell through",
             used / (1024 * 1024), g_pool.size / (1024 * 1024), served, fallback);
    });
}

static void *zs_pool_take(uint64_t length)
{
    const uint64_t need = zs_round_page(length);
    void *result = NULL;
    BOOL dirty = NO;
    BOOL crossedStride = NO;
    uint64_t usedAfter = 0;

    os_unfair_lock_lock(&g_pool.lock);

    int best = -1;
    uint64_t bestSize = UINT64_MAX;

    for (uint32_t i = 0; i < g_pool.freeCount; i++)
    {
        const uint64_t candidate = g_pool.free[i].size;

        if (candidate >= need && candidate < bestSize)
        {
            best = (int)i;
            bestSize = candidate;

            if (candidate == need)
            {
                break;
            }
        }
    }

    if (best >= 0)
    {
        result = (void *)(g_pool.base + g_pool.free[best].offset);
        dirty = YES;

        if (g_pool.free[best].size == need)
        {
            memmove(&g_pool.free[best], &g_pool.free[best + 1],
                    (g_pool.freeCount - (uint32_t)best - 1) * sizeof(ZSPoolRange));
            g_pool.freeCount--;
        }
        else
        {
            g_pool.free[best].offset += need;
            g_pool.free[best].size -= need;
        }
    }
    else if (g_pool.size - g_pool.cleanOffset >= need)
    {
        result = (void *)(g_pool.base + g_pool.cleanOffset);
        g_pool.cleanOffset += need;
    }

    if (result)
    {
        const uint64_t before = g_pool.used;
        g_pool.used += need;
        usedAfter = g_pool.used;
        crossedStride = (before / kZSDonatedLogStride) != (usedAfter / kZSDonatedLogStride);
    }

    os_unfair_lock_unlock(&g_pool.lock);

    if (!result)
    {
        return NULL;
    }

    if (dirty)
    {
        memset(result, 0, need);
    }

    atomic_fetch_add(&g_servedCount, 1);

    if (crossedStride)
    {
        zs_pool_log_async(usedAfter);
    }

    return result;
}

static void zs_pool_give(void *address, uint64_t length)
{
    const uint64_t size = zs_round_page(length);
    const uint64_t offset = (uintptr_t)address - g_pool.base;

    os_unfair_lock_lock(&g_pool.lock);

    if (offset + size > g_pool.cleanOffset)
    {
        os_unfair_lock_unlock(&g_pool.lock);
        return;
    }

    uint32_t index = 0;

    while (index < g_pool.freeCount && g_pool.free[index].offset < offset)
    {
        index++;
    }

    const BOOL overlapsPrevious = index > 0 &&
        g_pool.free[index - 1].offset + g_pool.free[index - 1].size > offset;
    const BOOL overlapsNext = index < g_pool.freeCount &&
        g_pool.free[index].offset < offset + size;

    if (overlapsPrevious || overlapsNext)
    {
        os_unfair_lock_unlock(&g_pool.lock);
        return;
    }

    const BOOL mergesPrevious = index > 0 &&
        g_pool.free[index - 1].offset + g_pool.free[index - 1].size == offset;
    const BOOL mergesNext = index < g_pool.freeCount &&
        g_pool.free[index].offset == offset + size;

    if (mergesPrevious && mergesNext)
    {
        g_pool.free[index - 1].size += size + g_pool.free[index].size;
        memmove(&g_pool.free[index], &g_pool.free[index + 1],
                (g_pool.freeCount - index - 1) * sizeof(ZSPoolRange));
        g_pool.freeCount--;
    }
    else if (mergesPrevious)
    {
        g_pool.free[index - 1].size += size;
    }
    else if (mergesNext)
    {
        g_pool.free[index].offset = offset;
        g_pool.free[index].size += size;
    }
    else if (g_pool.freeCount < ZS_POOL_MAX_FREE)
    {
        memmove(&g_pool.free[index + 1], &g_pool.free[index],
                (g_pool.freeCount - index) * sizeof(ZSPoolRange));
        g_pool.free[index].offset = offset;
        g_pool.free[index].size = size;
        g_pool.freeCount++;
    }
    else if (!atomic_exchange(&g_freeOverflowLogged, 1))
    {
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            ZLog(@"[RamBypass] free list is full, further fragmented frees are leaked");
        });
    }

    g_pool.used -= MIN(g_pool.used, size);

    os_unfair_lock_unlock(&g_pool.lock);
}

static void zs_pool_install(void *base, uint64_t size)
{
    g_pool.base = (uintptr_t)base;
    g_pool.size = size;
    g_pool.cleanOffset = 0;
    g_pool.used = 0;
    g_pool.freeCount = 0;

    atomic_store_explicit(&g_poolReady, 1, memory_order_release);

    if (atomic_load_explicit(&g_mallocAllocationEnabled, memory_order_acquire))
    {
        zs_malloc_zone_register();
    }

    ZLog(@"[RamBypass] pool ready: %llu MB at %p, serving anonymous mappings of %llu KB or more",
         size / (1024 * 1024), base, kZSDonatedMinAllocation / 1024);
}

static void zs_log_rejected_mmap(size_t length, void *address, int prot, int flags, int fd)
{
    if (atomic_fetch_add(&g_rejectLogged, 1) >= 8)
    {
        return;
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        ZLog(@"[RamBypass] large mmap of %zu KB not eligible: addr=%p prot=0x%x flags=0x%x fd=%d",
             length / 1024, address, prot, flags, fd);
    });
}

static void *zs_hook_mmap(void *address, size_t length, int prot, int flags, int fd, off_t offset)
{
    const BOOL anonymous = (flags & MAP_ANON) != 0 && (fd == -1 || ((uint32_t)fd & 0xff000000u) != 0);

    const BOOL large = length >= kZSDonatedMinAllocation;
    const BOOL eligible = large && anonymous &&
        (flags & MAP_PRIVATE) != 0 && (flags & (MAP_FIXED | MAP_JIT | MAP_SHARED)) == 0 &&
        prot == (PROT_READ | PROT_WRITE);

    atomic_fetch_add(&g_mmapCalls, 1);

    if (large)
    {
        atomic_fetch_add(&g_largeCalls, 1);
    }

    if (large && !eligible)
    {
        atomic_fetch_add(&g_rejectedCalls, 1);

        if (anonymous && prot == PROT_NONE)
        {
            atomic_fetch_add(&g_reserveCalls, 1);
        }
        else if (anonymous)
        {
            zs_log_rejected_mmap(length, address, prot, flags, fd);
        }
    }

    if (eligible)
    {
        if (atomic_load_explicit(&g_poolReady, memory_order_acquire))
        {
            void *served = zs_pool_take(length);

            if (served)
            {
                return served;
            }
        }

        atomic_fetch_add(&g_fallbackCount, 1);
    }

    return g_origMmap(address, length, prot, flags, fd, offset);
}

static int zs_hook_munmap(void *address, size_t length)
{
    if (length != 0 && zs_pool_contains(address, length))
    {
        zs_pool_give(address, length);
        return 0;
    }

    return g_origMunmap(address, length);
}

static void zs_log_rejected_vm(const char *api, uint64_t length, int flags)
{
    if (atomic_fetch_add(&g_rejectLogged, 1) >= 8)
    {
        return;
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        ZLog(@"[RamBypass] large %s of %llu KB not eligible: flags=0x%x", api, length / 1024, flags);
    });
}

static BOOL zs_vm_allocate_common(const char *api, vm_map_t target, uint64_t *address, uint64_t size, int flags)
{
    if (!address || target != mach_task_self() || size < kZSDonatedMinAllocation)
    {
        return NO;
    }

    atomic_fetch_add(&g_vmLargeCalls, 1);

    if ((flags & VM_FLAGS_ANYWHERE) == 0 || (flags & (VM_FLAGS_OVERWRITE | VM_FLAGS_PURGABLE)) != 0)
    {
        zs_log_rejected_vm(api, size, flags);
        return NO;
    }

    if (!atomic_load_explicit(&g_poolReady, memory_order_acquire))
    {
        return NO;
    }

    void *served = zs_pool_take(size);

    if (!served)
    {
        atomic_fetch_add(&g_fallbackCount, 1);
        return NO;
    }

    *address = (uint64_t)(uintptr_t)served;

    return YES;
}

static kern_return_t zs_hook_vm_allocate(vm_map_t target, vm_address_t *address, vm_size_t size, int flags)
{
    uint64_t served = 0;

    if (zs_vm_allocate_common("vm_allocate", target, &served, size, flags))
    {
        *address = (vm_address_t)served;

        return KERN_SUCCESS;
    }

    return g_origVmAllocate(target, address, size, flags);
}

static kern_return_t zs_hook_mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags)
{
    uint64_t served = 0;

    if (zs_vm_allocate_common("mach_vm_allocate", target, &served, size, flags))
    {
        *address = (mach_vm_address_t)served;

        return KERN_SUCCESS;
    }

    return g_origMachVmAllocate(target, address, size, flags);
}

static kern_return_t zs_hook_vm_deallocate(vm_map_t target, vm_address_t address, vm_size_t size)
{
    if (target == mach_task_self() && size != 0 && zs_pool_contains((const void *)address, size))
    {
        zs_pool_give((void *)address, size);

        return KERN_SUCCESS;
    }

    return g_origVmDeallocate(target, address, size);
}

static kern_return_t zs_hook_mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size)
{
    if (target == mach_task_self() && size != 0 && zs_pool_contains((const void *)(uintptr_t)address, size))
    {
        zs_pool_give((void *)(uintptr_t)address, size);

        return KERN_SUCCESS;
    }

    return g_origMachVmDeallocate(target, address, size);
}

static size_t zs_malloc_align_size(size_t value, size_t alignment)
{
    if (value > SIZE_MAX - (alignment - 1))
    {
        return 0;
    }

    return (value + alignment - 1) & ~(alignment - 1);
}

static ZSMallocAllocationHeader *zs_malloc_header_for_pointer(const void *pointer)
{
    if (!pointer || !atomic_load_explicit(&g_poolReady, memory_order_acquire))
    {
        return NULL;
    }

    const uintptr_t value = (uintptr_t)pointer;

    if (value < sizeof(ZSMallocAllocationHeader))
    {
        return NULL;
    }

    ZSMallocAllocationHeader *header = (ZSMallocAllocationHeader *)(value - sizeof(ZSMallocAllocationHeader));

    if (!zs_pool_contains(header, sizeof(*header)) || header->magic != ZS_MALLOC_ALLOCATION_MAGIC)
    {
        return NULL;
    }

    if (header->kind != ZS_MALLOC_KIND_LARGE && header->kind != ZS_MALLOC_KIND_SMALL)
    {
        return NULL;
    }

    if (header->ownerOffset >= g_pool.size)
    {
        return NULL;
    }

    const uintptr_t owner = g_pool.base + header->ownerOffset;
    const uintptr_t headerAddress = (uintptr_t)header;
    const uintptr_t poolEnd = g_pool.base + g_pool.size;

    if (header->requestedSize > header->capacity)
    {
        return NULL;
    }

    if (header->kind == ZS_MALLOC_KIND_SMALL)
    {
        if (header->ownerOffset % vm_page_size != 0 || owner + vm_page_size > poolEnd)
        {
            return NULL;
        }

        ZSMallocSlab *slab = (ZSMallocSlab *)owner;
        const uintptr_t firstBlock = owner + sizeof(*slab);

        if (slab->magic != ZS_MALLOC_SLAB_MAGIC || slab->blockSize < sizeof(*header) ||
            headerAddress < firstBlock || headerAddress + sizeof(*header) > owner + vm_page_size ||
            (headerAddress - firstBlock) % slab->blockSize != 0 ||
            header->allocationSize != slab->blockSize ||
            header->capacity != slab->blockSize - sizeof(*header) ||
            header->classIndex != slab->classIndex)
        {
            return NULL;
        }
    }
    else if (header->ownerOffset % vm_page_size != 0 || header->allocationSize == 0 ||
             header->allocationSize % vm_page_size != 0 || owner + header->allocationSize > poolEnd ||
             headerAddress < owner || headerAddress + sizeof(*header) > owner + header->allocationSize ||
             header->capacity > header->allocationSize || header->classIndex < 16 ||
             (header->classIndex & (header->classIndex - 1)) != 0)
    {
        return NULL;
    }

    return header;
}

static void zs_malloc_update_peak(uint64_t bytes)
{
    uint64_t peak = atomic_load_explicit(&g_mallocPeakBytesInUse, memory_order_relaxed);

    while (bytes > peak && !atomic_compare_exchange_weak_explicit(&g_mallocPeakBytesInUse, &peak, bytes,
                                                                   memory_order_relaxed, memory_order_relaxed))
    {
    }
}

static void zs_malloc_record_allocation(size_t requested)
{
    atomic_fetch_add_explicit(&g_mallocBlocksInUse, 1, memory_order_relaxed);
    const uint64_t used = atomic_fetch_add_explicit(&g_mallocBytesInUse, requested, memory_order_relaxed) + requested;
    zs_malloc_update_peak(used);
}

static void zs_malloc_record_free(size_t requested)
{
    atomic_fetch_sub_explicit(&g_mallocBlocksInUse, 1, memory_order_relaxed);
    atomic_fetch_sub_explicit(&g_mallocBytesInUse, requested, memory_order_relaxed);
}

static void *zs_malloc_zone_allocate(size_t requested, size_t alignment, BOOL zeroed)
{
    if (!atomic_load_explicit(&g_poolReady, memory_order_acquire))
    {
        return NULL;
    }

    const size_t actualSize = MAX(requested, (size_t)1);
    alignment = MAX(alignment, (size_t)16);

    if ((alignment & (alignment - 1)) != 0 || alignment > UINT32_MAX || actualSize > UINT32_MAX ||
        actualSize > SIZE_MAX - sizeof(ZSMallocAllocationHeader) - (alignment - 1) - ((size_t)vm_page_size - 1))
    {
        return NULL;
    }

    const size_t smallLimit = (size_t)vm_page_size / 2;

    if (alignment <= 16 && actualSize <= smallLimit)
    {
        const size_t blockSize = zs_malloc_align_size(actualSize + sizeof(ZSMallocAllocationHeader), 16);
        const size_t classIndex = blockSize / 16;

        if (blockSize == 0 || classIndex >= ZS_MALLOC_SMALL_CLASS_COUNT)
        {
            return NULL;
        }

        os_unfair_lock_lock(&g_mallocZoneLock);

        ZSMallocSlab *slab = g_mallocSlabs[classIndex];

        while (slab && !slab->freeList)
        {
            slab = slab->next;
        }

        if (!slab)
        {
            void *page = zs_pool_take(vm_page_size);

            if (!page)
            {
                os_unfair_lock_unlock(&g_mallocZoneLock);
                return NULL;
            }

            slab = (ZSMallocSlab *)page;
            memset(slab, 0, sizeof(*slab));
            slab->magic = ZS_MALLOC_SLAB_MAGIC;
            slab->classIndex = (uint32_t)classIndex;
            slab->blockSize = (uint32_t)blockSize;
            slab->totalBlocks = (uint32_t)(((size_t)vm_page_size - sizeof(*slab)) / blockSize);
            slab->freeBlocks = slab->totalBlocks;

            if (slab->totalBlocks == 0)
            {
                os_unfair_lock_unlock(&g_mallocZoneLock);
                zs_pool_give(page, vm_page_size);
                return NULL;
            }

            uint8_t *firstBlock = (uint8_t *)page + sizeof(*slab);

            for (uint32_t i = 0; i < slab->totalBlocks; i++)
            {
                uintptr_t block = (uintptr_t)(firstBlock + (size_t)i * blockSize);
                *(uintptr_t *)block = slab->freeList;
                slab->freeList = block;
            }

            slab->next = g_mallocSlabs[classIndex];
            g_mallocSlabs[classIndex] = slab;
            atomic_fetch_add_explicit(&g_mallocBytesAllocated, vm_page_size, memory_order_relaxed);
        }

        uintptr_t block = slab->freeList;
        slab->freeList = *(uintptr_t *)block;
        slab->freeBlocks--;

        ZSMallocAllocationHeader *header = (ZSMallocAllocationHeader *)block;
        header->magic = ZS_MALLOC_ALLOCATION_MAGIC;
        header->requestedSize = (uint32_t)requested;
        header->capacity = (uint32_t)(blockSize - sizeof(*header));
        header->allocationSize = (uint32_t)blockSize;
        header->ownerOffset = (uint32_t)((uintptr_t)slab - g_pool.base);
        header->kind = ZS_MALLOC_KIND_SMALL;
        header->classIndex = (uint32_t)classIndex;

        void *result = (uint8_t *)header + sizeof(*header);
        os_unfair_lock_unlock(&g_mallocZoneLock);

        if (zeroed && requested)
        {
            memset(result, 0, requested);
        }

        zs_malloc_record_allocation(requested);
        return result;
    }

    const size_t totalSize = actualSize + sizeof(ZSMallocAllocationHeader) + alignment - 1;
    void *base = zs_pool_take(totalSize);

    if (!base)
    {
        return NULL;
    }

    const uint64_t mappedSize = zs_round_page(totalSize);
    const uintptr_t firstUserAddress = (uintptr_t)base + sizeof(ZSMallocAllocationHeader);
    const uintptr_t alignedUserAddress = (firstUserAddress + alignment - 1) & ~(uintptr_t)(alignment - 1);
    ZSMallocAllocationHeader *header = (ZSMallocAllocationHeader *)(alignedUserAddress - sizeof(*header));

    header->magic = ZS_MALLOC_ALLOCATION_MAGIC;
    header->requestedSize = (uint32_t)requested;
    header->capacity = (uint32_t)((uintptr_t)base + mappedSize - alignedUserAddress);
    header->allocationSize = (uint32_t)mappedSize;
    header->ownerOffset = (uint32_t)((uintptr_t)base - g_pool.base);
    header->kind = ZS_MALLOC_KIND_LARGE;
    header->classIndex = (uint32_t)alignment;

    void *result = (void *)alignedUserAddress;

    if (zeroed && requested)
    {
        memset(result, 0, requested);
    }

    atomic_fetch_add_explicit(&g_mallocBytesAllocated, mappedSize, memory_order_relaxed);
    zs_malloc_record_allocation(requested);
    return result;
}

static void zs_malloc_zone_free_pointer(void *pointer)
{
    ZSMallocAllocationHeader *header = zs_malloc_header_for_pointer(pointer);

    if (!header)
    {
        return;
    }

    const uint64_t requested = header->requestedSize;
    const uint64_t allocationSize = header->allocationSize;
    const uintptr_t owner = g_pool.base + header->ownerOffset;
    const uint32_t kind = header->kind;
    header->magic = 0;
    zs_malloc_record_free(requested);

    if (kind == ZS_MALLOC_KIND_SMALL)
    {
        ZSMallocSlab *slab = (ZSMallocSlab *)owner;

        if (slab->magic != ZS_MALLOC_SLAB_MAGIC)
        {
            return;
        }

        os_unfair_lock_lock(&g_mallocZoneLock);
        *(uintptr_t *)header = slab->freeList;
        slab->freeList = (uintptr_t)header;
        slab->freeBlocks++;
        os_unfair_lock_unlock(&g_mallocZoneLock);
        return;
    }

    atomic_fetch_sub_explicit(&g_mallocBytesAllocated, allocationSize, memory_order_relaxed);
    zs_pool_give((void *)owner, allocationSize);
}

static void *zs_malloc_zone_reallocate(void *pointer, size_t requested)
{
    if (!pointer)
    {
        return zs_malloc_zone_allocate(requested, 16, NO);
    }

    ZSMallocAllocationHeader *header = zs_malloc_header_for_pointer(pointer);

    if (!header)
    {
        return NULL;
    }

    if (requested == 0)
    {
        zs_malloc_zone_free_pointer(pointer);
        return NULL;
    }

    const uint64_t oldRequested = header->requestedSize;

    if (requested <= header->capacity)
    {
        header->requestedSize = (uint32_t)requested;

        if (requested > oldRequested)
        {
            const uint64_t used = atomic_fetch_add_explicit(&g_mallocBytesInUse, requested - oldRequested, memory_order_relaxed) + requested - oldRequested;
            zs_malloc_update_peak(used);
        }
        else if (requested < oldRequested)
        {
            atomic_fetch_sub_explicit(&g_mallocBytesInUse, oldRequested - requested, memory_order_relaxed);
        }

        return pointer;
    }

    const size_t alignment = header->kind == ZS_MALLOC_KIND_LARGE ? MAX((size_t)header->classIndex, (size_t)16) : 16;
    void *replacement = zs_malloc_zone_allocate(requested, alignment, NO);

    if (!replacement && g_origMalloc)
    {
        replacement = g_origMalloc(requested);
    }

    if (!replacement)
    {
        return NULL;
    }

    memcpy(replacement, pointer, MIN((size_t)oldRequested, requested));
    zs_malloc_zone_free_pointer(pointer);
    return replacement;
}

static size_t zs_malloc_zone_size(malloc_zone_t *zone, const void *pointer)
{
    ZSMallocAllocationHeader *header = zs_malloc_header_for_pointer(pointer);
    return header ? (size_t)header->capacity : 0;
}

static void *zs_malloc_zone_malloc(malloc_zone_t *zone, size_t size)
{
    return zs_malloc_zone_allocate(size, 16, NO);
}

static void *zs_malloc_zone_calloc(malloc_zone_t *zone, size_t count, size_t size)
{
    if (count && size > SIZE_MAX / count)
    {
        errno = ENOMEM;
        return NULL;
    }

    return zs_malloc_zone_allocate(count * size, 16, YES);
}

static void *zs_malloc_zone_valloc(malloc_zone_t *zone, size_t size)
{
    return zs_malloc_zone_allocate(size, vm_page_size, NO);
}

static void zs_malloc_zone_free(malloc_zone_t *zone, void *pointer)
{
    zs_malloc_zone_free_pointer(pointer);
}

static void *zs_malloc_zone_realloc(malloc_zone_t *zone, void *pointer, size_t size)
{
    return zs_malloc_zone_reallocate(pointer, size);
}

static void zs_malloc_zone_destroy(malloc_zone_t *zone)
{
}

static unsigned zs_malloc_zone_batch_malloc(malloc_zone_t *zone, size_t size, void **results, unsigned count)
{
    unsigned allocated = 0;

    while (allocated < count)
    {
        void *pointer = zs_malloc_zone_allocate(size, 16, NO);

        if (!pointer)
        {
            break;
        }

        results[allocated++] = pointer;
    }

    return allocated;
}

static void zs_malloc_zone_batch_free(malloc_zone_t *zone, void **pointers, unsigned count)
{
    for (unsigned i = 0; i < count; i++)
    {
        zs_malloc_zone_free_pointer(pointers[i]);
    }
}

static void *zs_malloc_zone_memalign(malloc_zone_t *zone, size_t alignment, size_t size)
{
    if (alignment < sizeof(void *) || (alignment & (alignment - 1)) != 0)
    {
        return NULL;
    }

    return zs_malloc_zone_allocate(size, alignment, NO);
}

static void zs_malloc_zone_free_definite_size(malloc_zone_t *zone, void *pointer, size_t size)
{
    zs_malloc_zone_free_pointer(pointer);
}

static size_t zs_malloc_zone_pressure_relief(malloc_zone_t *zone, size_t goal)
{
    return 0;
}

static boolean_t zs_malloc_zone_claimed_address(malloc_zone_t *zone, void *pointer)
{
    return zs_malloc_header_for_pointer(pointer) != NULL;
}

static kern_return_t zs_malloc_zone_enumerator(task_t task, void *context, unsigned typeMask,
                                                vm_address_t zoneAddress, memory_reader_t reader,
                                                vm_range_recorder_t recorder)
{
    return KERN_FAILURE;
}

static size_t zs_malloc_zone_good_size(malloc_zone_t *zone, size_t size)
{
    const size_t actualSize = MAX(size, (size_t)1);
    const size_t smallLimit = (size_t)vm_page_size / 2;

    if (actualSize <= smallLimit)
    {
        return zs_malloc_align_size(actualSize + sizeof(ZSMallocAllocationHeader), 16) - sizeof(ZSMallocAllocationHeader);
    }

    if (actualSize > SIZE_MAX - sizeof(ZSMallocAllocationHeader) - ((size_t)vm_page_size - 1))
    {
        return 0;
    }

    return (size_t)zs_round_page(actualSize + sizeof(ZSMallocAllocationHeader)) - sizeof(ZSMallocAllocationHeader);
}

static boolean_t zs_malloc_zone_check(malloc_zone_t *zone)
{
    return atomic_load_explicit(&g_poolReady, memory_order_acquire) != 0;
}

static void zs_malloc_zone_print(malloc_zone_t *zone, boolean_t verbose)
{
}

static void zs_malloc_zone_log(malloc_zone_t *zone, void *address)
{
}

static void zs_malloc_zone_force_lock(malloc_zone_t *zone)
{
    os_unfair_lock_lock(&g_mallocZoneLock);
}

static void zs_malloc_zone_force_unlock(malloc_zone_t *zone)
{
    os_unfair_lock_unlock(&g_mallocZoneLock);
}

static void zs_malloc_zone_statistics(malloc_zone_t *zone, malloc_statistics_t *stats)
{
    if (!stats)
    {
        return;
    }

    memset(stats, 0, sizeof(*stats));
    stats->blocks_in_use = (unsigned)atomic_load_explicit(&g_mallocBlocksInUse, memory_order_relaxed);
    stats->size_in_use = atomic_load_explicit(&g_mallocBytesInUse, memory_order_relaxed);
    stats->max_size_in_use = atomic_load_explicit(&g_mallocPeakBytesInUse, memory_order_relaxed);
    stats->size_allocated = atomic_load_explicit(&g_mallocBytesAllocated, memory_order_relaxed);
}

static boolean_t zs_malloc_zone_locked(malloc_zone_t *zone)
{
    return false;
}

static void zs_malloc_zone_reinit_lock(malloc_zone_t *zone)
{
    g_mallocZoneLock = OS_UNFAIR_LOCK_INIT;
}

static void zs_malloc_zone_register(void)
{
    uint8_t expected = 0;

    if (!atomic_compare_exchange_strong_explicit(&g_mallocZoneRegistered, &expected, 1,
                                                  memory_order_acq_rel, memory_order_acquire))
    {
        return;
    }

    memset(&g_mallocZone, 0, sizeof(g_mallocZone));
    memset(&g_mallocIntrospection, 0, sizeof(g_mallocIntrospection));

    g_mallocIntrospection.enumerator = zs_malloc_zone_enumerator;
    g_mallocIntrospection.good_size = zs_malloc_zone_good_size;
    g_mallocIntrospection.check = zs_malloc_zone_check;
    g_mallocIntrospection.print = zs_malloc_zone_print;
    g_mallocIntrospection.log = zs_malloc_zone_log;
    g_mallocIntrospection.force_lock = zs_malloc_zone_force_lock;
    g_mallocIntrospection.force_unlock = zs_malloc_zone_force_unlock;
    g_mallocIntrospection.statistics = zs_malloc_zone_statistics;
    g_mallocIntrospection.zone_locked = zs_malloc_zone_locked;
    g_mallocIntrospection.reinit_lock = zs_malloc_zone_reinit_lock;

    g_mallocZone.size = zs_malloc_zone_size;
    g_mallocZone.malloc = zs_malloc_zone_malloc;
    g_mallocZone.calloc = zs_malloc_zone_calloc;
    g_mallocZone.valloc = zs_malloc_zone_valloc;
    g_mallocZone.free = zs_malloc_zone_free;
    g_mallocZone.realloc = zs_malloc_zone_realloc;
    g_mallocZone.destroy = zs_malloc_zone_destroy;
    g_mallocZone.zone_name = "ZSingularity Donated Malloc";
    g_mallocZone.batch_malloc = zs_malloc_zone_batch_malloc;
    g_mallocZone.batch_free = zs_malloc_zone_batch_free;
    g_mallocZone.introspect = &g_mallocIntrospection;
    g_mallocZone.version = 10;
    g_mallocZone.memalign = zs_malloc_zone_memalign;
    g_mallocZone.free_definite_size = zs_malloc_zone_free_definite_size;
    g_mallocZone.pressure_relief = zs_malloc_zone_pressure_relief;
    g_mallocZone.claimed_address = zs_malloc_zone_claimed_address;

    malloc_zone_register(&g_mallocZone);
    atomic_store_explicit(&g_mallocZoneRegistered, 2, memory_order_release);
}

static BOOL zs_malloc_redirect_enabled(void)
{
    return atomic_load_explicit(&g_mallocAllocationEnabled, memory_order_acquire) != 0 &&
           atomic_load_explicit(&g_poolReady, memory_order_acquire) != 0 &&
           atomic_load_explicit(&g_mallocZoneRegistered, memory_order_acquire) == 2;
}

static void *zs_hook_malloc(size_t size)
{
    if (zs_malloc_redirect_enabled())
    {
        void *pointer = zs_malloc_zone_allocate(size, 16, NO);

        if (pointer)
        {
            return pointer;
        }
    }

    return g_origMalloc(size);
}

static void *zs_hook_calloc(size_t count, size_t size)
{
    if (zs_malloc_redirect_enabled())
    {
        if (count && size > SIZE_MAX / count)
        {
            return g_origCalloc(count, size);
        }

        void *pointer = zs_malloc_zone_allocate(count * size, 16, YES);

        if (pointer)
        {
            return pointer;
        }
    }

    return g_origCalloc(count, size);
}

static void zs_hook_free(void *pointer)
{
    if (zs_malloc_header_for_pointer(pointer))
    {
        zs_malloc_zone_free_pointer(pointer);
        return;
    }

    g_origFree(pointer);
}

static void *zs_hook_realloc(void *pointer, size_t size)
{
    if (!pointer)
    {
        return zs_hook_malloc(size);
    }

    if (zs_malloc_header_for_pointer(pointer))
    {
        return zs_malloc_zone_reallocate(pointer, size);
    }

    return g_origRealloc(pointer, size);
}

static size_t zs_hook_malloc_size(const void *pointer)
{
    ZSMallocAllocationHeader *header = zs_malloc_header_for_pointer(pointer);
    return header ? (size_t)header->capacity : g_origMallocSize(pointer);
}

static void *zs_hook_valloc(size_t size)
{
    if (zs_malloc_redirect_enabled())
    {
        void *pointer = zs_malloc_zone_allocate(size, vm_page_size, NO);

        if (pointer)
        {
            return pointer;
        }
    }

    return g_origValloc(size);
}

static int zs_hook_posix_memalign(void **pointer, size_t alignment, size_t size)
{
    if (!pointer)
    {
        return EINVAL;
    }

    if (zs_malloc_redirect_enabled() && alignment >= sizeof(void *) &&
        (alignment & (alignment - 1)) == 0)
    {
        void *allocated = zs_malloc_zone_allocate(size, alignment, NO);

        if (allocated)
        {
            *pointer = allocated;
            return 0;
        }
    }

    return g_origPosixMemalign(pointer, alignment, size);
}

static void *zs_hook_aligned_alloc(size_t alignment, size_t size)
{
    if (zs_malloc_redirect_enabled() && alignment >= sizeof(void *) &&
        (alignment & (alignment - 1)) == 0 && size % alignment == 0)
    {
        void *pointer = zs_malloc_zone_allocate(size, alignment, NO);

        if (pointer)
        {
            return pointer;
        }
    }

    return g_origAlignedAlloc(alignment, size);
}

static void *zs_hook_memalign(size_t alignment, size_t size)
{
    if (zs_malloc_redirect_enabled() && alignment >= sizeof(void *) &&
        (alignment & (alignment - 1)) == 0)
    {
        void *pointer = zs_malloc_zone_allocate(size, alignment, NO);

        if (pointer)
        {
            return pointer;
        }
    }

    return g_origMemalign(alignment, size);
}

static void *zs_hook_malloc_type_malloc(size_t size, uintptr_t typeID)
{
    if (zs_malloc_redirect_enabled())
    {
        void *pointer = zs_malloc_zone_allocate(size, 16, NO);

        if (pointer)
        {
            return pointer;
        }
    }

    return g_origMallocTypeMalloc ? g_origMallocTypeMalloc(size, typeID) : g_origMalloc(size);
}

static void *zs_hook_malloc_type_calloc(size_t count, size_t size, uintptr_t typeID)
{
    if (zs_malloc_redirect_enabled())
    {
        if (!count || size <= SIZE_MAX / count)
        {
            void *pointer = zs_malloc_zone_allocate(count * size, 16, YES);

            if (pointer)
            {
                return pointer;
            }
        }
    }

    return g_origMallocTypeCalloc ? g_origMallocTypeCalloc(count, size, typeID) : g_origCalloc(count, size);
}

static void *zs_hook_malloc_type_realloc(void *pointer, size_t size, uintptr_t typeID)
{
    if (!pointer)
    {
        return zs_hook_malloc_type_malloc(size, typeID);
    }

    if (zs_malloc_header_for_pointer(pointer))
    {
        return zs_malloc_zone_reallocate(pointer, size);
    }

    return g_origMallocTypeRealloc ? g_origMallocTypeRealloc(pointer, size, typeID) : g_origRealloc(pointer, size);
}

static void *zs_hook_malloc_type_memalign(size_t alignment, size_t size, uintptr_t typeID)
{
    if (zs_malloc_redirect_enabled() && alignment >= sizeof(void *) &&
        (alignment & (alignment - 1)) == 0)
    {
        void *pointer = zs_malloc_zone_allocate(size, alignment, NO);

        if (pointer)
        {
            return pointer;
        }
    }

    return g_origMallocTypeMemalign ? g_origMallocTypeMemalign(alignment, size, typeID) : g_origMemalign(alignment, size);
}

static void zs_rebind_section(const struct section_64 *section, intptr_t slide,
                              const struct nlist_64 *symbols, const char *strings,
                              const uint32_t *indirect)
{
    const uint32_t *indices = indirect + section->reserved1;
    void **slots = (void **)(section->addr + slide);
    const size_t count = section->size / sizeof(void *);
    const BOOL isConst = strcmp(section->segname, "__DATA_CONST") == 0;

    BOOL unlocked = NO;
    const uintptr_t pageMask = (uintptr_t)vm_page_size - 1;
    const uintptr_t regionStart = (uintptr_t)slots & ~pageMask;
    const uintptr_t regionEnd = ((uintptr_t)slots + section->size + pageMask) & ~pageMask;

    for (size_t i = 0; i < count; i++)
    {
        const uint32_t index = indices[i];

        if (index == INDIRECT_SYMBOL_ABS || index == INDIRECT_SYMBOL_LOCAL ||
            index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS))
        {
            continue;
        }

        const char *name = strings + symbols[index].n_un.n_strx;

        if (name[0] != '_')
        {
            continue;
        }

        void *replacement = NULL;

        if (strcmp(name + 1, "mmap") == 0)
        {
            replacement = (void *)zs_hook_mmap;
        }
        else if (strcmp(name + 1, "munmap") == 0)
        {
            replacement = (void *)zs_hook_munmap;
        }
        else if (strcmp(name + 1, "malloc_type_malloc") == 0 && g_origMallocTypeMalloc)
        {
            replacement = (void *)zs_hook_malloc_type_malloc;
        }
        else if (strcmp(name + 1, "malloc_type_calloc") == 0 && g_origMallocTypeCalloc)
        {
            replacement = (void *)zs_hook_malloc_type_calloc;
        }
        else if (strcmp(name + 1, "malloc_type_realloc") == 0 && g_origMallocTypeRealloc)
        {
            replacement = (void *)zs_hook_malloc_type_realloc;
        }
        else if (strcmp(name + 1, "malloc_type_memalign") == 0 && g_origMallocTypeMemalign)
        {
            replacement = (void *)zs_hook_malloc_type_memalign;
        }
        else if (strcmp(name + 1, "malloc") == 0 && g_origMalloc)
        {
            replacement = (void *)zs_hook_malloc;
        }
        else if (strcmp(name + 1, "calloc") == 0 && g_origCalloc)
        {
            replacement = (void *)zs_hook_calloc;
        }
        else if (strcmp(name + 1, "free") == 0 && g_origFree)
        {
            replacement = (void *)zs_hook_free;
        }
        else if (strcmp(name + 1, "realloc") == 0 && g_origRealloc)
        {
            replacement = (void *)zs_hook_realloc;
        }
        else if (strcmp(name + 1, "malloc_size") == 0 && g_origMallocSize)
        {
            replacement = (void *)zs_hook_malloc_size;
        }
        else if (strcmp(name + 1, "valloc") == 0 && g_origValloc)
        {
            replacement = (void *)zs_hook_valloc;
        }
        else if (strcmp(name + 1, "posix_memalign") == 0 && g_origPosixMemalign)
        {
            replacement = (void *)zs_hook_posix_memalign;
        }
        else if (strcmp(name + 1, "aligned_alloc") == 0 && g_origAlignedAlloc)
        {
            replacement = (void *)zs_hook_aligned_alloc;
        }
        else if (strcmp(name + 1, "memalign") == 0 && g_origMemalign)
        {
            replacement = (void *)zs_hook_memalign;
        }
        else if (strcmp(name + 1, "vm_allocate") == 0)
        {
            replacement = (void *)zs_hook_vm_allocate;
        }
        else if (strcmp(name + 1, "mach_vm_allocate") == 0)
        {
            replacement = (void *)zs_hook_mach_vm_allocate;
        }
        else if (strcmp(name + 1, "vm_deallocate") == 0)
        {
            replacement = (void *)zs_hook_vm_deallocate;
        }
        else if (strcmp(name + 1, "mach_vm_deallocate") == 0)
        {
            replacement = (void *)zs_hook_mach_vm_deallocate;
        }
        else
        {
            continue;
        }

        if (slots[i] == replacement)
        {
            continue;
        }

        if (isConst && !unlocked)
        {
            if (vm_protect(mach_task_self(), regionStart, regionEnd - regionStart, FALSE,
                           VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS)
            {
                return;
            }

            unlocked = YES;
        }

        slots[i] = replacement;
    }

    if (unlocked)
    {
        vm_protect(mach_task_self(), regionStart, regionEnd - regionStart, FALSE, VM_PROT_READ);
    }
}

static void zs_rebind_image(const struct mach_header_64 *header, intptr_t slide)
{
    if (header->magic != MH_MAGIC_64)
    {
        return;
    }

    const struct symtab_command *symtab = NULL;
    const struct dysymtab_command *dysymtab = NULL;
    const struct segment_command_64 *linkedit = NULL;
    const struct segment_command_64 *segments[4];
    int segmentCount = 0;

    const uint8_t *cursor = (const uint8_t *)(header + 1);

    for (uint32_t i = 0; i < header->ncmds; i++)
    {
        const struct load_command *command = (const struct load_command *)cursor;

        if (command->cmd == LC_SEGMENT_64)
        {
            const struct segment_command_64 *segment = (const struct segment_command_64 *)command;

            if (strcmp(segment->segname, SEG_LINKEDIT) == 0)
            {
                linkedit = segment;
            }
            else if ((strcmp(segment->segname, SEG_DATA) == 0 ||
                      strcmp(segment->segname, "__DATA_CONST") == 0) && segmentCount < 4)
            {
                segments[segmentCount++] = segment;
            }
        }
        else if (command->cmd == LC_SYMTAB)
        {
            symtab = (const struct symtab_command *)command;
        }
        else if (command->cmd == LC_DYSYMTAB)
        {
            dysymtab = (const struct dysymtab_command *)command;
        }

        cursor += command->cmdsize;
    }

    if (!symtab || !dysymtab || !linkedit || dysymtab->nindirectsyms == 0)
    {
        return;
    }

    const uintptr_t linkeditBase = (uintptr_t)slide + linkedit->vmaddr - linkedit->fileoff;
    const struct nlist_64 *symbols = (const struct nlist_64 *)(linkeditBase + symtab->symoff);
    const char *strings = (const char *)(linkeditBase + symtab->stroff);
    const uint32_t *indirect = (const uint32_t *)(linkeditBase + dysymtab->indirectsymoff);

    for (int s = 0; s < segmentCount; s++)
    {
        const struct section_64 *sections =
            (const struct section_64 *)((uintptr_t)segments[s] + sizeof(struct segment_command_64));

        for (uint32_t j = 0; j < segments[s]->nsects; j++)
        {
            const uint32_t type = sections[j].flags & SECTION_TYPE;

            if (type == S_LAZY_SYMBOL_POINTERS || type == S_NON_LAZY_SYMBOL_POINTERS)
            {
                zs_rebind_section(&sections[j], slide, symbols, strings, indirect);
            }
        }
    }
}

static void zs_image_added(const struct mach_header *header, intptr_t slide)
{
    Dl_info info;

    if (!dladdr(header, &info) || !info.dli_fname || info.dli_fbase == g_selfBase)
    {
        return;
    }

    if (strncmp(info.dli_fname, "/System/", 8) == 0 || strncmp(info.dli_fname, "/usr/", 5) == 0)
    {
        return;
    }

    char resolved[PATH_MAX];

    if (!realpath(info.dli_fname, resolved) ||
        strncmp(resolved, g_bundlePrefix, g_bundlePrefixLength) != 0)
    {
        return;
    }

    zs_rebind_image((const struct mach_header_64 *)header, slide);
}

static BOOL zs_install_rebinds(void)
{
    static dispatch_once_t once;
    static BOOL installed;

    dispatch_once(&once, ^{
        g_origMmap = dlsym(RTLD_DEFAULT, "mmap");
        g_origMunmap = dlsym(RTLD_DEFAULT, "munmap");
        g_origMalloc = dlsym(RTLD_DEFAULT, "malloc");
        g_origCalloc = dlsym(RTLD_DEFAULT, "calloc");
        g_origRealloc = dlsym(RTLD_DEFAULT, "realloc");
        g_origFree = dlsym(RTLD_DEFAULT, "free");
        g_origMallocSize = dlsym(RTLD_DEFAULT, "malloc_size");
        g_origValloc = dlsym(RTLD_DEFAULT, "valloc");
        g_origPosixMemalign = dlsym(RTLD_DEFAULT, "posix_memalign");
        g_origAlignedAlloc = dlsym(RTLD_DEFAULT, "aligned_alloc");
        g_origMemalign = dlsym(RTLD_DEFAULT, "memalign");
        g_origMallocTypeMalloc = dlsym(RTLD_DEFAULT, "malloc_type_malloc");
        g_origMallocTypeCalloc = dlsym(RTLD_DEFAULT, "malloc_type_calloc");
        g_origMallocTypeRealloc = dlsym(RTLD_DEFAULT, "malloc_type_realloc");
        g_origMallocTypeMemalign = dlsym(RTLD_DEFAULT, "malloc_type_memalign");
        g_origVmAllocate = dlsym(RTLD_DEFAULT, "vm_allocate");
        g_origMachVmAllocate = dlsym(RTLD_DEFAULT, "mach_vm_allocate");
        g_origVmDeallocate = dlsym(RTLD_DEFAULT, "vm_deallocate");
        g_origMachVmDeallocate = dlsym(RTLD_DEFAULT, "mach_vm_deallocate");

        const char *bundlePath = NSBundle.mainBundle.bundlePath.fileSystemRepresentation;

        if (!g_origMmap || !g_origMunmap || !g_origVmAllocate || !g_origMachVmAllocate ||
            !g_origVmDeallocate || !g_origMachVmDeallocate || !bundlePath || !realpath(bundlePath, g_bundlePrefix))
        {
            ZLog(@"[RamBypass] could not resolve libsystem symbols or the bundle path, hooks not installed");
            return;
        }

        g_bundlePrefixLength = strlen(g_bundlePrefix);

        Dl_info selfInfo;

        if (dladdr((void *)zs_image_added, &selfInfo))
        {
            g_selfBase = selfInfo.dli_fbase;
        }

        _dyld_register_func_for_add_image(zs_image_added);
        installed = YES;
    });

    return installed;
}

static void zs_ram_bypass_start(void)
{
    if (!zs_install_rebinds())
    {
        return;
    }

    for (NSNumber *delay in @[@20, @60, @120])
    {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay.doubleValue * NSEC_PER_SEC)),
                       dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            ZLog(@"[RamBypass] after %@s: hook saw %llu mmap calls (%llu large, %llu not eligible, %llu of those PROT_NONE reservations) and %llu large vm_allocate calls, %llu served, %llu fell through, pool %@",
                 delay,
                 atomic_load(&g_mmapCalls), atomic_load(&g_largeCalls), atomic_load(&g_rejectedCalls),
                 atomic_load(&g_reserveCalls), atomic_load(&g_vmLargeCalls),
                 atomic_load(&g_servedCount), atomic_load(&g_fallbackCount),
                 atomic_load(&g_poolReady) ? @"ready" : @"not ready");
        });
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        if (!ZSRamDonor.donorBundleIdentifier)
        {
            ZLog(@"[RamBypass] the donor extension is not embedded in this build, running without it");
            return;
        }

        ZSRamDonor *donor = ZSRamDonor.shared;
        donor.killDonorsAfterMapping = YES;

        uint64_t granted = 0;
        void *mapped = [donor acquireUpTo:kZSDonatedTargetBytes
                                  minimum:kZSDonatedMinimumBytes
                                   actual:&granted];

        if (!mapped || granted == 0)
        {
            ZLog(@"[RamBypass] could not source donor memory: %@", donor.lastError ?: @"unknown error");
            [donor shutdown];
            return;
        }

        zs_pool_install(mapped, granted);
    });
}

__attribute__((constructor))
static void ZSRamBypassConstructor(void)
{
    if (zs_ram_bypass_enabled())
    {
        atomic_store_explicit(&g_mallocAllocationEnabled, 1, memory_order_release);
        zs_ram_bypass_start();
    }
}
