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
static NSString * const kZSRamRedirectModeKey = @"redirectMode";

#define ZS_MALLOC_ALLOCATION_MAGIC 0x5A534D414C4C4F43ull
#define ZS_MALLOC_SLAB_MAGIC 0x5A53534C41424D47ull
#define ZS_MALLOC_SMALL_CLASS_COUNT 4096
#define ZS_MALLOC_SHARD_COUNT 64
#define ZS_MALLOC_KIND_LARGE 1u
#define ZS_MALLOC_KIND_SMALL 2u
#define ZS_POOL_SIZE_BIN_COUNT 64
#define ZS_POOL_RANGE_NONE UINT32_MAX
#define ZS_MALLOC_MAX_CLASS_BLOCK_SIZE ((ZS_MALLOC_SMALL_CLASS_COUNT - 1u) * 16u)

typedef struct __attribute__((aligned(16))) {
    uint64_t magic;
    uint32_t requestedSize;
    uint32_t capacity;
    uint32_t allocationSize;
    uint32_t ownerOffset;
    uint32_t kind;
    uint32_t classIndex;
} ZSMallocAllocationHeader;

typedef struct __attribute__((aligned(16))) ZSMallocSlab {
    uint64_t magic;
    uint32_t classIndex;
    uint32_t blockSize;
    uint32_t totalBlocks;
    uint32_t freeBlocks;
    uint32_t spanSize;
    uint32_t linked;
    uintptr_t freeList;
    struct ZSMallocSlab *next;
    struct ZSMallocSlab *prev;
} ZSMallocSlab;

#ifndef VM_FLAGS_OVERWRITE
#define VM_FLAGS_OVERWRITE 0x4000
#endif

static const uint64_t kZSDonatedTargetBytes = 3ull * 1024ull * 1024ull * 1024ull;
static const uint64_t kZSDonatedMinimumBytes = 256ull * 1024ull * 1024ull;
static const uint64_t kZSDonatedMinAllocation = 256ull * 1024ull;
static const uint64_t kZSDonatedMinAllocation16KB = 16ull * 1024ull;

#define ZS_POOL_MAX_FREE 8192

typedef struct {
    uint64_t offset;
    uint64_t size;
    uint32_t sizePrev;
    uint32_t sizeNext;
    uint32_t treeLeft;
    uint32_t treeRight;
    uint32_t treeParent;
    uint32_t treeHeight;
    uint8_t inUse;
} ZSPoolRange;

static struct {
    os_unfair_lock lock;
    uintptr_t base;
    uint64_t size;
    uint64_t cleanOffset;
    uint64_t used;
    uint32_t freeCount;
    uint32_t freeNodeHead;
    uint32_t addressRoot;
    uint32_t sizeBins[ZS_POOL_SIZE_BIN_COUNT];
    ZSPoolRange free[ZS_POOL_MAX_FREE];
} g_pool;

static _Atomic(uint8_t) g_poolReady;
static _Atomic(uint8_t) g_mallocAllocationEnabled;
static _Atomic(uint8_t) g_mallocZoneRegistered;
static _Atomic(uint8_t) g_mallocRedirect16KB;
static os_unfair_lock g_mallocShardLocks[ZS_MALLOC_SHARD_COUNT];
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

NSInteger zs_ram_redirect_mode(void)
{
    id stored = zs_settings_section(kZSRamBypassSection)[kZSRamRedirectModeKey];
    NSInteger mode = [stored respondsToSelector:@selector(integerValue)] ? [stored integerValue] : 0;
    return mode == 1 ? 1 : 0;
}

void zs_set_ram_redirect_mode(NSInteger mode)
{
    mode = mode == 1 ? 1 : 0;
    atomic_store_explicit(&g_mallocRedirect16KB, mode == 1, memory_order_release);
    NSMutableDictionary *section = [zs_settings_section(kZSRamBypassSection) mutableCopy] ?: [NSMutableDictionary new];
    section[kZSRamRedirectModeKey] = @(mode);
    zs_write_settings_section(kZSRamBypassSection, section);
}

static uint64_t zs_donated_min_allocation(void)
{
    return atomic_load_explicit(&g_mallocRedirect16KB, memory_order_acquire)
        ? kZSDonatedMinAllocation16KB
        : kZSDonatedMinAllocation;
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

static uint32_t zs_pool_size_bin(uint64_t size)
{
    uint64_t pages = MAX(size / vm_page_size, (uint64_t)1);
    uint32_t bin = 0;

    while (pages > 1 && bin + 1 < ZS_POOL_SIZE_BIN_COUNT)
    {
        pages >>= 1;
        bin++;
    }

    return bin;
}

static void zs_pool_size_bin_remove(uint32_t index)
{
    ZSPoolRange *range = &g_pool.free[index];
    const uint32_t bin = zs_pool_size_bin(range->size);

    if (range->sizePrev != ZS_POOL_RANGE_NONE)
    {
        g_pool.free[range->sizePrev].sizeNext = range->sizeNext;
    }
    else
    {
        g_pool.sizeBins[bin] = range->sizeNext;
    }

    if (range->sizeNext != ZS_POOL_RANGE_NONE)
    {
        g_pool.free[range->sizeNext].sizePrev = range->sizePrev;
    }

    range->sizePrev = ZS_POOL_RANGE_NONE;
    range->sizeNext = ZS_POOL_RANGE_NONE;
}

static void zs_pool_size_bin_insert(uint32_t index)
{
    ZSPoolRange *range = &g_pool.free[index];
    const uint32_t bin = zs_pool_size_bin(range->size);
    const uint32_t head = g_pool.sizeBins[bin];

    range->sizePrev = ZS_POOL_RANGE_NONE;
    range->sizeNext = head;

    if (head != ZS_POOL_RANGE_NONE)
    {
        g_pool.free[head].sizePrev = index;
    }

    g_pool.sizeBins[bin] = index;
}

static uint32_t zs_pool_tree_height(uint32_t index)
{
    return index == ZS_POOL_RANGE_NONE ? 0 : g_pool.free[index].treeHeight;
}

static void zs_pool_tree_update_height(uint32_t index)
{
    const uint32_t leftHeight = zs_pool_tree_height(g_pool.free[index].treeLeft);
    const uint32_t rightHeight = zs_pool_tree_height(g_pool.free[index].treeRight);
    g_pool.free[index].treeHeight = 1 + MAX(leftHeight, rightHeight);
}

static uint32_t zs_pool_tree_rotate_left(uint32_t index)
{
    ZSPoolRange *node = &g_pool.free[index];
    const uint32_t pivot = node->treeRight;
    ZSPoolRange *pivotNode = &g_pool.free[pivot];
    const uint32_t parent = node->treeParent;
    const uint32_t middle = pivotNode->treeLeft;

    if (parent == ZS_POOL_RANGE_NONE)
    {
        g_pool.addressRoot = pivot;
    }
    else if (g_pool.free[parent].treeLeft == index)
    {
        g_pool.free[parent].treeLeft = pivot;
    }
    else
    {
        g_pool.free[parent].treeRight = pivot;
    }

    pivotNode->treeParent = parent;
    pivotNode->treeLeft = index;
    node->treeParent = pivot;
    node->treeRight = middle;

    if (middle != ZS_POOL_RANGE_NONE)
    {
        g_pool.free[middle].treeParent = index;
    }

    zs_pool_tree_update_height(index);
    zs_pool_tree_update_height(pivot);
    return pivot;
}

static uint32_t zs_pool_tree_rotate_right(uint32_t index)
{
    ZSPoolRange *node = &g_pool.free[index];
    const uint32_t pivot = node->treeLeft;
    ZSPoolRange *pivotNode = &g_pool.free[pivot];
    const uint32_t parent = node->treeParent;
    const uint32_t middle = pivotNode->treeRight;

    if (parent == ZS_POOL_RANGE_NONE)
    {
        g_pool.addressRoot = pivot;
    }
    else if (g_pool.free[parent].treeLeft == index)
    {
        g_pool.free[parent].treeLeft = pivot;
    }
    else
    {
        g_pool.free[parent].treeRight = pivot;
    }

    pivotNode->treeParent = parent;
    pivotNode->treeRight = index;
    node->treeParent = pivot;
    node->treeLeft = middle;

    if (middle != ZS_POOL_RANGE_NONE)
    {
        g_pool.free[middle].treeParent = index;
    }

    zs_pool_tree_update_height(index);
    zs_pool_tree_update_height(pivot);
    return pivot;
}

static void zs_pool_tree_rebalance(uint32_t index)
{
    while (index != ZS_POOL_RANGE_NONE)
    {
        zs_pool_tree_update_height(index);
        const int balance = (int)zs_pool_tree_height(g_pool.free[index].treeLeft) -
                            (int)zs_pool_tree_height(g_pool.free[index].treeRight);

        if (balance > 1)
        {
            const uint32_t left = g_pool.free[index].treeLeft;
            if (zs_pool_tree_height(g_pool.free[left].treeLeft) < zs_pool_tree_height(g_pool.free[left].treeRight))
            {
                zs_pool_tree_rotate_left(left);
            }

            const uint32_t root = zs_pool_tree_rotate_right(index);
            index = g_pool.free[root].treeParent;
        }
        else if (balance < -1)
        {
            const uint32_t right = g_pool.free[index].treeRight;
            if (zs_pool_tree_height(g_pool.free[right].treeRight) < zs_pool_tree_height(g_pool.free[right].treeLeft))
            {
                zs_pool_tree_rotate_right(right);
            }

            const uint32_t root = zs_pool_tree_rotate_left(index);
            index = g_pool.free[root].treeParent;
        }
        else
        {
            index = g_pool.free[index].treeParent;
        }
    }
}

static void zs_pool_address_insert(uint32_t index)
{
    ZSPoolRange *range = &g_pool.free[index];
    range->treeLeft = ZS_POOL_RANGE_NONE;
    range->treeRight = ZS_POOL_RANGE_NONE;
    range->treeParent = ZS_POOL_RANGE_NONE;
    range->treeHeight = 1;

    if (g_pool.addressRoot == ZS_POOL_RANGE_NONE)
    {
        g_pool.addressRoot = index;
        return;
    }

    uint32_t cursor = g_pool.addressRoot;
    uint32_t parent = ZS_POOL_RANGE_NONE;

    while (cursor != ZS_POOL_RANGE_NONE)
    {
        parent = cursor;
        cursor = range->offset < g_pool.free[cursor].offset
            ? g_pool.free[cursor].treeLeft
            : g_pool.free[cursor].treeRight;
    }

    range->treeParent = parent;
    if (range->offset < g_pool.free[parent].offset)
    {
        g_pool.free[parent].treeLeft = index;
    }
    else
    {
        g_pool.free[parent].treeRight = index;
    }

    zs_pool_tree_rebalance(parent);
}

static void zs_pool_address_neighbors(uint64_t offset, uint32_t *previous, uint32_t *next)
{
    uint32_t cursor = g_pool.addressRoot;
    *previous = ZS_POOL_RANGE_NONE;
    *next = ZS_POOL_RANGE_NONE;

    while (cursor != ZS_POOL_RANGE_NONE)
    {
        if (g_pool.free[cursor].offset < offset)
        {
            *previous = cursor;
            cursor = g_pool.free[cursor].treeRight;
        }
        else
        {
            *next = cursor;
            cursor = g_pool.free[cursor].treeLeft;
        }
    }
}

static uint32_t zs_pool_tree_minimum(uint32_t index)
{
    while (g_pool.free[index].treeLeft != ZS_POOL_RANGE_NONE)
    {
        index = g_pool.free[index].treeLeft;
    }

    return index;
}

static void zs_pool_tree_transplant(uint32_t oldIndex, uint32_t newIndex)
{
    const uint32_t parent = g_pool.free[oldIndex].treeParent;

    if (parent == ZS_POOL_RANGE_NONE)
    {
        g_pool.addressRoot = newIndex;
    }
    else if (g_pool.free[parent].treeLeft == oldIndex)
    {
        g_pool.free[parent].treeLeft = newIndex;
    }
    else
    {
        g_pool.free[parent].treeRight = newIndex;
    }

    if (newIndex != ZS_POOL_RANGE_NONE)
    {
        g_pool.free[newIndex].treeParent = parent;
    }
}

static void zs_pool_address_remove(uint32_t index)
{
    ZSPoolRange *range = &g_pool.free[index];
    uint32_t rebalanceFrom;

    if (range->treeLeft == ZS_POOL_RANGE_NONE)
    {
        rebalanceFrom = range->treeParent;
        zs_pool_tree_transplant(index, range->treeRight);
    }
    else if (range->treeRight == ZS_POOL_RANGE_NONE)
    {
        rebalanceFrom = range->treeParent;
        zs_pool_tree_transplant(index, range->treeLeft);
    }
    else
    {
        const uint32_t successor = zs_pool_tree_minimum(range->treeRight);

        if (g_pool.free[successor].treeParent != index)
        {
            rebalanceFrom = g_pool.free[successor].treeParent;
            zs_pool_tree_transplant(successor, g_pool.free[successor].treeRight);
            g_pool.free[successor].treeRight = range->treeRight;
            g_pool.free[range->treeRight].treeParent = successor;
        }
        else
        {
            rebalanceFrom = successor;
        }

        zs_pool_tree_transplant(index, successor);
        g_pool.free[successor].treeLeft = range->treeLeft;
        g_pool.free[range->treeLeft].treeParent = successor;
    }

    range->treeLeft = ZS_POOL_RANGE_NONE;
    range->treeRight = ZS_POOL_RANGE_NONE;
    range->treeParent = ZS_POOL_RANGE_NONE;
    range->treeHeight = 0;

    if (rebalanceFrom != ZS_POOL_RANGE_NONE)
    {
        zs_pool_tree_rebalance(rebalanceFrom);
    }
}

static uint32_t zs_pool_range_acquire(void)
{
    const uint32_t index = g_pool.freeNodeHead;

    if (index == ZS_POOL_RANGE_NONE)
    {
        return ZS_POOL_RANGE_NONE;
    }

    g_pool.freeNodeHead = g_pool.free[index].sizeNext;
    g_pool.free[index].inUse = 1;
    g_pool.free[index].sizePrev = ZS_POOL_RANGE_NONE;
    g_pool.free[index].sizeNext = ZS_POOL_RANGE_NONE;
    g_pool.free[index].treeLeft = ZS_POOL_RANGE_NONE;
    g_pool.free[index].treeRight = ZS_POOL_RANGE_NONE;
    g_pool.free[index].treeParent = ZS_POOL_RANGE_NONE;
    g_pool.free[index].treeHeight = 0;
    return index;
}

static void zs_pool_range_release(uint32_t index)
{
    ZSPoolRange *range = &g_pool.free[index];
    range->inUse = 0;
    range->sizePrev = ZS_POOL_RANGE_NONE;
    range->sizeNext = g_pool.freeNodeHead;
    range->treeLeft = ZS_POOL_RANGE_NONE;
    range->treeRight = ZS_POOL_RANGE_NONE;
    range->treeParent = ZS_POOL_RANGE_NONE;
    range->treeHeight = 0;
    g_pool.freeNodeHead = index;
}

static void *zs_pool_take(uint64_t length)
{
    if (length == 0 || length > UINT64_MAX - ((uint64_t)vm_page_size - 1))
    {
        return NULL;
    }

    const uint64_t need = zs_round_page(length);
    void *result = NULL;

    os_unfair_lock_lock(&g_pool.lock);

    const uint32_t firstBin = zs_pool_size_bin(need);
    uint32_t selected = ZS_POOL_RANGE_NONE;

    for (uint32_t bin = firstBin; bin < ZS_POOL_SIZE_BIN_COUNT && selected == ZS_POOL_RANGE_NONE; bin++)
    {
        if (bin == firstBin)
        {
            for (uint32_t index = g_pool.sizeBins[bin]; index != ZS_POOL_RANGE_NONE; index = g_pool.free[index].sizeNext)
            {
                if (g_pool.free[index].size >= need)
                {
                    selected = index;
                    break;
                }
            }
        }
        else if (g_pool.sizeBins[bin] != ZS_POOL_RANGE_NONE)
        {
            selected = g_pool.sizeBins[bin];
        }
    }

    if (selected != ZS_POOL_RANGE_NONE)
    {
        ZSPoolRange *range = &g_pool.free[selected];
        result = (void *)(g_pool.base + range->offset);
        zs_pool_size_bin_remove(selected);

        if (range->size == need)
        {
            zs_pool_address_remove(selected);
            zs_pool_range_release(selected);
            g_pool.freeCount--;
        }
        else
        {
            zs_pool_address_remove(selected);
            range->offset += need;
            range->size -= need;
            zs_pool_address_insert(selected);
            zs_pool_size_bin_insert(selected);
        }
    }
    else if (g_pool.size - g_pool.cleanOffset >= need)
    {
        result = (void *)(g_pool.base + g_pool.cleanOffset);
        g_pool.cleanOffset += need;
    }

    if (result)
    {
        g_pool.used += need;
    }

    os_unfair_lock_unlock(&g_pool.lock);

    if (!result)
    {
        return NULL;
    }

    atomic_fetch_add(&g_servedCount, 1);

    return result;
}

static void zs_pool_give(void *address, uint64_t length)
{
    const uint64_t size = zs_round_page(length);
    const uintptr_t pointer = (uintptr_t)address;

    if (pointer < g_pool.base || size > g_pool.size || pointer - g_pool.base > g_pool.size - size)
    {
        return;
    }

    const uint64_t offset = pointer - g_pool.base;
    os_unfair_lock_lock(&g_pool.lock);

    if (offset + size > g_pool.cleanOffset)
    {
        os_unfair_lock_unlock(&g_pool.lock);
        return;
    }

    uint32_t previous = ZS_POOL_RANGE_NONE;
    uint32_t next = ZS_POOL_RANGE_NONE;
    zs_pool_address_neighbors(offset, &previous, &next);

    const BOOL overlapsPrevious = previous != ZS_POOL_RANGE_NONE &&
        g_pool.free[previous].offset + g_pool.free[previous].size > offset;
    const BOOL overlapsNext = next != ZS_POOL_RANGE_NONE &&
        g_pool.free[next].offset < offset + size;

    if (overlapsPrevious || overlapsNext)
    {
        os_unfair_lock_unlock(&g_pool.lock);
        return;
    }

    const BOOL mergesPrevious = previous != ZS_POOL_RANGE_NONE &&
        g_pool.free[previous].offset + g_pool.free[previous].size == offset;
    const BOOL mergesNext = next != ZS_POOL_RANGE_NONE &&
        g_pool.free[next].offset == offset + size;

    if (mergesPrevious && mergesNext)
    {
        zs_pool_size_bin_remove(previous);
        zs_pool_size_bin_remove(next);
        const uint64_t nextSize = g_pool.free[next].size;
        zs_pool_address_remove(next);
        g_pool.free[previous].size += size + nextSize;
        zs_pool_range_release(next);
        g_pool.freeCount--;
        zs_pool_size_bin_insert(previous);
    }
    else if (mergesPrevious)
    {
        zs_pool_size_bin_remove(previous);
        g_pool.free[previous].size += size;
        zs_pool_size_bin_insert(previous);
    }
    else if (mergesNext)
    {
        zs_pool_size_bin_remove(next);
        zs_pool_address_remove(next);
        g_pool.free[next].offset = offset;
        g_pool.free[next].size += size;
        zs_pool_address_insert(next);
        zs_pool_size_bin_insert(next);
    }
    else
    {
        uint32_t index = zs_pool_range_acquire();

        if (index == ZS_POOL_RANGE_NONE)
        {
            os_unfair_lock_unlock(&g_pool.lock);
            if (!atomic_exchange(&g_freeOverflowLogged, 1))
            {
                dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                    ZLog(@"[RamBypass] free range metadata is exhausted, further fragmented frees are leaked");
                });
            }
            return;
        }

        ZSPoolRange *range = &g_pool.free[index];
        range->offset = offset;
        range->size = size;
        zs_pool_address_insert(index);
        zs_pool_size_bin_insert(index);
        g_pool.freeCount++;
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
    g_pool.addressRoot = ZS_POOL_RANGE_NONE;
    g_pool.freeNodeHead = 0;

    for (uint32_t i = 0; i < ZS_POOL_SIZE_BIN_COUNT; i++)
    {
        g_pool.sizeBins[i] = ZS_POOL_RANGE_NONE;
    }

    for (uint32_t i = 0; i < ZS_POOL_MAX_FREE; i++)
    {
        ZSPoolRange *range = &g_pool.free[i];
        range->inUse = 0;
        range->sizePrev = ZS_POOL_RANGE_NONE;
        range->sizeNext = i + 1 < ZS_POOL_MAX_FREE ? i + 1 : ZS_POOL_RANGE_NONE;
        range->treeLeft = ZS_POOL_RANGE_NONE;
        range->treeRight = ZS_POOL_RANGE_NONE;
        range->treeParent = ZS_POOL_RANGE_NONE;
        range->treeHeight = 0;
    }

    atomic_store_explicit(&g_poolReady, 1, memory_order_release);

    if (atomic_load_explicit(&g_mallocAllocationEnabled, memory_order_acquire))
    {
        zs_malloc_zone_register();
    }

    ZLog(@"[RamBypass] pool ready: %llu MB at %p, serving anonymous mappings of %llu KB or more",
         size / (1024 * 1024), base, zs_donated_min_allocation() / 1024);
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

    const BOOL large = length >= zs_donated_min_allocation();
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
                memset(served, 0, zs_round_page(length));
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
    if (!address || target != mach_task_self() || size < zs_donated_min_allocation())
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

    memset(served, 0, zs_round_page(size));
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
            slab->spanSize < vm_page_size || slab->spanSize % vm_page_size != 0 ||
            owner + slab->spanSize > poolEnd ||
            headerAddress < firstBlock || headerAddress + sizeof(*header) > owner + slab->spanSize ||
            (headerAddress - firstBlock) % slab->blockSize != 0 ||
            (headerAddress - firstBlock) / slab->blockSize >= slab->totalBlocks ||
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

static inline os_unfair_lock *zs_malloc_class_lock(uint32_t classIndex)
{
    return &g_mallocShardLocks[classIndex % ZS_MALLOC_SHARD_COUNT];
}

static void zs_malloc_slab_link(ZSMallocSlab *slab)
{
    if (slab->linked)
    {
        return;
    }

    const uint32_t classIndex = slab->classIndex;
    ZSMallocSlab *head = g_mallocSlabs[classIndex];
    slab->prev = NULL;
    slab->next = head;

    if (head)
    {
        head->prev = slab;
    }

    g_mallocSlabs[classIndex] = slab;
    slab->linked = 1;
}

static void zs_malloc_slab_unlink(ZSMallocSlab *slab)
{
    if (!slab->linked)
    {
        return;
    }

    if (slab->prev)
    {
        slab->prev->next = slab->next;
    }
    else
    {
        g_mallocSlabs[slab->classIndex] = slab->next;
    }

    if (slab->next)
    {
        slab->next->prev = slab->prev;
    }

    slab->next = NULL;
    slab->prev = NULL;
    slab->linked = 0;
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

    if (alignment <= 16 && actualSize + sizeof(ZSMallocAllocationHeader) <= ZS_MALLOC_MAX_CLASS_BLOCK_SIZE)
    {
        const size_t blockSize = zs_malloc_align_size(actualSize + sizeof(ZSMallocAllocationHeader), 16);
        const size_t classIndex = blockSize / 16;

        if (blockSize == 0 || classIndex >= ZS_MALLOC_SMALL_CLASS_COUNT)
        {
            return NULL;
        }

        os_unfair_lock *lock = zs_malloc_class_lock((uint32_t)classIndex);
        os_unfair_lock_lock(lock);
        ZSMallocSlab *slab = g_mallocSlabs[classIndex];

        if (!slab)
        {
            size_t spanSize = vm_page_size;
            if (blockSize >= (size_t)vm_page_size / 2)
            {
                const size_t targetSpan = blockSize > SIZE_MAX / 8 ? SIZE_MAX : blockSize * 8;
                spanSize = MAX((size_t)vm_page_size * 4, (size_t)zs_round_page(targetSpan));
            }

            if (spanSize > UINT32_MAX)
            {
                os_unfair_lock_unlock(lock);
                return NULL;
            }

            void *span = zs_pool_take(spanSize);

            if (!span)
            {
                os_unfair_lock_unlock(lock);
                return NULL;
            }

            slab = (ZSMallocSlab *)span;
            slab->magic = ZS_MALLOC_SLAB_MAGIC;
            slab->classIndex = (uint32_t)classIndex;
            slab->blockSize = (uint32_t)blockSize;
            slab->spanSize = (uint32_t)spanSize;
            slab->totalBlocks = (uint32_t)(((size_t)spanSize - sizeof(*slab)) / blockSize);
            slab->freeBlocks = slab->totalBlocks;
            slab->linked = 0;
            slab->freeList = 0;
            slab->next = NULL;
            slab->prev = NULL;

            if (slab->totalBlocks == 0)
            {
                slab->magic = 0;
                os_unfair_lock_unlock(lock);
                zs_pool_give(span, spanSize);
                return NULL;
            }

            uint8_t *firstBlock = (uint8_t *)span + sizeof(*slab);

            for (uint32_t i = 0; i < slab->totalBlocks; i++)
            {
                uintptr_t block = (uintptr_t)(firstBlock + (size_t)i * blockSize);
                *(uintptr_t *)block = slab->freeList;
                slab->freeList = block;
            }

            zs_malloc_slab_link(slab);
            atomic_fetch_add_explicit(&g_mallocBytesAllocated, spanSize, memory_order_relaxed);
        }

        uintptr_t block = slab->freeList;
        slab->freeList = *(uintptr_t *)block;
        slab->freeBlocks--;

        if (!slab->freeList)
        {
            zs_malloc_slab_unlink(slab);
        }

        ZSMallocAllocationHeader *header = (ZSMallocAllocationHeader *)block;
        header->magic = ZS_MALLOC_ALLOCATION_MAGIC;
        header->requestedSize = (uint32_t)requested;
        header->capacity = (uint32_t)(blockSize - sizeof(*header));
        header->allocationSize = (uint32_t)blockSize;
        header->ownerOffset = (uint32_t)((uintptr_t)slab - g_pool.base);
        header->kind = ZS_MALLOC_KIND_SMALL;
        header->classIndex = (uint32_t)classIndex;

        void *result = (uint8_t *)header + sizeof(*header);
        os_unfair_lock_unlock(lock);

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

        os_unfair_lock *lock = zs_malloc_class_lock(slab->classIndex);
        BOOL releaseSpan = NO;
        uint32_t spanSize = slab->spanSize;

        os_unfair_lock_lock(lock);
        *(uintptr_t *)header = slab->freeList;
        slab->freeList = (uintptr_t)header;
        slab->freeBlocks++;

        if (slab->freeBlocks == slab->totalBlocks)
        {
            zs_malloc_slab_unlink(slab);
            slab->magic = 0;
            releaseSpan = YES;
        }
        else
        {
            zs_malloc_slab_link(slab);
        }

        os_unfair_lock_unlock(lock);

        if (releaseSpan)
        {
            atomic_fetch_sub_explicit(&g_mallocBytesAllocated, spanSize, memory_order_relaxed);
            zs_pool_give((void *)owner, spanSize);
        }
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
    if (actualSize <= ZS_MALLOC_MAX_CLASS_BLOCK_SIZE - sizeof(ZSMallocAllocationHeader))
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
    for (uint32_t i = 0; i < ZS_MALLOC_SHARD_COUNT; i++)
    {
        os_unfair_lock_lock(&g_mallocShardLocks[i]);
    }
}

static void zs_malloc_zone_force_unlock(malloc_zone_t *zone)
{
    for (uint32_t i = ZS_MALLOC_SHARD_COUNT; i > 0; i--)
    {
        os_unfair_lock_unlock(&g_mallocShardLocks[i - 1]);
    }
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
    for (uint32_t i = 0; i < ZS_MALLOC_SHARD_COUNT; i++)
    {
        g_mallocShardLocks[i] = OS_UNFAIR_LOCK_INIT;
    }
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
    atomic_store_explicit(&g_mallocRedirect16KB, zs_ram_redirect_mode() == 1, memory_order_release);

    if (zs_ram_bypass_enabled())
    {
        atomic_store_explicit(&g_mallocAllocationEnabled, 1, memory_order_release);
        zs_ram_bypass_start();
    }
}
