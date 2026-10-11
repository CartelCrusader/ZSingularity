#import "DonatedHeap.h"
#import "RamDonor.h"
#import "Engine.h"
#import "ZTweakLog.h"

#import <dlfcn.h>
#import <limits.h>
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

static const uint64_t kZSDonatedTargetBytes = 3ull * 1024ull * 1024ull * 1024ull;
static const uint64_t kZSDonatedMinimumBytes = 256ull * 1024ull * 1024ull;
static const uint64_t kZSDonatedMinAllocation = 2ull * 1024ull * 1024ull;
static const uint64_t kZSDonatedLogStride = 256ull * 1024ull * 1024ull;

#define ZS_POOL_MAX_FREE 2048

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
static _Atomic(uint64_t) g_servedCount;
static _Atomic(uint64_t) g_fallbackCount;
static _Atomic(uint8_t) g_freeOverflowLogged;

static void *(*g_origMmap)(void *, size_t, int, int, int, off_t);
static int (*g_origMunmap)(void *, size_t);

static void *g_selfBase;
static char g_bundlePrefix[PATH_MAX];
static size_t g_bundlePrefixLength;

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
    outSnapshot->donatedUsedBytes = stats.active ? stats.usedBytes : 0;
    outSnapshot->totalBytes = outSnapshot->appBytes + outSnapshot->donatedBytes;
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

    ZLog(@"[RamBypass] pool ready: %llu MB at %p, serving anonymous mappings of %llu MB or more",
         size / (1024 * 1024), base, kZSDonatedMinAllocation / (1024 * 1024));
}

static void *zs_hook_mmap(void *address, size_t length, int prot, int flags, int fd, off_t offset)
{
    const BOOL anonymous = (flags & MAP_ANON) != 0 && (fd == -1 || ((uint32_t)fd & 0xff000000u) != 0);

    if (address == NULL && length >= kZSDonatedMinAllocation && anonymous &&
        (flags & MAP_PRIVATE) != 0 && (flags & (MAP_FIXED | MAP_JIT | MAP_SHARED)) == 0 &&
        prot == (PROT_READ | PROT_WRITE))
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

        const char *bundlePath = NSBundle.mainBundle.bundlePath.fileSystemRepresentation;

        if (!g_origMmap || !g_origMunmap || !bundlePath || !realpath(bundlePath, g_bundlePrefix))
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
        zs_ram_bypass_start();
    }
}
