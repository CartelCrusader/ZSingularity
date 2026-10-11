#ifndef DonatedHeap_h
#define DonatedHeap_h

#import <Foundation/Foundation.h>
#import <stdint.h>

typedef struct {
    BOOL active;
    uint64_t poolBytes;
    uint64_t usedBytes;
    uint64_t servedAllocations;
    uint64_t fallbackAllocations;
} RamBypassStats;

BOOL zs_ram_bypass_enabled(void);
void zs_set_donated_heap_enabled(BOOL enabled);
void zs_ram_bypass_get_stats(RamBypassStats *outStats);

#endif
