#ifndef RamDonor_h
#define RamDonor_h

@import Foundation;

NS_ASSUME_NONNULL_BEGIN

@interface ZSRamDonor : NSObject

@property (class, readonly) ZSRamDonor *shared;
@property (class, readonly, nullable) NSString *donorBundleIdentifier;
@property (readonly) NSUInteger liveDonorCount;
@property (nonatomic) NSUInteger maxDonors;
@property (nonatomic) BOOL killDonorsAfterMapping;
@property (nonatomic, readonly, copy, nullable) NSString *lastError;

- (nullable void *)acquireUpTo:(uint64_t)size
                       minimum:(uint64_t)minimum
                        actual:(uint64_t *_Nullable)actual;
- (void)releaseRegionAt:(void *)base;
- (uint64_t)donatedBytes;
- (void)killDonorProcesses;
- (void)shutdown;

@end

NS_ASSUME_NONNULL_END

#endif
