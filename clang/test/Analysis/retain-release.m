// RUN: rm -f %t.objc.plist %t.objcpp.plist
// RUN: %clang_analyze_cc1 -triple x86_64-apple-darwin10\
// RUN:     -analyzer-checker=core,osx.coreFoundation.CFRetainRelease\
// RUN:     -analyzer-checker=osx.cocoa.ClassRelease,osx.cocoa.RetainCount\
// RUN:     -analyzer-checker=debug.ExprInspection -fblocks -verify %s\
// RUN:     -Wno-objc-root-class -analyzer-output=plist -o %t.objc.plist
// RUN: %clang_analyze_cc1 -triple x86_64-apple-darwin10\
// RUN:     -analyzer-checker=core,osx.coreFoundation.CFRetainRelease\
// RUN:     -analyzer-checker=osx.cocoa.ClassRelease,osx.cocoa.RetainCount\
// RUN:     -analyzer-checker=debug.ExprInspection -fblocks -verify %s\
// RUN:     -Wno-objc-root-class -analyzer-output=plist -o %t.objcpp.plist\
// RUN:     -x objective-c++ -std=gnu++98
// RUN: %clang_analyze_cc1 -triple x86_64-apple-darwin10\
// RUN:     -analyzer-checker=core,osx.coreFoundation.CFRetainRelease\
// RUN:     -analyzer-checker=osx.cocoa.ClassRelease,osx.cocoa.RetainCount\
// RUN:     -analyzer-checker=debug.ExprInspection -fblocks -verify %s\
// RUN:     -Wno-objc-root-class -x objective-c++ -std=gnu++98\
// RUN:     -analyzer-config osx.cocoa.RetainCount:TrackNSCFStartParam=true\
// RUN:     -DTRACK_START_PARAM
// RUN: %normalize_plist <%t.objcpp.plist | diff -ub %S/Inputs/expected-plists/retain-release.m.objcpp.plist -
// RUN: %normalize_plist <%t.objc.plist | diff -ub %S/Inputs/expected-plists/retain-release.m.objc.plist -

void clang_analyzer_eval(int);

#if __has_feature(attribute_ns_returns_retained)
#define NS_RETURNS_RETAINED __attribute__((ns_returns_retained))
#endif
#if __has_feature(attribute_cf_returns_retained)
#define CF_RETURNS_RETAINED __attribute__((cf_returns_retained))
#endif
#if __has_feature(attribute_ns_returns_not_retained)
#define NS_RETURNS_NOT_RETAINED __attribute__((ns_returns_not_retained))
#endif
#if __has_feature(attribute_cf_returns_not_retained)
#define CF_RETURNS_NOT_RETAINED __attribute__((cf_returns_not_retained))
#endif
#if __has_feature(attribute_ns_consumes_self)
#define NS_CONSUMES_SELF __attribute__((ns_consumes_self))
#endif
#if __has_feature(attribute_ns_consumed)
#define NS_CONSUMED __attribute__((ns_consumed))
#endif
#if __has_feature(attribute_cf_consumed)
#define CF_CONSUMED __attribute__((cf_consumed))
#endif
#if __has_attribute(ns_returns_autoreleased)
#define NS_RETURNS_AUTORELEASED __attribute__((ns_returns_autoreleased))
#endif

//===----------------------------------------------------------------------===//
// The following code is reduced using delta-debugging from Mac OS X headers:
//
// #include <Cocoa/Cocoa.h>
// #include <CoreFoundation/CoreFoundation.h>
// #include <DiskArbitration/DiskArbitration.h>
// #include <QuartzCore/QuartzCore.h>
// #include <Quartz/Quartz.h>
// #include <IOKit/IOKitLib.h>
//
// It includes the basic definitions for the test cases below.
//===----------------------------------------------------------------------===//

typedef unsigned int __darwin_natural_t;
typedef unsigned long uintptr_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef unsigned int UInt32;
typedef signed long CFIndex;
typedef CFIndex CFByteOrder;
typedef struct {
    CFIndex location;
    CFIndex length;
} CFRange;
static __inline__ __attribute__((always_inline)) CFRange CFRangeMake(CFIndex loc, CFIndex len) {
    CFRange range;
    range.location = loc;
    range.length = len;
    return range;
}
typedef const void * CFTypeRef;
typedef const struct __CFString * CFStringRef;
typedef const struct __CFAllocator * CFAllocatorRef;
extern const CFAllocatorRef kCFAllocatorDefault;

extern CFTypeRef CFRetain(CFTypeRef cf);
extern void CFRelease(CFTypeRef cf);
extern CFTypeRef CFMakeCollectable(CFTypeRef cf);
extern CFTypeRef CFAutorelease(CFTypeRef CF_CONSUMED cf);

typedef struct {
}
CFArrayCallBacks;
extern const CFArrayCallBacks kCFTypeArrayCallBacks;
typedef const struct __CFArray * CFArrayRef;
typedef struct __CFArray * CFMutableArrayRef;
extern CFMutableArrayRef CFArrayCreateMutable(CFAllocatorRef allocator, CFIndex capacity, const CFArrayCallBacks *callBacks);
extern const void *CFArrayGetValueAtIndex(CFArrayRef theArray, CFIndex idx);
extern void CFArrayAppendValue(CFMutableArrayRef theArray, const void *value);
typedef struct {
}
CFDictionaryKeyCallBacks;
extern const CFDictionaryKeyCallBacks kCFTypeDictionaryKeyCallBacks;
typedef struct {
}
CFDictionaryValueCallBacks;
extern const CFDictionaryValueCallBacks kCFTypeDictionaryValueCallBacks;
typedef const struct __CFDictionary * CFDictionaryRef;
typedef struct __CFDictionary * CFMutableDictionaryRef;
extern CFMutableDictionaryRef CFDictionaryCreateMutable(CFAllocatorRef allocator, CFIndex capacity, const CFDictionaryKeyCallBacks *keyCallBacks, const CFDictionaryValueCallBacks *valueCallBacks);
typedef UInt32 CFStringEncoding;
enum {
kCFStringEncodingMacRoman = 0,     kCFStringEncodingWindowsLatin1 = 0x0500,     kCFStringEncodingISOLatin1 = 0x0201,     kCFStringEncodingNextStepLatin = 0x0B01,     kCFStringEncodingASCII = 0x0600,     kCFStringEncodingUnicode = 0x0100,     kCFStringEncodingUTF8 = 0x08000100,     kCFStringEncodingNonLossyASCII = 0x0BFF      ,     kCFStringEncodingUTF16 = 0x0100,     kCFStringEncodingUTF16BE = 0x10000100,     kCFStringEncodingUTF16LE = 0x14000100,      kCFStringEncodingUTF32 = 0x0c000100,     kCFStringEncodingUTF32BE = 0x18000100,     kCFStringEncodingUTF32LE = 0x1c000100  };
extern CFStringRef CFStringCreateWithCString(CFAllocatorRef alloc, const char *cStr, CFStringEncoding encoding);
typedef double CFTimeInterval;
typedef CFTimeInterval CFAbsoluteTime;
extern CFAbsoluteTime CFAbsoluteTimeGetCurrent(void);
typedef const struct __CFDate * CFDateRef;
extern CFDateRef CFDateCreate(CFAllocatorRef allocator, CFAbsoluteTime at);
extern CFAbsoluteTime CFDateGetAbsoluteTime(CFDateRef theDate);
typedef __darwin_natural_t natural_t;
typedef natural_t mach_port_name_t;
typedef mach_port_name_t mach_port_t;
typedef int kern_return_t;
typedef kern_return_t mach_error_t;
enum {
kCFNumberSInt8Type = 1,     kCFNumberSInt16Type = 2,     kCFNumberSInt32Type = 3,     kCFNumberSInt64Type = 4,     kCFNumberFloat32Type = 5,     kCFNumberFloat64Type = 6,      kCFNumberCharType = 7,     kCFNumberShortType = 8,     kCFNumberIntType = 9,     kCFNumberLongType = 10,     kCFNumberLongLongType = 11,     kCFNumberFloatType = 12,     kCFNumberDoubleType = 13,      kCFNumberCFIndexType = 14,      kCFNumberNSIntegerType = 15,     kCFNumberCGFloatType = 16,     kCFNumberMaxType = 16    };
typedef CFIndex CFNumberType;
typedef const struct __CFNumber * CFNumberRef;
extern CFNumberRef CFNumberCreate(CFAllocatorRef allocator, CFNumberType theType, const void *valuePtr);
typedef const struct __CFAttributedString *CFAttributedStringRef;
typedef struct __CFAttributedString *CFMutableAttributedStringRef;
extern CFAttributedStringRef CFAttributedStringCreate(CFAllocatorRef alloc, CFStringRef str, CFDictionaryRef attributes) ;
extern CFMutableAttributedStringRef CFAttributedStringCreateMutableCopy(CFAllocatorRef alloc, CFIndex maxLength, CFAttributedStringRef aStr) ;
extern void CFAttributedStringSetAttribute(CFMutableAttributedStringRef aStr, CFRange range, CFStringRef attrName, CFTypeRef value) ;
typedef signed char BOOL;
typedef unsigned long NSUInteger;
@class NSString, Protocol;
extern void NSLog(NSString *format, ...) __attribute__((format(__NSString__, 1, 2)));
typedef struct _NSZone NSZone;
@class NSInvocation, NSMethodSignature, NSCoder, NSString, NSEnumerator;
@protocol NSObject
- (BOOL)isEqual:(id)object;
- (id)retain;
- (oneway void)release;
- (id)autorelease;
- (NSString *)description;
- (id)init;
@end
@protocol NSCopying 
- (id)copyWithZone:(NSZone *)zone;
@end
@protocol NSMutableCopying  - (id)mutableCopyWithZone:(NSZone *)zone;
@end
@protocol NSCoding  - (void)encodeWithCoder:(NSCoder *)aCoder;
@end
@interface NSObject <NSObject> {}
+ (id)allocWithZone:(NSZone *)zone;
+ (id)alloc;
+ (id)new;
- (void)dealloc;
@end
@interface NSObject (NSCoderMethods)
- (id)awakeAfterUsingCoder:(NSCoder *)aDecoder;
@end
extern id NSAllocateObject(Class aClass, NSUInteger extraBytes, NSZone *zone);
typedef struct {
}
NSFastEnumerationState;
@protocol NSFastEnumeration 
- (NSUInteger)countByEnumeratingWithState:(NSFastEnumerationState *)state objects:(id *)stackbuf count:(NSUInteger)len;
@end
@class NSString, NSDictionary;
@interface NSValue : NSObject <NSCopying, NSCoding>  - (void)getValue:(void *)value;
@end
@interface NSNumber : NSValue
- (char)charValue;
- (id)initWithInt:(int)value;
+ (NSNumber *)numberWithInt:(int)value;
@end
@class NSString;
@interface NSArray : NSObject <NSCopying, NSMutableCopying, NSCoding, NSFastEnumeration>
- (NSUInteger)count;
- (id)initWithObjects:(const id [])objects count:(NSUInteger)cnt;
+ (id)arrayWithObject:(id)anObject;
+ (id)arrayWithObjects:(const id [])objects count:(NSUInteger)cnt;
+ (id)arrayWithObjects:(id)firstObj, ... __attribute__((sentinel(0,1)));
- (id)initWithObjects:(id)firstObj, ... __attribute__((sentinel(0,1)));
- (id)initWithArray:(NSArray *)array;
@end  @interface NSArray (NSArrayCreation)  + (id)array;
@end       @interface NSAutoreleasePool : NSObject {
}
- (void)drain;
@end extern NSString * const NSBundleDidLoadNotification;
typedef double NSTimeInterval;
@interface NSDate : NSObject <NSCopying, NSCoding>  - (NSTimeInterval)timeIntervalSinceReferenceDate;
@end            typedef unsigned short unichar;
@interface NSString : NSObject <NSCopying, NSMutableCopying, NSCoding>
- (NSUInteger)length;
- (NSString *)stringByAppendingString:(NSString *)aString;
- ( const char *)UTF8String;
- (id)initWithUTF8String:(const char *)nullTerminatedCString;
+ (id)stringWithUTF8String:(const char *)nullTerminatedCString;
@end        @class NSString, NSURL, NSError;
@interface NSData : NSObject <NSCopying, NSMutableCopying, NSCoding>  - (NSUInteger)length;
+ (id)dataWithBytesNoCopy:(void *)bytes length:(NSUInteger)length;
+ (id)dataWithBytesNoCopy:(void *)bytes length:(NSUInteger)length freeWhenDone:(BOOL)b;
@end   @class NSLocale, NSDate, NSCalendar, NSTimeZone, NSError, NSArray, NSMutableDictionary;
@interface NSDictionary : NSObject <NSCopying, NSMutableCopying, NSCoding, NSFastEnumeration>
- (NSUInteger)count;
+ (id)dictionaryWithObjects:(NSArray *)objects forKeys:(NSArray *)keys;
+ (id)dictionaryWithObjects:(const id [])objects forKeys:(const id <NSCopying> [])keys count:(NSUInteger)cnt;
@end
@interface NSMutableDictionary : NSDictionary  - (void)removeObjectForKey:(id)aKey;
- (void)setObject:(id)anObject forKey:(id)aKey;
@end
@interface NSMutableDictionary (NSMutableDictionaryCreation)  + (id)dictionaryWithCapacity:(NSUInteger)numItems;
@end

@interface NSNull : NSObject
+ (NSNull*) null;
@end

typedef double CGFloat;
struct CGSize {
};
typedef struct CGSize CGSize;
struct CGRect {
};
typedef struct CGRect CGRect;
typedef mach_port_t io_object_t;
typedef char io_name_t[128];
typedef io_object_t io_iterator_t;
typedef io_object_t io_service_t;
typedef struct IONotificationPort * IONotificationPortRef;
typedef void (*IOServiceMatchingCallback)(  void * refcon,  io_iterator_t iterator );
io_service_t IOServiceGetMatchingService(  mach_port_t mainPort,  CFDictionaryRef matching );
kern_return_t IOServiceGetMatchingServices(  mach_port_t mainPort,  CFDictionaryRef matching,  io_iterator_t * existing );
kern_return_t IOServiceAddNotification(  mach_port_t mainPort,  const io_name_t notificationType,  CFDictionaryRef matching,  mach_port_t wakePort,  uintptr_t reference,  io_iterator_t * notification ) __attribute__((deprecated)); // expected-note {{'IOServiceAddNotification' has been explicitly marked deprecated here}}
kern_return_t IOServiceAddMatchingNotification(  IONotificationPortRef notifyPort,  const io_name_t notificationType,  CFDictionaryRef matching,         IOServiceMatchingCallback callback,         void * refCon,  io_iterator_t * notification );
CFMutableDictionaryRef IOServiceMatching(  const char * name );
CFMutableDictionaryRef IOServiceNameMatching(  const char * name );
CFMutableDictionaryRef IOBSDNameMatching(  mach_port_t mainPort,  uint32_t options,  const char * bsdName );
CFMutableDictionaryRef IOOpenFirmwarePathMatching(  mach_port_t mainPort,  uint32_t options,  const char * path );
CFMutableDictionaryRef IORegistryEntryIDMatching(  uint64_t entryID );
typedef struct __DASession * DASessionRef;
extern DASessionRef DASessionCreate( CFAllocatorRef allocator );
typedef struct __DADisk * DADiskRef;
extern DADiskRef DADiskCreateFromBSDName( CFAllocatorRef allocator, DASessionRef session, const char * name );
extern DADiskRef DADiskCreateFromIOMedia( CFAllocatorRef allocator, DASessionRef session, io_service_t media );
extern CFDictionaryRef DADiskCopyDescription( DADiskRef disk );
extern DADiskRef DADiskCopyWholeDisk( DADiskRef disk );
@interface NSTask : NSObject - (id)init;
@end                    typedef struct CGColorSpace *CGColorSpaceRef;
typedef struct CGImage *CGImageRef;
typedef struct CGLayer *CGLayerRef;
@interface NSResponder : NSObject <NSCoding> {
}
@end    @protocol NSAnimatablePropertyContainer      - (id)animator;
@end  extern NSString *NSAnimationTriggerOrderIn ;
@interface NSView : NSResponder  <NSAnimatablePropertyContainer>  {
}
@end @protocol NSValidatedUserInterfaceItem - (SEL)action;
@end   @protocol NSUserInterfaceValidations - (BOOL)validateUserInterfaceItem:(id <NSValidatedUserInterfaceItem>)anItem;
@end  @class NSDate, NSDictionary, NSError, NSException, NSNotification;
@class NSTextField, NSPanel, NSArray, NSWindow, NSImage, NSButton, NSError;
@interface NSApplication : NSResponder <NSUserInterfaceValidations> {
}
- (void)beginSheet:(NSWindow *)sheet modalForWindow:(NSWindow *)docWindow modalDelegate:(id)modalDelegate didEndSelector:(SEL)didEndSelector contextInfo:(void *)contextInfo;
@end   enum {
NSTerminateCancel = 0,         NSTerminateNow = 1,         NSTerminateLater = 2 };
typedef NSUInteger NSApplicationTerminateReply;
@protocol NSApplicationDelegate <NSObject> @optional        - (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)sender;
@end  @class NSAttributedString, NSEvent, NSFont, NSFormatter, NSImage, NSMenu, NSText, NSView, NSTextView;
@interface NSCell : NSObject <NSCopying, NSCoding> {
}
@end 
typedef struct {
}
CVTimeStamp;
@interface CIImage : NSObject <NSCoding, NSCopying> {
}
typedef int CIFormat;
@end  enum {
kDAReturnSuccess = 0,     kDAReturnError = (((0x3eU)&0x3f)<<26) | (((0x368)&0xfff)<<14) | 0x01,     kDAReturnBusy = (((0x3eU)&0x3f)<<26) | (((0x368)&0xfff)<<14) | 0x02,     kDAReturnBadArgument = (((0x3eU)&0x3f)<<26) | (((0x368)&0xfff)<<14) | 0x03,     kDAReturnExclusiveAccess = (((0x3eU)&0x3f)<<26) | (((0x368)&0xfff)<<14) | 0x04,     kDAReturnNoResources = (((0x3eU)&0x3f)<<26) | (((0x368)&0xfff)<<14) | 0x05,     kDAReturnNotFound = (((0x3eU)&0x3f)<<26) | (((0x368)&0xfff)<<14) | 0x06,     kDAReturnNotMounted = (((0x3eU)&0x3f)<<26) | (((0x368)&0xfff)<<14) | 0x07,     kDAReturnNotPermitted = (((0x3eU)&0x3f)<<26) | (((0x368)&0xfff)<<14) | 0x08,     kDAReturnNotPrivileged = (((0x3eU)&0x3f)<<26) | (((0x368)&0xfff)<<14) | 0x09,     kDAReturnNotReady = (((0x3eU)&0x3f)<<26) | (((0x368)&0xfff)<<14) | 0x0A,     kDAReturnNotWritable = (((0x3eU)&0x3f)<<26) | (((0x368)&0xfff)<<14) | 0x0B,     kDAReturnUnsupported = (((0x3eU)&0x3f)<<26) | (((0x368)&0xfff)<<14) | 0x0C };
typedef mach_error_t DAReturn;
typedef const struct __DADissenter * DADissenterRef;
extern DADissenterRef DADissenterCreate( CFAllocatorRef allocator, DAReturn status, CFStringRef string );
@interface CIContext: NSObject {
}
- (CGImageRef)createCGImage:(CIImage *)im fromRect:(CGRect)r;
- (CGImageRef)createCGImage:(CIImage *)im fromRect:(CGRect)r     format:(CIFormat)f colorSpace:(CGColorSpaceRef)cs;
- (CGLayerRef)createCGLayerWithSize:(CGSize)size info:(CFDictionaryRef)d;
@end extern NSString* const QCRendererEventKey;
@protocol QCCompositionRenderer - (NSDictionary*) attributes;
@end   @interface QCRenderer : NSObject <QCCompositionRenderer> {
}
- (id) createSnapshotImageOfType:(NSString*)type;
@end  extern NSString* const QCViewDidStartRenderingNotification;
@interface QCView : NSView <QCCompositionRenderer> {
}
- (id) createSnapshotImageOfType:(NSString*)type;
@end    enum {
ICEXIFOrientation1 = 1,     ICEXIFOrientation2 = 2,     ICEXIFOrientation3 = 3,     ICEXIFOrientation4 = 4,     ICEXIFOrientation5 = 5,     ICEXIFOrientation6 = 6,     ICEXIFOrientation7 = 7,     ICEXIFOrientation8 = 8, };
@class ICDevice;
@protocol ICDeviceDelegate <NSObject>  @required      - (void)didRemoveDevice:(ICDevice*)device;
@end extern NSString *const ICScannerStatusWarmingUp;
@class ICScannerDevice;
@protocol ICScannerDeviceDelegate <ICDeviceDelegate>  @optional       - (void)scannerDeviceDidBecomeAvailable:(ICScannerDevice*)scanner;
@end

typedef long unsigned int __darwin_size_t;
typedef __darwin_size_t size_t;
typedef unsigned long CFTypeID;
struct CGPoint {
  CGFloat x;
  CGFloat y;
};
typedef struct CGPoint CGPoint;
typedef struct CGGradient *CGGradientRef;
typedef uint32_t CGGradientDrawingOptions;
extern CFTypeID CGGradientGetTypeID(void);
extern CGGradientRef CGGradientCreateWithColorComponents(CGColorSpaceRef
  space, const CGFloat components[], const CGFloat locations[], size_t count);
extern CGGradientRef CGGradientCreateWithColors(CGColorSpaceRef space,
  CFArrayRef colors, const CGFloat locations[]);
extern CGGradientRef CGGradientRetain(CGGradientRef gradient);
extern void CGGradientRelease(CGGradientRef gradient);
typedef struct CGContext *CGContextRef;
extern void CGContextDrawLinearGradient(CGContextRef context,
    CGGradientRef gradient, CGPoint startPoint, CGPoint endPoint,
    CGGradientDrawingOptions options);
extern CGColorSpaceRef CGColorSpaceCreateDeviceRGB(void);

@interface NSMutableArray : NSObject
- (void)addObject:(id)object;
+ (id)array;
@end

// This is how NSMakeCollectable is declared in the OS X 10.8 headers.
id NSMakeCollectable(CFTypeRef __attribute__((cf_consumed))) __attribute__((ns_returns_retained));

typedef const struct __CFUUID * CFUUIDRef;

extern
void *CFPlugInInstanceCreate(CFAllocatorRef allocator, CFUUIDRef factoryUUID, CFUUIDRef typeUUID);
typedef struct {
  int ref;
} isl_basic_map;

//===----------------------------------------------------------------------===//
// Test cases.
//===----------------------------------------------------------------------===//

CFAbsoluteTime f1(void) {
  CFAbsoluteTime t = CFAbsoluteTimeGetCurrent();
  CFDateRef date = CFDateCreate(0, t);
  CFRetain(date);
  CFRelease(date);
  CFDateGetAbsoluteTime(date); // no-warning
  CFRelease(date);
  t = CFDateGetAbsoluteTime(date);   // expected-warning{{Reference-counted object is used after it is released}}
  return t;
}

CFAbsoluteTime f2(void) {
  CFAbsoluteTime t = CFAbsoluteTimeGetCurrent();
  CFDateRef date = CFDateCreate(0, t);  
  [((NSDate*) date) retain];
  CFRelease(date);
  CFDateGetAbsoluteTime(date); // no-warning
  [((NSDate*) date) release];
  t = CFDateGetAbsoluteTime(date);   // expected-warning{{Reference-counted object is used after it is released}}
  return t;
}


NSDate* global_x;

// Test to see if we suppress an error when we store the pointer
// to a global.

CFAbsoluteTime f3(void) {
  CFAbsoluteTime t = CFAbsoluteTimeGetCurrent();
  CFDateRef date = CFDateCreate(0, t);  
  [((NSDate*) date) retain];
  CFRelease(date);
  CFDateGetAbsoluteTime(date); // no-warning
  global_x = (NSDate*) date;  
  [((NSDate*) date) release];
  t = CFDateGetAbsoluteTime(date);   // no-warning
  return t;
}

//---------------------------------------------------------------------------
// Test case 'f4' differs for region store and basic store.  See
// retain-release-region-store.m and retain-release-basic-store.m.
//---------------------------------------------------------------------------

// Test a leak.

CFAbsoluteTime f5(int x) {  
  CFAbsoluteTime t = CFAbsoluteTimeGetCurrent();
  CFDateRef date = CFDateCreate(0, t); // expected-warning{{leak}}
  
  if (x)
    CFRelease(date);
  
  return t;
}

// Test a leak involving the return.

CFDateRef f6(int x) {  
  CFDateRef date = CFDateCreate(0, CFAbsoluteTimeGetCurrent());  // expected-warning{{leak}}
  CFRetain(date);
  return date;
}

// Test a leak involving an overwrite.

CFDateRef f7(void) {
  CFDateRef date = CFDateCreate(0, CFAbsoluteTimeGetCurrent());  //expected-warning{{leak}}
  CFRetain(date);
  date = CFDateCreate(0, CFAbsoluteTimeGetCurrent()); // expected-warning {{leak}}
  return date;
}

// Generalization of Create rule.  MyDateCreate returns a CFXXXTypeRef, and
// has the word create.
CFDateRef MyDateCreate(void);

CFDateRef f8(void) {
  CFDateRef date = MyDateCreate(); // expected-warning{{leak}}
  CFRetain(date);  
  return date;
}

__attribute__((cf_returns_retained)) CFDateRef f9(void) {
  CFDateRef date = CFDateCreate(0, CFAbsoluteTimeGetCurrent()); // no-warning
  int *p = 0;
  // When allocations fail, CFDateCreate can return null.
  if (!date) *p = 1; // expected-warning{{null}}
  return date;
}

// Handle DiskArbitration API:
//
// http://developer.apple.com/DOCUMENTATION/DARWIN/Reference/DiscArbitrationFramework/
//
void f10(io_service_t media, DADiskRef d, CFStringRef s) {
  DADiskRef disk = DADiskCreateFromBSDName(kCFAllocatorDefault, 0, "hello"); // expected-warning{{leak}}
  if (disk) NSLog(@"ok");
  
  disk = DADiskCreateFromIOMedia(kCFAllocatorDefault, 0, media); // expected-warning{{leak}}
  if (disk) NSLog(@"ok");

  CFDictionaryRef dict = DADiskCopyDescription(d);  // expected-warning{{leak}}
  if (dict) NSLog(@"ok"); 
  
  disk = DADiskCopyWholeDisk(d); // expected-warning{{leak}}
  if (disk) NSLog(@"ok");
    
  DADissenterRef dissenter = DADissenterCreate(kCFAllocatorDefault,   // expected-warning{{leak}}
                                                kDAReturnSuccess, s);
  if (dissenter) NSLog(@"ok");
  
  DASessionRef session = DASessionCreate(kCFAllocatorDefault);  // expected-warning{{leak}}
  if (session) NSLog(@"ok");
}


// Handle CoreMedia API

struct CMFoo;
typedef struct CMFoo *CMFooRef;

CMFooRef CMCreateFooRef(void);
CMFooRef CMGetFooRef(void);

typedef signed long SInt32;
typedef SInt32  OSStatus;
OSStatus CMCreateFooAndReturnViaOutParameter(CMFooRef * CF_RETURNS_RETAINED fooOut);

void testLeakCoreMediaReferenceType(void) {
  CMFooRef f = CMCreateFooRef(); // expected-warning{{leak}}
}

void testOverReleaseMediaReferenceType(void) {
  CMFooRef f = CMGetFooRef();
  CFRelease(f); // expected-warning{{Incorrect decrement of the reference count}}
}

void testOkToReleaseReturnsRetainedOutParameter(void) {
  CMFooRef foo = 0;
  OSStatus status = CMCreateFooAndReturnViaOutParameter(&foo);

  if (status != 0)
    return;

  CFRelease(foo); // no-warning
}

void testLeakWithReturnsRetainedOutParameter(void) {
  CMFooRef foo = 0;
  OSStatus status = CMCreateFooAndReturnViaOutParameter(&foo);

  if (status != 0)
    return;

  // FIXME: Ideally we would report a leak here since it is the caller's
  // responsibility to release 'foo'. However, we don't currently have
  // a mechanism in this checker to only require a release when a successful
  // status is returned.
}

typedef CFTypeRef CMBufferRef;

typedef CFTypeRef *CMBufferQueueRef;

CMBufferRef CMBufferQueueDequeueAndRetain(CMBufferQueueRef);

void testCMBufferQueueDequeueAndRetain(CMBufferQueueRef queue) {
  CMBufferRef buffer = CMBufferQueueDequeueAndRetain(queue); // expected-warning{{Potential leak of an object stored into 'buffer'}}
  // There's a state split due to the eagerly-assume behavior.
  // The point here is that we don't treat CMBufferQueueDequeueAndRetain
  // as some sort of CFRetain() that returns its argument.
  clang_analyzer_eval((CMFooRef)buffer == (CMFooRef)queue); // expected-warning{{TRUE}}
                                                            // expected-warning@-1{{FALSE}}
}

// Test retain/release checker with CFString and CFMutableArray.
void f11(void) {
  // Create the array.
  CFMutableArrayRef A = CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks);

  // Create a string.
  CFStringRef s1 = CFStringCreateWithCString(0, "hello world",
                                             kCFStringEncodingUTF8);

  // Add the string to the array.
  CFArrayAppendValue(A, s1);
  
  // Decrement the reference count.
  CFRelease(s1); // no-warning
  
  // Get the string.  We don't own it.
  s1 = (CFStringRef) CFArrayGetValueAtIndex(A, 0);
  
  // Release the array.
  CFRelease(A); // no-warning
  
  // Release the string.  This is a bug.
  CFRelease(s1); // expected-warning{{Incorrect decrement of the reference count}}
}

// PR 3337: Handle functions declared using typedefs.
typedef CFTypeRef CREATEFUN(void);
CREATEFUN MyCreateFun;

void f12(void) {
  CFTypeRef o = MyCreateFun(); // expected-warning {{leak}}
}

void f13_autorelease(void) {
  CFMutableArrayRef A = CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks); // no-warning
  [(id) A autorelease]; // no-warning
}

void f13_autorelease_b(void) {
  CFMutableArrayRef A = CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks);
  [(id) A autorelease];
  [(id) A autorelease];
} // expected-warning{{Object autoreleased too many times}}

CFMutableArrayRef f13_autorelease_c(void) {
  CFMutableArrayRef A = CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks);
  [(id) A autorelease];
  [(id) A autorelease]; 
  return A; // expected-warning{{Object autoreleased too many times}}
}

CFMutableArrayRef f13_autorelease_d(void) {
  CFMutableArrayRef A = CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks);
  [(id) A autorelease];
  [(id) A autorelease]; 
  CFMutableArrayRef B = CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks); // expected-warning{{Object autoreleased too many times}}
  CFRelease(B); // no-warning
  while (1) {}
}


// This case exercises the logic where the leak site is the same as the allocation site.
void f14_leakimmediately(void) {
  CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks); // expected-warning{{leak}}
}

// Test that we track an allocated object beyond the point where the *name*
// of the variable storing the reference is no longer live.
void f15(void) {
  // Create the array.
  CFMutableArrayRef A = CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks);
  CFMutableArrayRef *B = &A;
  // At this point, the name 'A' is no longer live.
  CFRelease(*B);  // no-warning
}

// Test when we pass NULL to CFRetain/CFRelease/CFMakeCollectable/CFAutorelease.
void f16(int x, CFTypeRef p) {
  if (p)
    return;

  switch (x) {
  case 0:
    CFRelease(p); // expected-warning{{Null pointer argument in call to CFRelease}}
    break;
  case 1:
    CFRetain(p); // expected-warning{{Null pointer argument in call to CFRetain}}
    break;
  case 2:
    CFMakeCollectable(p); // expected-warning{{Null pointer argument in call to CFMakeCollectable}}
    break;
  case 3:
    CFAutorelease(p); // expected-warning{{Null pointer argument in call to CFAutorelease}}
    break;
  default:
    break;
  }
}

#ifdef TRACK_START_PARAM
@interface TestParam : NSObject
- (void) f:(id) object;
@end

@implementation TestParam
- (void) f:(id) object { // expected-warning{{Potential leak of an object of type 'id'}}
  [object retain];
  [object retain];
}
@end
#endif

// Test that an object is non-null after CFRetain/CFRelease/CFMakeCollectable/CFAutorelease.
void f17(int x, CFTypeRef p) {
#ifdef TRACK_START_PARAM
  // expected-warning@-2{{Potential leak of an object of type 'CFTypeRef'}}
#endif
  switch (x) {
  case 0:
    CFRelease(p);
#ifdef TRACK_START_PARAM
  // expected-warning@-2{{Incorrect decrement of the reference count of an object that is not owned at this point by the caller}}
#endif
    if (!p)
      CFRelease(0); // no-warning
    break;
  case 1:
    CFRetain(p);
    if (!p)
      CFRetain(0); // no-warning
    break;
  case 2:
    CFMakeCollectable(p);
    if (!p)
      CFMakeCollectable(0); // no-warning
    break;
  case 3:
    CFAutorelease(p);
    if (!p)
      CFAutorelease(0); // no-warning
    break;
  default:
    break;
  }
}
#ifdef TRACK_START_PARAM
  // expected-warning@-2{{Object autoreleased too many times}}
#endif

__attribute__((annotate("rc_ownership_returns_retained"))) isl_basic_map *isl_basic_map_cow(__attribute__((annotate("rc_ownership_consumed"))) isl_basic_map *bmap);

// Test custom diagnostics for generalized objects.
void f18(__attribute__((annotate("rc_ownership_consumed"))) isl_basic_map *bmap) {
  // After this call, 'bmap' has a +1 reference count.
  bmap = isl_basic_map_cow(bmap); // expected-warning {{Potential leak of an object}}
}

// Test basic tracking of ivars associated with 'self'.  For the retain/release
// checker we currently do not want to flag leaks associated with stores
// of tracked objects to ivars.
@interface SelfIvarTest : NSObject {
  id myObj;
}
- (void)test_self_tracking;
@end

@implementation SelfIvarTest
- (void)test_self_tracking {
  myObj = (id) CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks); // no-warning
}
@end

// Test return of non-owned objects in contexts where an owned object
// is expected.
@interface TestReturnNotOwnedWhenExpectedOwned
- (NSString*)newString;
@end

@implementation TestReturnNotOwnedWhenExpectedOwned
- (NSString*)newString {
  NSString *s = [NSString stringWithUTF8String:"hello"];
  return s; // expected-warning{{Object with a +0 retain count returned to caller where a +1 (owning) retain count is expected}}
}
@end

int isFoo(char c);

static void rdar_6659160(char *inkind, char *inname)
{
  // We currently expect that [NSObject alloc] cannot fail.  This
  // will be a toggled flag in the future.  It can indeed return null, but
  // Cocoa programmers generally aren't expected to reason about out-of-memory
  // conditions.
  NSString *kind = [[NSString alloc] initWithUTF8String:inkind];  // expected-warning{{leak}}
  
  // We do allow stringWithUTF8String to fail.  This isn't really correct, as
  // far as returning 0.  In most error conditions it will throw an exception.
  // If allocation fails it could return 0, but again this
  // isn't expected.
  NSString *name = [NSString stringWithUTF8String:inname];
  if(!name)
    return;

  const char *kindC = 0;
  const char *nameC = 0;
  
  // In both cases, we cannot reach a point down below where we
  // dereference kindC or nameC with either being null.  This is because
  // we assume that [NSObject alloc] doesn't fail and that we have the guard
  // up above.
  
  if(kind)
    kindC = [kind UTF8String];
  if(name)
    nameC = [name UTF8String];
  if(!isFoo(kindC[0])) // expected-warning{{null}}
    return;
  if(!isFoo(nameC[0])) // no-warning
    return;

  [kind release];
  [name release]; // expected-warning{{Incorrect decrement of the reference count}}
}

// PR 3677 - 'allocWithZone' should be treated as following the Cocoa naming
//  conventions with respect to 'return'ing ownership.
@interface PR3677: NSObject @end
@implementation PR3677
+ (id)allocWithZone:(NSZone *)inZone {
  return [super allocWithZone:inZone];  // no-warning
}
@end

// PR 3820 - Reason about calls to -dealloc
void pr3820_DeallocInsteadOfRelease(void)
{
  id foo = [[NSString alloc] init]; // no-warning
  [foo dealloc];
  // foo is not leaked, since it has been deallocated.
}

void pr3820_ReleaseAfterDealloc(void)
{
  id foo = [[NSString alloc] init];
  [foo dealloc];
  [foo release];  // expected-warning{{used after it is release}}
  // NSInternalInconsistencyException: message sent to deallocated object
}

void pr3820_DeallocAfterRelease(void)
{
  NSLog(@"\n\n[%s]", __FUNCTION__);
  id foo = [[NSString alloc] init];
  [foo release];
  [foo dealloc]; // expected-warning{{used after it is released}}
  // message sent to released object
}

// The problem here is that 'length' binds to'($0 - 1)' after '--length', but
// SimpleConstraintManager doesn't know how to reason about
// '($0 - 1) > constant'.  As a temporary hack, we drop the value of '($0 - 1)'
// and conjure a new symbol.
void rdar6704930(unsigned char *s, unsigned int length) {
  NSString* name = 0;
  if (s != 0) {
    if (length > 0) {
      while (length > 0) {
        if (*s == ':') {
          ++s;
          --length;
          name = [[NSString alloc] init]; // no-warning
          break;
        }
        ++s;
        --length;
      }
      if ((length == 0) && (name != 0)) {
        [name release];
        name = 0;
      }
      if (length == 0) { // no ':' found -> use it all as name
        name = [[NSString alloc] init]; // no-warning
      }
    }
  }

  if (name != 0) {
    [name release];
  }
}

//===----------------------------------------------------------------------===//
// One build of the analyzer accidentally stopped tracking the allocated
// object after the 'retain'.
//===----------------------------------------------------------------------===//

@interface rdar_6833332 : NSObject <NSApplicationDelegate> {
    NSWindow *window;
}
@property (nonatomic, retain) NSWindow *window;
@end

@implementation rdar_6833332
@synthesize window;
- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
 NSMutableDictionary *dict = [[NSMutableDictionary dictionaryWithCapacity:4] retain]; // expected-warning{{leak}}

 [dict setObject:@"foo" forKey:@"bar"];

 NSLog(@"%@", dict);
}
- (void)dealloc {
    [window release];
    [super dealloc];
}

- (void)radar10102244 {
 NSMutableDictionary *dict = [[NSMutableDictionary dictionaryWithCapacity:4] retain]; // expected-warning{{leak}} 
 if (window) 
   NSLog(@"%@", window);    
}
@end

//===----------------------------------------------------------------------===//
// clang checker fails to catch use-after-release
//===----------------------------------------------------------------------===//
int rdar_6257780_Case1(void) {
  NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
  NSArray *array = [NSArray array];
  [array release]; // expected-warning{{Incorrect decrement of the reference count of an object that is not owned at this point by the caller}}
  [pool drain];
  return 0;
}

//===----------------------------------------------------------------------===//
// Analyzer is confused about NSAutoreleasePool -allocWithZone:.
//===----------------------------------------------------------------------===//
void rdar_10640253_autorelease_allocWithZone(void) {
    NSAutoreleasePool *pool = [[NSAutoreleasePool allocWithZone:(NSZone*)0] init];
    (void) pool;
}

//===----------------------------------------------------------------------===//
// Checker should understand new/setObject:/release constructs
//===----------------------------------------------------------------------===//
void rdar_6866843(void) {
 NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
 NSMutableDictionary* dictionary = [[NSMutableDictionary alloc] init];
 NSArray* array = [[NSArray alloc] init];
 [dictionary setObject:array forKey:@"key"];
 [array release];
 // Using 'array' here should be fine
 NSLog(@"array = %@\n", array); // no-warning
 // Now the array is released
 [dictionary release];
 [pool drain];
}


//===----------------------------------------------------------------------===//
// Classes typedef-ed to CF objects should get the same treatment as CF objects
//===----------------------------------------------------------------------===//

typedef CFTypeRef OtherRef;

@interface RDar6877235 : NSObject {}
- (CFTypeRef)_copyCFTypeRef;
- (OtherRef)_copyOtherRef;
@end

@implementation RDar6877235
- (CFTypeRef)_copyCFTypeRef {
  return [[NSString alloc] init]; // no-warning
}
- (OtherRef)_copyOtherRef {
  return [[NSString alloc] init]; // no-warning
}
@end

//===----------------------------------------------------------------------===//
// False positive - init method returns an object owned by caller.
//===----------------------------------------------------------------------===//
@interface RDar6320065 : NSObject {
  NSString *_foo;
}
- (id)initReturningNewClass;
- (id)_initReturningNewClassBad;
- (id)initReturningNewClassBad2;
@end

@interface RDar6320065Subclass : RDar6320065
@end

@implementation RDar6320065
- (id)initReturningNewClass {
  [self release];
  self = [[RDar6320065Subclass alloc] init]; // no-warning
  return self;
}
- (id)_initReturningNewClassBad {
  [self release];
  [[RDar6320065Subclass alloc] init]; // expected-warning {{leak}}
  return self;
}
- (id)initReturningNewClassBad2 {
  [self release];
  self = [[RDar6320065Subclass alloc] init];
  return [self autorelease]; // expected-warning{{Object with a +0 retain count returned to caller where a +1 (owning) retain count is expected}}
}

@end

@implementation RDar6320065Subclass
@end

int RDar6320065_test(void) {
  RDar6320065 *test = [[RDar6320065 alloc] init]; // no-warning
  [test release];
  return 0;
}

//===----------------------------------------------------------------------===//
// -awakeAfterUsingCoder: returns an owned object and claims the receiver
//===----------------------------------------------------------------------===//
@interface RDar7129086 : NSObject {} @end
@implementation RDar7129086
- (id)awakeAfterUsingCoder:(NSCoder *)aDecoder {
  [self release]; // no-warning
  return [NSString alloc];  // no-warning
}
@end

//===----------------------------------------------------------------------===//
// [NSData dataWithBytesNoCopy] does not return a retained object
//===----------------------------------------------------------------------===//
@interface RDar6859457 : NSObject {}
- (NSString*) NoCopyString;
- (NSString*) noCopyString;
@end

@implementation RDar6859457 
- (NSString*) NoCopyString { return [[NSString alloc] init]; } // expected-warning{{leak}}
- (NSString*) noCopyString { return [[NSString alloc] init]; } // expected-warning{{leak}}
@end

void test_RDar6859457(RDar6859457 *x, void *bytes, NSUInteger dataLength) {
  [x NoCopyString]; // expected-warning{{leak}}
  [x noCopyString]; // expected-warning{{leak}}
  [NSData dataWithBytesNoCopy:bytes length:dataLength];  // no-warning
  [NSData dataWithBytesNoCopy:bytes length:dataLength freeWhenDone:1]; // no-warning
}

//===----------------------------------------------------------------------===//
// PR 4230 - an autorelease pool is not necessarily leaked during a premature
//  return
//===----------------------------------------------------------------------===//

static void PR4230(void)
{
  NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init]; // no-warning
  NSString *object = [[[NSString alloc] init] autorelease]; // no-warning
  return;
}

static void PR4230_new(void)
{
  NSAutoreleasePool *pool = [NSAutoreleasePool new]; // no-warning
  NSString *object = [[[NSString alloc] init] autorelease]; // no-warning
  return;
}

//===----------------------------------------------------------------------===//
// Method name that has a null IdentifierInfo* for its first selector slot.
// This test just makes sure that we handle it.
//===----------------------------------------------------------------------===//

@interface TestNullIdentifier
@end

@implementation TestNullIdentifier
+ (id):(int)x, ... {
  return [[NSString alloc] init]; // expected-warning{{leak}}
}
@end

//===----------------------------------------------------------------------===//
// Don't flag leaks for return types that cannot be determined to be CF types.
//===----------------------------------------------------------------------===//

// We don't know if 'struct s6893565' represents a Core Foundation type, so
// we shouldn't emit an error here.
typedef struct s6893565* TD6893565;

@interface RDar6893565 {}
-(TD6893565)newThing;
@end

@implementation RDar6893565
-(TD6893565)newThing {  
  return (TD6893565) [[NSString alloc] init]; // no-warning
}
@end

//===----------------------------------------------------------------------===//
// clang: false positives w/QC and CoreImage methods
//===----------------------------------------------------------------------===//
void rdar6902710(QCView *view, QCRenderer *renderer, CIContext *context,
                 NSString *str, CIImage *img, CGRect rect,
                 CIFormat form, CGColorSpaceRef cs) {
  [view createSnapshotImageOfType:str]; // expected-warning{{leak}}
  [renderer createSnapshotImageOfType:str]; // expected-warning{{leak}}
  [context createCGImage:img fromRect:rect]; // expected-warning{{leak}}
  [context createCGImage:img fromRect:rect format:form colorSpace:cs]; // expected-warning{{leak}}
}

//===----------------------------------------------------------------------===//
// -[CIContext createCGLayerWithSize:info:] misinterpreted by clang scan-build
//===----------------------------------------------------------------------===//
void rdar6945561(CIContext *context, CGSize size, CFDictionaryRef d) {
  [context createCGLayerWithSize:size info:d]; // expected-warning{{leak}}
}

//===----------------------------------------------------------------------===//
// Add knowledge of IOKit functions to retain/release checker.
//===----------------------------------------------------------------------===//
void IOBSDNameMatching_wrapper(mach_port_t mainPort, uint32_t options,  const char * bsdName) {  
  IOBSDNameMatching(mainPort, options, bsdName); // expected-warning{{leak}}
}

void IOServiceMatching_wrapper(const char * name) {
  IOServiceMatching(name); // expected-warning{{leak}}
}

void IOServiceNameMatching_wrapper(const char * name) {
  IOServiceNameMatching(name); // expected-warning{{leak}}
}

CF_RETURNS_RETAINED CFDictionaryRef CreateDict(void);

void IOServiceAddNotification_wrapper(mach_port_t mainPort, const io_name_t notificationType,
  mach_port_t wakePort, uintptr_t reference, io_iterator_t * notification ) {

  CFDictionaryRef matching = CreateDict();
  CFRelease(matching);
  IOServiceAddNotification(mainPort, notificationType, matching, // expected-warning{{used after it is released}} expected-warning{{deprecated}}
                           wakePort, reference, notification);
}

void IORegistryEntryIDMatching_wrapper(uint64_t entryID ) {
  IORegistryEntryIDMatching(entryID); // expected-warning{{leak}}
}

void IOOpenFirmwarePathMatching_wrapper(mach_port_t mainPort, uint32_t options,
                                        const char * path) {
  IOOpenFirmwarePathMatching(mainPort, options, path); // expected-warning{{leak}}
}

void IOServiceGetMatchingService_wrapper(mach_port_t mainPort) {
  CFDictionaryRef matching = CreateDict();
  IOServiceGetMatchingService(mainPort, matching);
  CFRelease(matching); // expected-warning{{used after it is released}}
}

void IOServiceGetMatchingServices_wrapper(mach_port_t mainPort, io_iterator_t *existing) {
  CFDictionaryRef matching = CreateDict();
  IOServiceGetMatchingServices(mainPort, matching, existing);
  CFRelease(matching); // expected-warning{{used after it is released}}
}

void IOServiceAddMatchingNotification_wrapper(IONotificationPortRef notifyPort, const io_name_t notificationType, 
  IOServiceMatchingCallback callback, void * refCon, io_iterator_t * notification) {
    
  CFDictionaryRef matching = CreateDict();
  IOServiceAddMatchingNotification(notifyPort, notificationType, matching, callback, refCon, notification);
  CFRelease(matching); // expected-warning{{used after it is released}}
}

//===----------------------------------------------------------------------===//
// Test of handling objects whose references "escape" to containers.
//===----------------------------------------------------------------------===//

void CFDictionaryAddValue(CFMutableDictionaryRef, void *, void *);

void rdar_6539791(CFMutableDictionaryRef y, void* key, void* val_key) {
  CFMutableDictionaryRef x = CFDictionaryCreateMutable(kCFAllocatorDefault, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  CFDictionaryAddValue(y, key, x);
  CFRelease(x); // the dictionary keeps a reference, so the object isn't deallocated yet
  signed z = 1;
  CFNumberRef value = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &z);
  if (value) {
    CFDictionaryAddValue(x, val_key, (void*)value); // no-warning
    CFRelease(value);
    CFDictionaryAddValue(y, val_key, (void*)value); // no-warning
  }
}

// Same issue, except with "AppendValue" functions.
void rdar_6560661(CFMutableArrayRef x) {
  signed z = 1;
  CFNumberRef value = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &z);
  // CFArrayAppendValue keeps a reference to value.
  CFArrayAppendValue(x, value);
  CFRelease(value);
  CFRetain(value);
  CFRelease(value); // no-warning
}

// Same issue, excwept with "CFAttributeStringSetAttribute".
void rdar_7152619(CFStringRef str) {
  CFAttributedStringRef string = CFAttributedStringCreate(kCFAllocatorDefault, str, 0);
  CFMutableAttributedStringRef attrString = CFAttributedStringCreateMutableCopy(kCFAllocatorDefault, 100, string);
  CFRelease(string);
  NSNumber *number = [[NSNumber alloc] initWithInt:5]; // expected-warning{{leak}}
  CFAttributedStringSetAttribute(attrString, CFRangeMake(0, 1), str, number);
  [number release];
  [number retain];
  CFRelease(attrString);  
}

//===----------------------------------------------------------------------===//
// Test of handling CGGradientXXX functions.
//===----------------------------------------------------------------------===//

void rdar_7184450(CGContextRef myContext, CGFloat x, CGPoint myStartPoint,
                  CGPoint myEndPoint) {
  size_t num_locations = 6;
  CGFloat locations[6] = { 0.0, 0.265, 0.28, 0.31, 0.36, 1.0 };
  CGFloat components[28] = { 239.0/256.0, 167.0/256.0, 170.0/256.0,
     x,  // Start color
    207.0/255.0, 39.0/255.0, 39.0/255.0, x,
    147.0/255.0, 21.0/255.0, 22.0/255.0, x,
    175.0/255.0, 175.0/255.0, 175.0/255.0, x,
    255.0/255.0,255.0/255.0, 255.0/255.0, x,
    255.0/255.0,255.0/255.0, 255.0/255.0, x
  }; // End color
  
  CGGradientRef myGradient =
    CGGradientCreateWithColorComponents(CGColorSpaceCreateDeviceRGB(), // expected-warning{{leak}}
      components, locations, num_locations);

  CGContextDrawLinearGradient(myContext, myGradient, myStartPoint, myEndPoint,
                              0);
  CGGradientRelease(myGradient);
}

void rdar_7184450_pos(CGContextRef myContext, CGFloat x, CGPoint myStartPoint,
                  CGPoint myEndPoint) {
  size_t num_locations = 6;
  CGFloat locations[6] = { 0.0, 0.265, 0.28, 0.31, 0.36, 1.0 };
  CGFloat components[28] = { 239.0/256.0, 167.0/256.0, 170.0/256.0,
     x,  // Start color
    207.0/255.0, 39.0/255.0, 39.0/255.0, x,
    147.0/255.0, 21.0/255.0, 22.0/255.0, x,
    175.0/255.0, 175.0/255.0, 175.0/255.0, x,
    255.0/255.0,255.0/255.0, 255.0/255.0, x,
    255.0/255.0,255.0/255.0, 255.0/255.0, x
  }; // End color
  
  CGGradientRef myGradient =
   CGGradientCreateWithColorComponents(CGColorSpaceCreateDeviceRGB(), components, locations, num_locations); // expected-warning 2 {{leak}}

  CGContextDrawLinearGradient(myContext, myGradient, myStartPoint, myEndPoint,
                              0);
}

//===----------------------------------------------------------------------===//
// clang false positive: retained instance passed to thread in pthread_create
// marked as leak.
//
// Until we have full IPA, the analyzer should stop tracking the reference
// count of objects passed to pthread_create.
//===----------------------------------------------------------------------===//
struct _opaque_pthread_t {};
struct _opaque_pthread_attr_t {};
typedef struct _opaque_pthread_t *__darwin_pthread_t;
typedef struct _opaque_pthread_attr_t __darwin_pthread_attr_t;
typedef __darwin_pthread_t pthread_t;
typedef __darwin_pthread_attr_t pthread_attr_t;
typedef unsigned long __darwin_pthread_key_t;
typedef __darwin_pthread_key_t pthread_key_t;

int pthread_create(pthread_t *, const pthread_attr_t *,
                   void *(*)(void *), void *);

int pthread_setspecific(pthread_key_t key, const void *value);

void *rdar_7299394_start_routine(void *p) {
  [((id) p) release];
  return 0;
}
void rdar_7299394(pthread_attr_t *attr, pthread_t *thread, void *args) {
  NSNumber *number = [[NSNumber alloc] initWithInt:5]; // no-warning
  pthread_create(thread, attr, rdar_7299394_start_routine, number);
}
void rdar_7299394_positive(pthread_attr_t *attr, pthread_t *thread) {
  NSNumber *number = [[NSNumber alloc] initWithInt:5]; // expected-warning{{leak}}
}

//===----------------------------------------------------------------------===//
// False positive with not understanding thread local storage.
//===----------------------------------------------------------------------===//
void rdar11282706(pthread_key_t key) {
  NSNumber *number = [[NSNumber alloc] initWithInt:5]; // no-warning
  pthread_setspecific(key, (void*) number);
}

//===----------------------------------------------------------------------===//
// False leak associated with call to CVPixelBufferCreateWithBytes()
//
// According to the Core Video Reference (ADC), CVPixelBufferCreateWithBytes and
// CVPixelBufferCreateWithPlanarBytes can release (via a callback) the
// pixel buffer object.  These test cases show how the analyzer stops tracking
// the reference count for the objects passed for this argument.  This
// could be made smarter.
//===----------------------------------------------------------------------===//
typedef int int32_t;
typedef UInt32 FourCharCode;
typedef FourCharCode OSType;
typedef uint64_t CVOptionFlags;
typedef int32_t CVReturn;
typedef struct __CVBuffer *CVBufferRef;
typedef CVBufferRef CVImageBufferRef;
typedef CVImageBufferRef CVPixelBufferRef;
typedef void (*CVPixelBufferReleaseBytesCallback)( void *releaseRefCon, const void *baseAddress );

extern CVReturn CVPixelBufferCreateWithBytes(CFAllocatorRef allocator,
            size_t width,
            size_t height,
            OSType pixelFormatType,
            void *baseAddress,
            size_t bytesPerRow,
            CVPixelBufferReleaseBytesCallback releaseCallback,
            void *releaseRefCon,
            CFDictionaryRef pixelBufferAttributes,
                   CVPixelBufferRef *pixelBufferOut) ;

typedef void (*CVPixelBufferReleasePlanarBytesCallback)( void *releaseRefCon, const void *dataPtr, size_t dataSize, size_t numberOfPlanes, const void *planeAddresses[] );

extern CVReturn CVPixelBufferCreateWithPlanarBytes(CFAllocatorRef allocator,
        size_t width,
        size_t height,
        OSType pixelFormatType,
        void *dataPtr,
        size_t dataSize,
        size_t numberOfPlanes,
        void *planeBaseAddress[],
        size_t planeWidth[],
        size_t planeHeight[],
        size_t planeBytesPerRow[],
        CVPixelBufferReleasePlanarBytesCallback releaseCallback,
        void *releaseRefCon,
        CFDictionaryRef pixelBufferAttributes,
        CVPixelBufferRef *pixelBufferOut) ;

extern CVReturn CVPixelBufferCreateWithBytes(CFAllocatorRef allocator,
            size_t width,
            size_t height,
            OSType pixelFormatType,
            void *baseAddress,
            size_t bytesPerRow,
            CVPixelBufferReleaseBytesCallback releaseCallback,
            void *releaseRefCon,
            CFDictionaryRef pixelBufferAttributes,
                   CVPixelBufferRef *pixelBufferOut) ;

CVReturn rdar_7283567(CFAllocatorRef allocator, size_t width, size_t height,
                      OSType pixelFormatType, void *baseAddress,
                      size_t bytesPerRow,
                      CVPixelBufferReleaseBytesCallback releaseCallback,
                      CFDictionaryRef pixelBufferAttributes,
                      CVPixelBufferRef *pixelBufferOut) {

  // For the allocated object, it doesn't really matter what type it is
  // for the purpose of this test.  All we want to show is that
  // this is freed later by the callback.
  NSNumber *number = [[NSNumber alloc] initWithInt:5]; // no-warning
  
  return CVPixelBufferCreateWithBytes(allocator, width, height, pixelFormatType,
                                baseAddress, bytesPerRow, releaseCallback,
                                number, // potentially released by callback
                                pixelBufferAttributes, pixelBufferOut) ;
}

CVReturn rdar_7283567_2(CFAllocatorRef allocator, size_t width, size_t height,
        OSType pixelFormatType, void *dataPtr, size_t dataSize,
        size_t numberOfPlanes, void *planeBaseAddress[],
        size_t planeWidth[], size_t planeHeight[], size_t planeBytesPerRow[],
        CVPixelBufferReleasePlanarBytesCallback releaseCallback,
        CFDictionaryRef pixelBufferAttributes,
        CVPixelBufferRef *pixelBufferOut) {
    
    // For the allocated object, it doesn't really matter what type it is
    // for the purpose of this test.  All we want to show is that
    // this is freed later by the callback.
    NSNumber *number = [[NSNumber alloc] initWithInt:5]; // no-warning

    return CVPixelBufferCreateWithPlanarBytes(allocator,
              width, height, pixelFormatType, dataPtr, dataSize,
              numberOfPlanes, planeBaseAddress, planeWidth,
              planeHeight, planeBytesPerRow, releaseCallback,
              number, // potentially released by callback
              pixelBufferAttributes, pixelBufferOut) ;
}

#pragma clang arc_cf_code_audited begin
typedef struct SomeOpaqueStruct *CMSampleBufferRef;
CVImageBufferRef _Nonnull CMSampleBufferGetImageBuffer(CMSampleBufferRef _Nonnull sbuf);
#pragma clang arc_cf_code_audited end

CVBufferRef _Nullable CVBufferRetain(CVBufferRef _Nullable buffer);
void CVBufferRelease(CF_CONSUMED CVBufferRef _Nullable buffer);

void testCVPrefixRetain(CMSampleBufferRef sbuf) {
  // Make sure RetainCountChecker treats CVFooRetain() as a CF-style retain.
  CVPixelBufferRef pixelBuf = CMSampleBufferGetImageBuffer(sbuf);
  CVBufferRetain(pixelBuf);
  CVBufferRelease(pixelBuf); // no-warning


  // Make sure result of CVFooRetain() is the same as its argument.
  CVPixelBufferRef pixelBufAlias = CVBufferRetain(pixelBuf);
  CVBufferRelease(pixelBufAlias); // no-warning
}

typedef signed long SInt32;
typedef SInt32  OSStatus;
typedef FourCharCode CMVideoCodecType;


typedef UInt32 VTEncodeInfoFlags; enum {
 kVTEncodeInfo_Asynchronous = 1UL << 0,
 kVTEncodeInfo_FrameDropped = 1UL << 1,
};
typedef struct
{
  int ignore;
} CMTime;


typedef void (*VTCompressionOutputCallback)(
    void * _Nullable outputCallbackRefCon,
    void * _Nullable sourceFrameRefCon,
    OSStatus status,
    VTEncodeInfoFlags infoFlags,
    _Nullable CMSampleBufferRef sampleBuffer );

typedef struct OpaqueVTCompressionSession*  VTCompressionSessionRef;

extern OSStatus
VTCompressionSessionCreate(_Nullable CFAllocatorRef allocator,
    int32_t width,
    int32_t height,
    CMVideoCodecType codecType,
    _Nullable CFDictionaryRef encoderSpecification,
    _Nullable CFDictionaryRef sourceImageBufferAttributes,
    _Nullable CFAllocatorRef compressedDataAllocator,
    _Nullable VTCompressionOutputCallback outputCallback,
    void * _Nullable outputCallbackRefCon,
    CF_RETURNS_RETAINED _Nullable VTCompressionSessionRef * _Nonnull compressionSessionOut);

extern OSStatus
VTCompressionSessionEncodeFrame(
    _Nonnull VTCompressionSessionRef session,
    _Nonnull CVImageBufferRef imageBuffer,
    CMTime presentationTimeStamp,
    CMTime duration,
    _Nullable CFDictionaryRef frameProperties,
    void * _Nullable sourceFrameRefCon,
    VTEncodeInfoFlags * _Nullable infoFlagsOut);

OSStatus test_VTCompressionSessionCreateAndEncode_CallbackReleases(
    _Nullable CFAllocatorRef allocator,
    int32_t width,
    int32_t height,
    CMVideoCodecType codecType,
    _Nullable CFDictionaryRef encoderSpecification,
    _Nullable CFDictionaryRef sourceImageBufferAttributes,
    _Nullable CFAllocatorRef compressedDataAllocator,
    _Nullable VTCompressionOutputCallback outputCallback,

    _Nonnull CVImageBufferRef imageBuffer,
    CMTime presentationTimeStamp,
    CMTime duration,
    _Nullable CFDictionaryRef frameProperties
) {

  // The outputCallback is passed both contexts and so can release either.
  NSNumber *contextForCreate = [[NSNumber alloc] initWithInt:5]; // no-warning
  NSNumber *contextForEncode = [[NSNumber alloc] initWithInt:6]; // no-warning

  VTCompressionSessionRef session = 0;
  OSStatus status = VTCompressionSessionCreate(allocator,
      width, height, codecType, encoderSpecification,
      sourceImageBufferAttributes,
      compressedDataAllocator, outputCallback, contextForCreate,
      &session);

  VTEncodeInfoFlags encodeInfoFlags;

  status = VTCompressionSessionEncodeFrame(session, imageBuffer,
      presentationTimeStamp, duration, frameProperties, contextForEncode,
      &encodeInfoFlags);

  return status;
}

//===----------------------------------------------------------------------===//
// False leak associated with CGBitmapContextCreateWithData.
//===----------------------------------------------------------------------===//
typedef uint32_t CGBitmapInfo;
typedef void (*CGBitmapContextReleaseDataCallback)(void *releaseInfo, void *data);
    
CGContextRef CGBitmapContextCreateWithData(void *data,
    size_t width, size_t height, size_t bitsPerComponent,
    size_t bytesPerRow, CGColorSpaceRef space, CGBitmapInfo bitmapInfo,
    CGBitmapContextReleaseDataCallback releaseCallback, void *releaseInfo);

void rdar_7358899(void *data,
      size_t width, size_t height, size_t bitsPerComponent,
      size_t bytesPerRow, CGColorSpaceRef space, CGBitmapInfo bitmapInfo,
      CGBitmapContextReleaseDataCallback releaseCallback) {

    // For the allocated object, it doesn't really matter what type it is
    // for the purpose of this test.  All we want to show is that
    // this is freed later by the callback.
    NSNumber *number = [[NSNumber alloc] initWithInt:5]; // no-warning

  CGBitmapContextCreateWithData(data, width, height, bitsPerComponent, // expected-warning{{leak}}
    bytesPerRow, space, bitmapInfo, releaseCallback, number);
}

//===----------------------------------------------------------------------===//
// Allow 'new', 'copy', 'alloc', 'init' prefix to start before '_' when
// determining Cocoa fundamental rule.
//
// Previously the retain/release checker just skipped prefixes before the
// first '_' entirely.  Now the checker honors the prefix if it results in a
// recognizable naming convention (e.g., 'new', 'init').
//===----------------------------------------------------------------------===//
@interface RDar7265711 {}
- (id) new_stuff;
@end

void rdar7265711_a(RDar7265711 *x) {
  id y = [x new_stuff]; // expected-warning{{leak}}
}

void rdar7265711_b(RDar7265711 *x) {
  id y = [x new_stuff]; // no-warning
  [y release];
}

//===----------------------------------------------------------------------===//
// clang thinks [NSCursor dragCopyCursor] returns a retained reference.
//===----------------------------------------------------------------------===//
@interface NSCursor : NSObject
+ (NSCursor *)dragCopyCursor;
@end

void rdar7306898(void) {
  // 'dragCopyCursor' does not follow Cocoa's fundamental rule.  It is a noun, not an sentence
  // implying a 'copy' of something.
  NSCursor *c =  [NSCursor dragCopyCursor]; // no-warning
  NSNumber *number = [[NSNumber alloc] initWithInt:5]; // expected-warning{{leak}}
}

//===----------------------------------------------------------------------===//
// Sending 'release', 'retain', etc. to a Class directly is not likely what the
// user intended.
//===----------------------------------------------------------------------===//
@interface RDar7252064 : NSObject @end
void rdar7252064(void) {
  [RDar7252064 release]; // expected-warning{{The 'release' message should be sent to instances of class 'RDar7252064' and not the class directly}}
  [RDar7252064 retain]; // expected-warning{{The 'retain' message should be sent to instances of class 'RDar7252064' and not the class directly}}
  [RDar7252064 autorelease]; // expected-warning{{The 'autorelease' message should be sent to instances of class 'RDar7252064' and not the class directly}}
  [NSAutoreleasePool drain]; // expected-warning{{method '+drain' not found}} expected-warning{{The 'drain' message should be sent to instances of class 'NSAutoreleasePool' and not the class directly}}
}

//===----------------------------------------------------------------------===//
// Tests of ownership attributes.
//===----------------------------------------------------------------------===//

typedef NSString* MyStringTy;

@protocol FooP;

@interface TestOwnershipAttr : NSObject
- (NSString*) returnsAnOwnedString  NS_RETURNS_RETAINED; // no-warning
- (NSString*) returnsAnOwnedCFString  CF_RETURNS_RETAINED; // no-warning
- (MyStringTy) returnsAnOwnedTypedString NS_RETURNS_RETAINED; // no-warning
- (NSString*) newString NS_RETURNS_NOT_RETAINED; // no-warning
- (NSString*) newString_auto NS_RETURNS_AUTORELEASED; // no-warning
- (NSString*) newStringNoAttr;
- (int) returnsAnOwnedInt NS_RETURNS_RETAINED; // expected-warning{{'ns_returns_retained' attribute only applies to methods that return an Objective-C object}}
- (id) pseudoInit NS_CONSUMES_SELF NS_RETURNS_RETAINED;
+ (void) consume:(id) NS_CONSUMED x;
+ (void) consume2:(id) CF_CONSUMED x;
@end

static int ownership_attribute_doesnt_go_here NS_RETURNS_RETAINED; // expected-warning{{'ns_returns_retained' only applies to function types; type here is 'int'}}

void test_attr_1(TestOwnershipAttr *X) {
  NSString *str = [X returnsAnOwnedString]; // expected-warning{{leak}}
}

void test_attr_1b(TestOwnershipAttr *X) {
  NSString *str = [X returnsAnOwnedCFString]; // expected-warning{{leak}}
}

void test_attr1c(TestOwnershipAttr *X) {
  NSString *str = [X newString]; // no-warning
  NSString *str2 = [X newStringNoAttr]; // expected-warning{{leak}}
  NSString *str3 = [X newString_auto]; // no-warning
  NSString *str4 = [[X newString_auto] retain]; // expected-warning {{leak}}
}

void testattr2_a(void) {
  TestOwnershipAttr *x = [TestOwnershipAttr alloc]; // expected-warning{{leak}}
}

void testattr2_b(void) {
  TestOwnershipAttr *x = [[TestOwnershipAttr alloc] pseudoInit];  // expected-warning{{leak}}
}

void testattr2_b_11358224_self_assign_looses_the_leak(void) {
  TestOwnershipAttr *x = [[TestOwnershipAttr alloc] pseudoInit];// expected-warning{{leak}}
  x = x;
}

void testattr2_c(void) {
  TestOwnershipAttr *x = [[TestOwnershipAttr alloc] pseudoInit]; // no-warning
  [x release];
}

void testattr3(void) {
  TestOwnershipAttr *x = [TestOwnershipAttr alloc]; // no-warning
  [TestOwnershipAttr consume:x];
  TestOwnershipAttr *y = [TestOwnershipAttr alloc]; // no-warning
  [TestOwnershipAttr consume2:y];
}

void consume_ns(id NS_CONSUMED x);
void consume_cf(id CF_CONSUMED x);

void testattr4(void) {
  TestOwnershipAttr *x = [TestOwnershipAttr alloc]; // no-warning
  consume_ns(x);
  TestOwnershipAttr *y = [TestOwnershipAttr alloc]; // no-warning
  consume_cf(y);
}

@interface TestOwnershipAttr2 : NSObject
- (NSString*) newString NS_RETURNS_NOT_RETAINED; // no-warning
@end

@implementation TestOwnershipAttr2
- (NSString*) newString {
  return [NSString alloc]; // expected-warning {{Potential leak of an object}}
}
@end

@interface MyClassTestCFAttr : NSObject {}
- (NSDate*) returnsCFRetained CF_RETURNS_RETAINED;
- (CFDateRef) returnsCFRetainedAsCF CF_RETURNS_RETAINED;
- (CFDateRef) newCFRetainedAsCF CF_RETURNS_NOT_RETAINED;
- (CFDateRef) newCFRetainedAsCFNoAttr;
- (NSDate*) alsoReturnsRetained;
- (CFDateRef) alsoReturnsRetainedAsCF;
- (NSDate*) returnsNSRetained NS_RETURNS_RETAINED;
@end

CF_RETURNS_RETAINED
CFDateRef returnsRetainedCFDate(void)  {
  return CFDateCreate(0, CFAbsoluteTimeGetCurrent());
}

@implementation MyClassTestCFAttr
- (NSDate*) returnsCFRetained {
  return (NSDate*) returnsRetainedCFDate(); // No leak.
}

- (CFDateRef) returnsCFRetainedAsCF {
  return returnsRetainedCFDate(); // No leak.
}

- (CFDateRef) newCFRetainedAsCF {
  return (CFDateRef)[(id)[self returnsCFRetainedAsCF] autorelease];
}

- (CFDateRef) newCFRetainedAsCFNoAttr {
  return (CFDateRef)[(id)[self returnsCFRetainedAsCF] autorelease]; // expected-warning{{Object with a +0 retain count returned to caller where a +1 (owning) retain count is expected}}
}

- (NSDate*) alsoReturnsRetained {
  return (NSDate*) returnsRetainedCFDate(); // expected-warning{{leak}}
}

- (CFDateRef) alsoReturnsRetainedAsCF {
  return returnsRetainedCFDate(); // expected-warning{{leak}}
}


- (NSDate*) returnsNSRetained {
  return (NSDate*) returnsRetainedCFDate(); // no-warning
}
@end

//===----------------------------------------------------------------------===//
// Test that leaks post-dominated by "panic" functions are not reported.
//
// Do not report a leak when post-dominated by a call to a noreturn or panic
// function.
//===----------------------------------------------------------------------===//
void panic(void) __attribute__((noreturn));
void panic_not_in_hardcoded_list(void) __attribute__((noreturn));

void test_panic_negative(void) {
  signed z = 1;
  CFNumberRef value = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &z);  // expected-warning{{leak}}
}

void test_panic_positive(void) {
  signed z = 1;
  CFNumberRef value = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &z); // no-warning
  panic();
}

void test_panic_neg_2(int x) {
  signed z = 1;
  CFNumberRef value = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &z); // expected-warning{{leak}}
  if (x)
    panic();
}

void test_panic_pos_2(int x) {
  signed z = 1;
  CFNumberRef value = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &z); // no-warning
  if (x)
    panic();
  if (!x) {
    // This showed up previously where we silently missed checking the function
    // type for noreturn.  "panic()" is a hard-coded known panic function that
    // isn't always noreturn.
    panic_not_in_hardcoded_list();
  }
}

//===----------------------------------------------------------------------===//
// Test uses of blocks (closures)
//===----------------------------------------------------------------------===//

void test_blocks_1_pos(void) {
  NSNumber *number = [[NSNumber alloc] initWithInt:5]; // expected-warning{{leak}}
  ^{}();
}

void test_blocks_1_indirect_release(void) {
  NSNumber *number = [[NSNumber alloc] initWithInt:5]; // no-warning
  ^{ [number release]; }();
}

void test_blocks_1_indirect_retain(void) {
  // Eventually this should be reported as a leak.
  NSNumber *number = [[NSNumber alloc] initWithInt:5]; // no-warning
  ^{ [number retain]; }();
}

void test_blocks_1_indirect_release_via_call(void) {
  NSNumber *number = [[NSNumber alloc] initWithInt:5]; // no-warning
  ^(NSObject *o){ [o release]; }(number);
}

void test_blocks_1_indirect_retain_via_call(void) {
  NSNumber *number = [[NSNumber alloc] initWithInt:5]; // expected-warning {{leak}}
  ^(NSObject *o){ [o retain]; }(number);
}

//===--------------------------------------------------------------------===//
// Test sending message to super that returns an object alias.  Previously
// this caused a crash in the analyzer.
//===--------------------------------------------------------------------===//

@interface Rdar8015556 : NSObject {} @end
@implementation Rdar8015556
- (id)retain {
  return [super retain];
}
@end

// Correcly handle Class<...> in Cocoa Conventions detector.
@protocol Prot_R8272168 @end
Class <Prot_R8272168> GetAClassThatImplementsProt_R8272168(void);
void r8272168(void) {
  GetAClassThatImplementsProt_R8272168();
}

// This used to trigger a false positive.
@interface RDar8356342
- (NSDate*) rdar8356342:(NSDate *)inValue;
@end

@implementation RDar8356342
- (NSDate*) rdar8356342:(NSDate*)inValue {
  NSDate *outValue = inValue;
  if (outValue == 0)
    outValue = [[NSDate alloc] init]; // no-warning

  if (outValue != inValue)
    [outValue autorelease];

  return outValue;
}
@end

// This test case previously crashed because of a bug in BugReporter.
extern const void *CFDictionaryGetValue(CFDictionaryRef theDict, const void *key);
typedef struct __CFError * CFErrorRef;
extern const CFStringRef kCFErrorUnderlyingErrorKey;
extern CFDictionaryRef CFErrorCopyUserInfo(CFErrorRef err);
static void rdar_8724287(CFErrorRef error)
{
    CFErrorRef error_to_dump;

    error_to_dump = error;
    while (error_to_dump != ((void*)0)) {
        CFDictionaryRef info;

        info = CFErrorCopyUserInfo(error_to_dump); // expected-warning{{Potential leak of an object}}

        if (info != ((void*)0)) {
        }

        error_to_dump = (CFErrorRef) CFDictionaryGetValue(info, kCFErrorUnderlyingErrorKey);
    }
}

// Make sure the model applies cf_consumed correctly in argument positions
// besides the first.
extern void *CFStringCreate(void);
extern void rdar_9234108_helper(void *key, void * CF_CONSUMED value);
void rdar_9234108(void) {
  rdar_9234108_helper(0, CFStringCreate());
}

// Make sure that objc_method_family works to override naming conventions.
struct TwoDoubles {
  double one;
  double two;
};
typedef struct TwoDoubles TwoDoubles;

@interface NSValue (Mine)
- (id)_prefix_initWithTwoDoubles:(TwoDoubles)twoDoubles __attribute__((objc_method_family(init)));
@end

@implementation NSValue (Mine)
- (id)_prefix_initWithTwoDoubles:(TwoDoubles)twoDoubles
{
  return [self init];
}
@end

void rdar9726279(void) {
  TwoDoubles twoDoubles = { 0.0, 0.0 };
  NSValue *value = [[NSValue alloc] _prefix_initWithTwoDoubles:twoDoubles];
  [value release];
}

// Test camelcase support for CF conventions.  While Core Foundation APIs
// don't use camel casing, other code is allowed to use it.
CFArrayRef camelcase_create_1(void) {
  return CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks); // no-warning
}

CFArrayRef camelcase_createno(void) {
  return CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks); // expected-warning {{leak}}
}

CFArrayRef camelcase_copy(void) {
  return CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks); // no-warning
}

CFArrayRef camelcase_copying(void) {
  return CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks); // expected-warning {{leak}}
}

CFArrayRef copyCamelCase(void) {
  return CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks); // no-warning
}

CFArrayRef __copyCamelCase(void) {
  return CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks); // no-warning
}

CFArrayRef __createCamelCase(void) {
  return CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks); // no-warning
}

CFArrayRef camel_create(void) {
  return CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks); // no-warning
}


CFArrayRef camel_creat(void) {
  return CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks); // expected-warning {{leak}}
}

CFArrayRef camel_copy(void) {
  return CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks); // no-warning
}

CFArrayRef camel_copyMachine(void) {
  return CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks); // no-warning
}

CFArrayRef camel_copymachine(void) {
  return CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks); // expected-warning {{leak}}
}

@protocol F18P
- (id) clone; // expected-note 2 {{method declared here}}
@end
@interface F18 : NSObject<F18P> @end
@interface F18(Cat)
- (id) clone NS_RETURNS_RETAINED; // expected-warning {{overriding method has mismatched ns_returns_retained attributes}}
@end

@implementation F18
- (id) clone { // expected-warning {{overriding method has mismatched ns_returns_retained attributes}}
  return [F18 alloc];
}
@end

void rdar6582778(void) {
  CFAbsoluteTime t = CFAbsoluteTimeGetCurrent();
  CFTypeRef vals[] = { CFDateCreate(0, t) }; // expected-warning {{leak}}
}

CFTypeRef global;

void rdar6582778_2(void) {
  CFAbsoluteTime t = CFAbsoluteTimeGetCurrent();
  global = CFDateCreate(0, t); // no-warning
}

// Test that objects passed to containers are marked "escaped".
void rdar10232019(void) {
  NSMutableArray *array = [NSMutableArray array];

  NSString *string = [[NSString alloc] initWithUTF8String:"foo"];
  [array addObject:string];
  [string release];

  NSString *otherString = [string stringByAppendingString:@"bar"]; // no-warning
  NSLog(@"%@", otherString);
}

void rdar10232019_positive(void) {
  NSMutableArray *array = [NSMutableArray array];

  NSString *string = [[NSString alloc] initWithUTF8String:"foo"];
  [string release];

  NSString *otherString = [string stringByAppendingString:@"bar"]; // expected-warning {{Reference-counted object is used after it is release}}
  NSLog(@"%@", otherString);
}

// RetainCountChecker support for XPC.
typedef void * xpc_object_t;
xpc_object_t _CFXPCCreateXPCObjectFromCFObject(CFTypeRef cf);
void xpc_release(xpc_object_t object);

void rdar9658496(void) {
  CFStringRef cf;
  xpc_object_t xpc;
  cf = CFStringCreateWithCString( ((CFAllocatorRef)0), "test", kCFStringEncodingUTF8 ); // no-warning
  xpc = _CFXPCCreateXPCObjectFromCFObject( cf );
  CFRelease(cf);
  xpc_release(xpc);
}

// Support annotations with method families.
@interface RDar10824732 : NSObject
- (id)initWithObj:(id CF_CONSUMED)obj;
@end

@implementation RDar10824732
- (id)initWithObj:(id)obj {
  [obj release];
  return [super init];
}
@end

void rdar_10824732(void) {
  @autoreleasepool {
    NSString *obj = @"test";
    RDar10824732 *foo = [[RDar10824732 alloc] initWithObj:obj]; // no-warning
    [foo release];
  }
}

// Stop tracking objects passed to functions, which take callbacks as parameters.
// radar://10973977
typedef int (*CloseCallback) (void *);
void ReaderForIO(CloseCallback ioclose, void *ioctx);
int IOClose(void *context);

@protocol SInS <NSObject>
@end

@interface radar10973977 : NSObject
- (id<SInS>)inputS;
- (void)reader;
@end

@implementation radar10973977
- (void)reader
{
    id<SInS> inputS = [[self inputS] retain];
    ReaderForIO(IOClose, inputS);
}
- (id<SInS>)inputS
{
    return 0;
}
@end

// Object escapes through a selector callback: radar://11398514
extern id NSApp;
@interface MySheetController
- (id<SInS>)inputS;
- (void)showDoSomethingSheetAction:(id)action;
- (void)sheetDidEnd:(NSWindow *)sheet returnCode:(int)returnCode contextInfo:(void *)contextInfo;
@end

@implementation MySheetController
- (id<SInS>)inputS {
    return 0;
}
- (void)showDoSomethingSheetAction:(id)action {
  id<SInS> inputS = [[self inputS] retain]; 
  [NSApp beginSheet:0
         modalForWindow:0
         modalDelegate:0
         didEndSelector:@selector(sheetDidEnd:returnCode:contextInfo:)
         contextInfo:(void *)inputS]; // no - warning
}
- (void)sheetDidEnd:(NSWindow *)sheet returnCode:(int)returnCode contextInfo:(void *)contextInfo {
   
      id contextObject = (id)contextInfo;
      [contextObject release];
}

- (id)copyAutoreleaseRadar13081402 {
  id x = [[[NSString alloc] initWithUTF8String:"foo"] autorelease];
  [x retain];
  return x; // no warning
}

@end
//===----------------------------------------------------------------------===//
// Test returning allocated memory in a struct.
//
// We currently don't have a general way to track pointers that "escape".
// Here we test that RetainCountChecker doesn't get excited about returning
// allocated CF objects in struct fields.
//===----------------------------------------------------------------------===//
void *malloc(size_t);
struct rdar11104566 { CFStringRef myStr; };
struct rdar11104566 test_rdar11104566(void) {
  CFStringRef cf = CFStringCreateWithCString( ((CFAllocatorRef)0), "test", kCFStringEncodingUTF8 ); // no-warning
  struct rdar11104566 V;
  V.myStr = cf;
  return V; // no-warning
}

struct rdar11104566 *test_2_rdar11104566(void) {
  CFStringRef cf = CFStringCreateWithCString( ((CFAllocatorRef)0), "test", kCFStringEncodingUTF8 ); // no-warning
  struct rdar11104566 *V = (struct rdar11104566 *) malloc(sizeof(*V));
  V->myStr = cf;
  return V; // no-warning
}

//===----------------------------------------------------------------------===//
// ObjC literals support.
//===----------------------------------------------------------------------===//

void test_objc_arrays(void) {
    { // CASE ONE -- OBJECT IN ARRAY CREATED DIRECTLY
        NSObject *o = [[NSObject alloc] init];
        NSArray *a = [[NSArray alloc] initWithObjects:o, (void*)0]; // expected-warning {{leak}}
        [o release];
        [a description];
        [o description];
    }

    { // CASE TWO -- OBJECT IN ARRAY CREATED BY DUPING AUTORELEASED ARRAY
        NSObject *o = [[NSObject alloc] init];
        NSArray *a1 = [NSArray arrayWithObjects:o, (void*)0];
        NSArray *a2 = [[NSArray alloc] initWithArray:a1]; // expected-warning {{leak}}
        [o release];        
        [a2 description];
        [o description];
    }

    { // CASE THREE -- OBJECT IN RETAINED @[]
        NSObject *o = [[NSObject alloc] init];
        NSArray *a3 = [@[o] retain]; // expected-warning {{leak}}
        [o release];        
        [a3 description];
        [o description];
    }
    
    { // CASE FOUR -- OBJECT IN ARRAY CREATED BY DUPING @[]
        NSObject *o = [[NSObject alloc] init];
        NSArray *a = [[NSArray alloc] initWithArray:@[o]]; // expected-warning {{leak}}
        [o release];
        
        [a description];
        [o description];
    }
    
    { // CASE FIVE -- OBJECT IN RETAINED @{}
        NSValue *o = [[NSValue alloc] init];
        NSDictionary *a = [@{o : o} retain]; // expected-warning {{leak}}
        [o release];
        
        [a description];
        [o description];
    }
}

void test_objc_integer_literals(void) {
  id value = [@1 retain]; // expected-warning {{leak}}
  [value description];
}

void test_objc_boxed_expressions(int x, const char *y) {
  id value = [@(x) retain]; // expected-warning {{leak}}
  [value description];

  value = [@(y) retain]; // expected-warning {{leak}}
  [value description];
}

// Test NSLog doesn't escape tracked objects.
void rdar11400885(int y)
{
  @autoreleasepool {
    NSString *printString;
    if(y > 2)
      printString = [[NSString alloc] init];
    else
      printString = [[NSString alloc] init];
    NSLog(@"Once %@", printString);
    [printString release];
    NSLog(@"Again: %@", printString); // expected-warning {{Reference-counted object is used after it is released}}
  }
}

id makeCollectableNonLeak(void) {
  extern CFTypeRef CFCreateSomething(void);

  CFTypeRef object = CFCreateSomething(); // +1
  CFRetain(object); // +2
  id objCObject = NSMakeCollectable(object); // +2
  [objCObject release]; // +1
  return [objCObject autorelease]; // +0
}

void consumeAndStopTracking(id NS_CONSUMED obj, void (^callback)(void));
void CFConsumeAndStopTracking(CFTypeRef CF_CONSUMED obj, void (^callback)(void));

void testConsumeAndStopTracking(void) {
  id retained = [@[] retain]; // +1
  consumeAndStopTracking(retained, ^{}); // no-warning

  id doubleRetained = [[@[] retain] retain]; // +2
  consumeAndStopTracking(doubleRetained, ^{
    [doubleRetained release];
  }); // no-warning

  id unretained = @[]; // +0
  consumeAndStopTracking(unretained, ^{}); // expected-warning {{Incorrect decrement of the reference count of an object that is not owned at this point by the caller}}
}

void testCFConsumeAndStopTracking(void) {
  id retained = [@[] retain]; // +1
  CFConsumeAndStopTracking((CFTypeRef)retained, ^{}); // no-warning

  id doubleRetained = [[@[] retain] retain]; // +2
  CFConsumeAndStopTracking((CFTypeRef)doubleRetained, ^{
    [doubleRetained release];
  }); // no-warning

  id unretained = @[]; // +0
  CFConsumeAndStopTracking((CFTypeRef)unretained, ^{}); // expected-warning {{Incorrect decrement of the reference count of an object that is not owned at this point by the caller}}
}
//===----------------------------------------------------------------------===//
// Test 'pragma clang arc_cf_code_audited' support.
//===----------------------------------------------------------------------===//

typedef void *MyCFType;
#pragma clang arc_cf_code_audited begin
MyCFType CreateMyCFType(void);
#pragma clang arc_cf_code_audited end 
    
void test_custom_cf(void) {
  MyCFType x = CreateMyCFType(); // expected-warning {{leak of an object stored into 'x'}}
}

//===----------------------------------------------------------------------===//
// Test calling CFPlugInInstanceCreate, which appears in CF but doesn't
// return a CF object.
//===----------------------------------------------------------------------===//

void test_CFPlugInInstanceCreate(CFUUIDRef factoryUUID, CFUUIDRef typeUUID) {
  CFPlugInInstanceCreate(kCFAllocatorDefault, factoryUUID, typeUUID); // no-warning
}

//===----------------------------------------------------------------------===//
// PR14927: -drain only has retain-count semantics on NSAutoreleasePool.
//===----------------------------------------------------------------------===//

@interface PR14927 : NSObject
- (void)drain;
@end

void test_drain(void) {
  PR14927 *obj = [[PR14927 alloc] init];
  [obj drain];
  [obj release]; // no-warning
}

//===----------------------------------------------------------------------===//
// Allow cf_returns_retained and cf_returns_not_retained to mark a return
// value as tracked, even if the object isn't a known CF type.
//===----------------------------------------------------------------------===//

MyCFType getCustom(void) __attribute__((cf_returns_not_retained));
MyCFType makeCustom(void) __attribute__((cf_returns_retained));

void testCustomReturnsRetained(void) {
  MyCFType obj = makeCustom(); // expected-warning {{leak of an object stored into 'obj'}}
}

void testCustomReturnsNotRetained(void) {
  CFRelease(getCustom()); // expected-warning {{Incorrect decrement of the reference count of an object that is not owned at this point by the caller}}
}

//===----------------------------------------------------------------------===//
// Don't print variables which are out of the current scope.
//===----------------------------------------------------------------------===//
@interface MyObj12706177 : NSObject
-(id)initX;
+(void)test12706177;
@end
static int Cond;
@implementation MyObj12706177
-(id)initX {
  if (Cond)
    return 0;
  self = [super init];
  return self;
}
+(void)test12706177 {
  id x = [[MyObj12706177 alloc] initX]; //expected-warning {{Potential leak of an object}}
  [x release]; 
}
@end

//===----------------------------------------------------------------------===//
// CFAutorelease
//===----------------------------------------------------------------------===//

CFTypeRef getAutoreleasedCFType(void) {
  extern CFTypeRef CFCreateSomething(void);
  return CFAutorelease(CFCreateSomething()); // no-warning
}

CFTypeRef getIncorrectlyAutoreleasedCFType(void) {
  extern CFTypeRef CFGetSomething(void);
  return CFAutorelease(CFGetSomething()); // expected-warning{{Object autoreleased too many times}}
}

CFTypeRef createIncorrectlyAutoreleasedCFType(void) {
  extern CFTypeRef CFCreateSomething(void);
  return CFAutorelease(CFCreateSomething()); // expected-warning{{Object with a +0 retain count returned to caller where a +1 (owning) retain count is expected}}
}

void useAfterAutorelease(void) {
  extern CFTypeRef CFCreateSomething(void);
  CFTypeRef obj = CFCreateSomething();
  CFAutorelease(obj);

  extern void useCF(CFTypeRef);
  useCF(obj); // no-warning
}

void useAfterRelease(void) {
  // Verify that the previous example would have warned with CFRelease.
  extern CFTypeRef CFCreateSomething(void);
  CFTypeRef obj = CFCreateSomething();
  CFRelease(obj);

  extern void useCF(CFTypeRef);
  useCF(obj); // expected-warning{{Reference-counted object is used after it is released}}
}

void testAutoreleaseReturnsInput(void) {
  extern CFTypeRef CFCreateSomething(void);
  CFTypeRef obj = CFCreateSomething(); // expected-warning{{Potential leak of an object stored into 'second'}}
  CFTypeRef second = CFAutorelease(obj);
  CFRetain(second);
}

CFTypeRef testAutoreleaseReturnsInputSilent(void) {
  extern CFTypeRef CFCreateSomething(void);
  CFTypeRef obj = CFCreateSomething();
  CFTypeRef alias = CFAutorelease(obj);
  CFRetain(alias);
  CFRelease(obj);
  return obj; // no-warning
}

void autoreleaseTypedObject(void) {
  CFArrayRef arr = CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks);
  CFAutorelease((CFTypeRef)arr); // no-warning
}

void autoreleaseReturningTypedObject(void) {
  CFArrayRef arr = CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks); // expected-warning{{Potential leak of an object stored into 'alias'}}
  CFArrayRef alias = (CFArrayRef)CFAutorelease((CFTypeRef)arr);
  CFRetain(alias);
}

CFArrayRef autoreleaseReturningTypedObjectSilent(void) {
  CFArrayRef arr = CFArrayCreateMutable(0, 10, &kCFTypeArrayCallBacks);
  CFArrayRef alias = (CFArrayRef)CFAutorelease((CFTypeRef)arr);
  CFRetain(alias);
  CFRelease(arr);
  return alias; // no-warning
}

void autoreleaseObjC(void) {
  id obj = [@1 retain];
  CFAutorelease(obj); // no-warning

  id anotherObj = @1;
  CFAutorelease(anotherObj);
} // expected-warning{{Object autoreleased too many times}}

//===----------------------------------------------------------------------===//
// xpc_connection_set_finalizer_f
//===----------------------------------------------------------------------===//
typedef xpc_object_t xpc_connection_t;
typedef void (*xpc_finalizer_t)(void *value);
void xpc_connection_set_context(xpc_connection_t connection, void *ctx);
void xpc_connection_set_finalizer_f(xpc_connection_t connection,
                                    xpc_finalizer_t finalizer);
void releaseAfterXPC(void *context) {
  [(NSArray *)context release];
}

void rdar13783514(xpc_connection_t connection) {
  xpc_connection_set_context(connection, [[NSMutableArray alloc] init]);
  xpc_connection_set_finalizer_f(connection, releaseAfterXPC);
} // no-warning

// Do not report leaks when object is cleaned up with __attribute__((cleanup ..)).
inline static void cleanupFunction(void *tp) {
    CFTypeRef x = *(CFTypeRef *)tp;
    if (x) {
        CFRelease(x);
    }
}
#define ADDCLEANUP __attribute__((cleanup(cleanupFunction)))
void foo(void) {
  ADDCLEANUP CFStringRef myString;
  myString = CFStringCreateWithCString(0, "hello world", kCFStringEncodingUTF8);
  ADDCLEANUP CFStringRef myString2 = 
    CFStringCreateWithCString(0, "hello world", kCFStringEncodingUTF8);
}

//===----------------------------------------------------------------------===//
// Handle NSNull
//===----------------------------------------------------------------------===//

__attribute__((ns_returns_retained))
id returnNSNull(void) {
  return [NSNull null]; // no-warning
}

//===----------------------------------------------------------------------===//
// cf_returns_[not_]retained on parameters
//===----------------------------------------------------------------------===//

void testCFReturnsNotRetained(void) {
  extern void getViaParam(CFTypeRef * CF_RETURNS_NOT_RETAINED outObj);
  CFTypeRef obj;
  getViaParam(&obj);
  CFRelease(obj); // // expected-warning {{Incorrect decrement of the reference count of an object that is not owned at this point by the caller}}
}

void testCFReturnsNotRetainedAnnotated(void) {
  extern void getViaParam2(CFTypeRef * _Nonnull CF_RETURNS_NOT_RETAINED outObj);
  CFTypeRef obj;
  getViaParam2(&obj);
  CFRelease(obj); // // expected-warning {{Incorrect decrement of the reference count of an object that is not owned at this point by the caller}}
}

void testCFReturnsRetained(void) {
  extern int copyViaParam(CFTypeRef * CF_RETURNS_RETAINED outObj);
  CFTypeRef obj;
  copyViaParam(&obj);
  CFRelease(obj);
  CFRelease(obj); // // FIXME-warning {{Incorrect decrement of the reference count of an object that is not owned at this point by the caller}}
}

void testCFReturnsRetainedError(void) {
  extern int copyViaParam(CFTypeRef * CF_RETURNS_RETAINED outObj);
  CFTypeRef obj;
  if (copyViaParam(&obj) == -42)
    return; // no-warning
  CFRelease(obj);
}
