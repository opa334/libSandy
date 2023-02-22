#import <HBLog.h>
#ifdef __DEBUG__
#define HBLogDebugWeak(args ...) HBLogDebug(args)
#else
#define HBLogDebugWeak(...)
#endif