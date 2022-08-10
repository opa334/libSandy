#import <stdbool.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define kLibSandySuccess 0
#define kLibSandyErrorXPCFailure 1
#define kLibSandyErrorRestricted 2

extern int libSandy_applyProfile(const char* profileName);
extern bool libSandy_works(void);

#if defined(__cplusplus)
}
#endif