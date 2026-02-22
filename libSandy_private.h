#if defined(__cplusplus)
extern "C" {
#endif

#include <xpc/xpc.h>

#ifndef kCFCoreFoundationVersionNumber_iOS_16_0
#define kCFCoreFoundationVersionNumber_iOS_16_0 1932.101
#endif

#define SANDY_PROXY_IDENTIFER "com.apple.securityd"
XPC_EXPORT mach_port_t _xpc_dictionary_extract_mach_send(xpc_object_t xdict, const char* key);

#define	BOOTSTRAP_MAX_NAME_LEN			128
#define	BOOTSTRAP_MAX_CMD_LEN			512

typedef char name_t[BOOTSTRAP_MAX_NAME_LEN];
typedef char cmd_t[BOOTSTRAP_MAX_CMD_LEN];
typedef name_t *name_array_t;
kern_return_t bootstrap_look_up(
		mach_port_t bp,
		const name_t service_name,
		mach_port_t *sp);

#if defined(__cplusplus)
}
#endif