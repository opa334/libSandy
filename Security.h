#import <mach/mach.h>
#import <xpc/xpc.h>

typedef struct __SecTask {
} SecTask;


extern void xpc_connection_get_audit_token(xpc_object_t connection, audit_token_t* auditToken);
extern CFStringRef SecTaskCopySigningIdentifier(struct __SecTask* task, CFErrorRef* error);
extern struct __SecTask* SecTaskCreateWithAuditToken(CFAllocatorRef allocator, audit_token_t token);
extern xpc_object_t xpc_array_create_empty(void);