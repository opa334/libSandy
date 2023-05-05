#import <sandbox_private.h>

char *compat_sandbox_extension_issue_file_to_process(const char *extension_class, const char *path, uint32_t flags, audit_token_t audit_token);
char *compat_sandbox_extension_issue_generic_to_process(const char *extension_class, uint32_t flags, audit_token_t audit_token);
char *compat_sandbox_extension_issue_iokit_registry_entry_class_to_process(const char *extension_class, const char *registry_entry_class, uint32_t flags, audit_token_t audit_token);
char *compat_sandbox_extension_issue_mach_to_process(const char *extension_class, const char *name, uint32_t flags, audit_token_t audit_token);

void initSandboxCompatibilityLayer(void);