#import "sandbox_compat.h"

#import <dlfcn.h>
#import <substrate.h>
#import <Foundation/Foundation.h>

char* (*__sandbox_extension_issue_file)(const char *extension_class, const char *path, uint32_t flags);
char* (*__sandbox_extension_issue_file_to_process)(const char *extension_class, const char *path, uint32_t flags, audit_token_t);

char* (*__sandbox_extension_issue_generic)(const char *extension_class, uint32_t flags);
char* (*__sandbox_extension_issue_generic_to_process)(const char *extension_class, uint32_t flags, audit_token_t);

char* (*__sandbox_extension_issue_iokit_registry_entry_class)(const char *extension_class, const char *registry_entry_class, uint32_t flags);
char* (*__sandbox_extension_issue_iokit_registry_entry_class_to_process)(const char *extension_class, const char *registry_entry_class, uint32_t flags, audit_token_t);

char* (*__sandbox_extension_issue_mach)(const char *extension_class, const char *name, uint32_t flags);
char* (*__sandbox_extension_issue_mach_to_process)(const char *extension_class, const char *name, uint32_t flags, audit_token_t);

char* compat_sandbox_extension_issue_file_to_process(const char *extension_class, const char *path, uint32_t flags, audit_token_t audit_token)
{
	if(__sandbox_extension_issue_file_to_process) {
		return __sandbox_extension_issue_file_to_process(extension_class, path, flags, audit_token);
	}
	else {
		return __sandbox_extension_issue_file(extension_class, path, flags);
	}
}

char* compat_sandbox_extension_issue_generic_to_process(const char *extension_class, uint32_t flags, audit_token_t audit_token)
{
	if(__sandbox_extension_issue_generic_to_process) {
		return __sandbox_extension_issue_generic_to_process(extension_class, flags, audit_token);
	}
	else {
		return __sandbox_extension_issue_generic(extension_class, flags);
	}
}

char* compat_sandbox_extension_issue_iokit_registry_entry_class_to_process(const char *extension_class, const char *registry_entry_class, uint32_t flags, audit_token_t audit_token)
{
	if(__sandbox_extension_issue_generic_to_process) {
		return __sandbox_extension_issue_iokit_registry_entry_class_to_process(extension_class, registry_entry_class, flags, audit_token);
	}
	else {
		return __sandbox_extension_issue_iokit_registry_entry_class(extension_class, registry_entry_class, flags);
	}
}

char* compat_sandbox_extension_issue_mach_to_process(const char *extension_class, const char *name, uint32_t flags, audit_token_t audit_token)
{
	if(__sandbox_extension_issue_mach_to_process) {
		return __sandbox_extension_issue_mach_to_process(extension_class, name, flags, audit_token);
	}
	else {
		return __sandbox_extension_issue_mach(extension_class, name, SANDBOX_EXTENSION_CANONICAL);
	}
}

// this was an attempt at getting the system to issue preference domain extensions but it doesn't seem to work
/*char* sandbox_extension_issue_custom(const char* class, uint32_t type, const char* data, uint32_t flags, int64_t pid, int64_t pidver)
{
	char* out = malloc(0x800);

	struct syscall_extension_issue_args args;
	args.extension_class = (uint64_t)class;
	args.extension_type = type;
	args.extension_data = (uint64_t)data;
	args.extension_flags = flags;
	args.extension_token = (uint64_t)out;
	args.extension_pid = pid;
	args.extension_pid_version = pidver;

	__sandbox_ms("Sandbox", 5, (void*)&args);

	return out;
}

char* compat_sandbox_extension_issue_preference(const char* extension_class, const char* preference_domain, uint32_t flags)
{
	NSLog(@"compat_sandbox_extension_issue_preference(%s, %s, %u)", extension_class, preference_domain, flags);
	return sandbox_extension_issue_custom(extension_class, EXTENSION_TYPE_PREFERENCE, preference_domain, flags & 0xFFFCFFFF, 0, 0);
}*/

void initSandboxCompatibilityLayer(void)
{
	void* libSystemSandboxHandle = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_NOW);
	
	__sandbox_extension_issue_file = dlsym(libSystemSandboxHandle, "sandbox_extension_issue_file");
	__sandbox_extension_issue_file_to_process = dlsym(libSystemSandboxHandle, "sandbox_extension_issue_file_to_process");

	__sandbox_extension_issue_generic = dlsym(libSystemSandboxHandle, "sandbox_extension_issue_generic");
	__sandbox_extension_issue_generic_to_process = dlsym(libSystemSandboxHandle, "sandbox_extension_issue_generic_to_process");

	__sandbox_extension_issue_iokit_registry_entry_class = dlsym(libSystemSandboxHandle, "sandbox_extension_issue_iokit_registry_entry_class");
	__sandbox_extension_issue_iokit_registry_entry_class_to_process = dlsym(libSystemSandboxHandle, "sandbox_extension_issue_iokit_registry_entry_class_to_process");

	__sandbox_extension_issue_mach = dlsym(libSystemSandboxHandle, "sandbox_extension_issue_mach");
	__sandbox_extension_issue_mach_to_process = dlsym(libSystemSandboxHandle, "sandbox_extension_issue_mach_to_process");
}