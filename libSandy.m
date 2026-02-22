#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <xpc/xpc.h>
#import <mach-o/dyld.h>
#import <sandbox_private.h>
#import <libroot.h>
#import <sandyd.h>
#import <substrate.h>
#import "HBLogWeak.h"
#import "libSandy.h"
#import "libSandy_private.h"

bool gProcNeedsRedirection = false;
NSMutableSet *gMachServicesToRedirect = nil;

static void enableMachRedirection(void);
static void redirectMachIdentifier(NSString *identifier);
xpc_object_t sandyProxySendMessage(xpc_object_t message);
xpc_object_t sandydSendMessage(xpc_object_t message);
int64_t libSandy_customLookup(xpc_object_t xmsg, xpc_object_t *xreply);
int64_t sandyProxy_customLookup(xpc_object_t xmsg, xpc_object_t *xreply);

NSString *safe_getExecutablePath()
{
	char executablePathC[PATH_MAX];
	uint32_t executablePathCSize = sizeof(executablePathC);
	_NSGetExecutablePath(&executablePathC[0], &executablePathCSize);
	return [NSString stringWithUTF8String:executablePathC];
}

// calling libSandy functions from inside sandyd itself locks the system up so we need to prevent it
static BOOL isRunningInsideSandyd()
{
	static BOOL isSandyd;
	static dispatch_once_t onceToken;
	dispatch_once (&onceToken, ^{
		isSandyd = [safe_getExecutablePath().lastPathComponent isEqualToString:@"sandyd"];
	});
	return isSandyd;
}

static BOOL sandydCommunicationWorks(void)
{
	if (sandbox_check(getpid(), "mach-lookup", SANDBOX_FILTER_GLOBAL_NAME | SANDBOX_CHECK_NO_REPORT, "com.opa334.sandyd") == 0) return true;

	// iOS 18.4+: sandbox_check with mach-lookup doesn't work anymore and just returns non zero even if sandyd is reachable
	// If you're an apple employee reading this: fuck you
	mach_port_t sandydPort = MACH_PORT_NULL;
	int r = bootstrap_look_up(mach_task_self(), "com.opa334.sandyd", &sandydPort);
	bool suc = MACH_PORT_VALID(sandydPort) && r == 0;
	if (sandydPort != MACH_PORT_NULL) mach_port_mod_refs(mach_task_self(), sandydPort, MACH_PORT_RIGHT_SEND, -1);
	return suc;
}

bool consumeSandydGlobalExtensions(void)
{
	if (!sandydCommunicationWorks()) {
		NSString *plistPath = JBROOT_PATH_NSSTRING(@"/usr/lib/sandyd_global.plist");
		if (![[NSFileManager defaultManager] fileExistsAtPath:plistPath]) {
			NSLog(@"[libSandy consumeSandydGlobalExtensions] FATAL ERROR: %@ does not exist", plistPath);
			return NO;
		}
		NSDictionary *plistDict = [NSDictionary dictionaryWithContentsOfFile:plistPath];
		if (!plistDict) {
			NSLog(@"[libSandy consumeSandydGlobalExtensions] FATAL ERROR: Unable to read %@", plistPath);
			return NO;
		}
		NSArray *extensions = plistDict[@"extensions"];
		if (!extensions) {
			NSLog(@"[libSandy consumeSandydGlobalExtensions] FATAL ERROR: No extensions found in %@", plistPath);
			return NO;
		}
		for (NSString *extension in extensions) {
			__unused int cr = sandbox_extension_consume(extension.UTF8String);
			HBLogDebugWeak(@"[libSandy consumeSandydGlobalExtensions] sandbox_extension_consume(\"%s\") => %d", extension.UTF8String, cr);
		}

		if (kCFCoreFoundationVersionNumber < kCFCoreFoundationVersionNumber_iOS_16_0) return NO;
		if (!sandydCommunicationWorks()) {
			NSLog(@"[libSandy consumeSandydGlobalExtensions] communication still does not work, even after consuming sandbox extensions, enabling redirection...");
			enableMachRedirection();
			return sandydCommunicationWorks();
		}
	}
	return YES;
}

int libSandy_applyProfile(const char *profileName)
{
	if (isRunningInsideSandyd()) return 0;

	HBLogDebugWeak(@"[libSandy libSandy_applyProfile] attempting to apply profile %s", profileName);

	xpc_object_t getExtensionsMessage = xpc_dictionary_create(NULL, NULL, 0);
	xpc_dictionary_set_int64(getExtensionsMessage, "id", SANDYD_MESSAGE_GET_PROFILE_EXTENSIONS);
	xpc_dictionary_set_string(getExtensionsMessage, "profile", profileName);

	__block int returnCode = kLibSandyErrorXPCFailure;
	xpc_object_t reply = sandydSendMessage(getExtensionsMessage);
	if (reply) {
		xpc_type_t replyType = xpc_get_type(reply);
		HBLogDebugWeak(@"[libSandy libSandy_applyProfile] got reply %s", xpc_copy_description(reply));
		if (replyType == XPC_TYPE_DICTIONARY) {
			xpc_object_t extensions = xpc_dictionary_get_value(reply, "extensions");
			xpc_type_t extensionsType = xpc_get_type(extensions);
			if (extensionsType == XPC_TYPE_ARRAY) {
				HBLogDebugWeak(@"[libSandy libSandy_applyProfile] got extensions %s", xpc_copy_description(extensions));
				returnCode = kLibSandyErrorRestricted;
				xpc_array_apply(extensions, ^bool(size_t index, xpc_object_t value) {
					if (xpc_get_type(value) == XPC_TYPE_STRING) {
						returnCode = kLibSandySuccess; // if returned extensions has one or more tokens: SUCCESS
						const char *ext = xpc_string_get_string_ptr(value);
						if (gProcNeedsRedirection && (strstr(ext, ";com.apple.app-sandbox.mach;") || strstr(ext, ";com.apple.security.exception.mach-lookup.global-name;"))) {
							HBLogDebugWeak(@"[libSandy libSandy_applyProfile] Mach extensions aren't permitted by this processes sandbox profile, adding to fixup array instead... (%s)", ext);
							redirectMachIdentifier([[NSString stringWithUTF8String:ext] componentsSeparatedByString:@";"].lastObject);
						}
						else {
							__unused int64_t suc = sandbox_extension_consume(ext);
							HBLogDebugWeak(@"[libSandy libSandy_applyProfile] Consumed extension (%s) -> %lld", ext, suc);
						}
					}
					return true;
				});
			}
		}
	}

	HBLogDebugWeak(@"[libSandy libSandy_applyProfile] applied profile %s => %d", profileName, returnCode);

	return returnCode;
}

bool libSandy_works()
{
	if (isRunningInsideSandyd()) return YES;

	xpc_object_t testMessage = xpc_dictionary_create(NULL, NULL, 0);
	xpc_dictionary_set_int64(testMessage, "id", SANDYD_MESSAGE_TEST_CONNECTION);

	bool returnCode = false;
	xpc_object_t reply = sandydSendMessage(testMessage);
	if (reply) {
		xpc_type_t replyType = xpc_get_type(reply);
		if (replyType == XPC_TYPE_DICTIONARY) {
			returnCode = xpc_dictionary_get_bool(reply, "works");
		}
	}

	return returnCode;
}

static void enableMachRedirection(void)
{
	static dispatch_once_t onceToken;
	dispatch_once (&onceToken, ^{
		gProcNeedsRedirection = true;
		gMachServicesToRedirect = [NSMutableSet new];

		MSImageRef xpcImage = MSGetImageByName("/usr/lib/system/libxpc.dylib");
		void *_xpc_interface_routine = MSFindSymbol(xpcImage, "__xpc_interface_routine");
		extern int64_t (*_xpc_interface_routine_orig)(int msgid, xpc_object_t xmsg, xpc_object_t *xreply, void *a4, void *a5);
		extern int64_t _xpc_interface_routine_hook(int msgid, xpc_object_t xmsg, xpc_object_t *xreply, void *a4, void *a5);
		MSHookFunction(_xpc_interface_routine, (void *)_xpc_interface_routine_hook, (void **)&_xpc_interface_routine_orig);
	});
}

static void redirectMachIdentifier(NSString *identifier)
{
	[gMachServicesToRedirect addObject:identifier];
}

bool isMachIdentifierRedirected(const char *identifier)
{
	return [gMachServicesToRedirect containsObject:[NSString stringWithUTF8String:identifier]];
}