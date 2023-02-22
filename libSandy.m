#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <xpc/xpc.h>
#import "sandbox.h"
#import "HBLogWeak.h"
#import "libSandy.h"

#define LIBSANDY_XPC_TIMEOUT 0.1 * NSEC_PER_SEC

extern char ***_NSGetArgv();
static NSString *safe_getExecutablePath()
{
	char *executablePathC = **_NSGetArgv();
	return [NSString stringWithUTF8String:executablePathC];
}

// calling libSandy functions from inside MobileGestaltHelper itself locks the system up so we need to prevent it
static BOOL isRunningInsideMobileGestaltHelper()
{
	static BOOL isMgh;
	static dispatch_once_t onceToken;
	dispatch_once (&onceToken, ^{
		isMgh = [safe_getExecutablePath().lastPathComponent isEqualToString:@"MobileGestaltHelper"];
	});
	return isMgh;
}

int libSandy_applyProfile(const char *profileName)
{
	if (isRunningInsideMobileGestaltHelper()) return 0;

	HBLogDebugWeak(@"[libSandy libSandy_applyProfile] attempting to apply profile %s", profileName);

	xpc_connection_t mgConnection = xpc_connection_create_mach_service("com.apple.mobilegestalt.xpc", 0, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
	xpc_connection_set_event_handler(mgConnection, ^(xpc_object_t object){});
	xpc_connection_resume(mgConnection);

	xpc_object_t getExtensionsMessage = xpc_dictionary_create(NULL,NULL,0);
	xpc_dictionary_set_bool(getExtensionsMessage, "libSandy_isProfileMessage", YES);
	xpc_dictionary_set_string(getExtensionsMessage, "profile", profileName);

	__block int returnCode = kLibSandyErrorXPCFailure;
	dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

	xpc_connection_send_message_with_reply(mgConnection, getExtensionsMessage, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^(xpc_object_t reply) {
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
							__unused int64_t suc = sandbox_extension_consume(ext);
							HBLogDebugWeak(@"[libSandy libSandy_applyProfile] Consumed extension (%s) -> %lld", ext, suc);
						}
						return true;
					});
				}
			}
		}

		dispatch_semaphore_signal(semaphore);
	});

	dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, LIBSANDY_XPC_TIMEOUT));
	
	HBLogDebugWeak(@"[libSandy libSandy_applyProfile] applied profile %s => %d", profileName, returnCode);

	return returnCode;
}

bool libSandy_works()
{
	if (isRunningInsideMobileGestaltHelper()) return YES;

	xpc_connection_t mgConnection = xpc_connection_create_mach_service("com.apple.mobilegestalt.xpc", 0, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
	xpc_connection_set_event_handler(mgConnection, ^(xpc_object_t object){});
	xpc_connection_resume(mgConnection);

	xpc_object_t testMessage = xpc_dictionary_create(NULL,NULL,0);
	xpc_dictionary_set_bool(testMessage, "libSandy_isTestMessage", YES);

	__block bool returnCode = false;
	dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

	xpc_connection_send_message_with_reply(mgConnection, testMessage, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^(xpc_object_t reply) {
		if (reply) {
			xpc_type_t replyType = xpc_get_type(reply);
			if (replyType == XPC_TYPE_DICTIONARY) {
				returnCode = xpc_dictionary_get_bool(reply, "works");
			}
		}
	});
	dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, LIBSANDY_XPC_TIMEOUT));

	return returnCode;
}