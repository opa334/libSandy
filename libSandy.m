#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <xpc/xpc.h>
#import <sandbox_private.h>
#import <rootless.h>
#import <sandyd.h>
#import "HBLogWeak.h"
#import "libSandy.h"

static bool sandydCommunicationWorkedOnce = NO;

extern char ***_NSGetArgv();
static NSString *safe_getExecutablePath()
{
	char *executablePathC = **_NSGetArgv();
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

static BOOL consumeGlobalExtensions(void)
{
	if (!sandydCommunicationWorkedOnce) {
		NSString *plistPath = ROOT_PATH_NS(@"/usr/lib/sandyd_global.plist");
		if (![[NSFileManager defaultManager] fileExistsAtPath:plistPath]) return NO;
		NSDictionary *plistDict = [NSDictionary dictionaryWithContentsOfFile:plistPath];
		if (!plistDict) return NO;
		NSArray *extensions = plistDict[@"extensions"];
		if (!extensions) return NO;
		for (NSString *extension in extensions) {
			sandbox_extension_consume(extension.UTF8String);
		}
	}
	return YES;
}

static xpc_object_t sandydSendMessage(xpc_object_t message)
{
	if (!consumeGlobalExtensions()) return nil;

	xpc_connection_t connection = xpc_connection_create_mach_service("com.opa334.sandyd", 0, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
	xpc_connection_set_event_handler(connection, ^(xpc_object_t object){});
	xpc_connection_resume(connection);

	xpc_connection_t reply = xpc_connection_send_message_with_reply_sync(connection, message);
	if (reply) sandydCommunicationWorkedOnce = YES;
	return reply;
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
						__unused int64_t suc = sandbox_extension_consume(ext);
						HBLogDebugWeak(@"[libSandy libSandy_applyProfile] Consumed extension (%s) -> %lld", ext, suc);
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