#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <xpc/xpc.h>
#import "sandbox.h"
#import "HBLogWeak.h"
#import "libSandy.h"

int libSandy_applyProfile(const char* profileName)
{
	__block int retcode = kLibSandyErrorXPCFailure;

	HBLogDebugWeak(@"[libSandy libSandy_applyProfile] attempting to apply profile %s", profileName);

	xpc_connection_t mgConnection = xpc_connection_create_mach_service("com.apple.mobilegestalt.xpc", 0, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
	xpc_connection_set_event_handler(mgConnection, ^(xpc_object_t object){});
	xpc_connection_resume(mgConnection);

	xpc_object_t getExtensionsMessage = xpc_dictionary_create(NULL,NULL,0);
	xpc_dictionary_set_bool(getExtensionsMessage, "libSandy_isProfileMessage", YES);
	xpc_dictionary_set_string(getExtensionsMessage, "profile", profileName);
	
	xpc_object_t reply = xpc_connection_send_message_with_reply_sync(mgConnection, getExtensionsMessage);
	if(reply)
	{
		xpc_type_t replyType = xpc_get_type(reply);
		HBLogDebugWeak(@"[libSandy libSandy_applyProfile] got reply %s", xpc_copy_description(reply));
		if(replyType == XPC_TYPE_DICTIONARY)
		{
			xpc_object_t extensions = xpc_dictionary_get_value(reply, "extensions");
			xpc_type_t extensionsType = xpc_get_type(extensions);
			if(extensionsType == XPC_TYPE_ARRAY)
			{
				HBLogDebugWeak(@"[libSandy libSandy_applyProfile] got extensions %s", xpc_copy_description(extensions));
				retcode = kLibSandyErrorRestricted;
				xpc_array_apply(extensions, ^bool(size_t index, xpc_object_t value)
				{
					if(xpc_get_type(value) == XPC_TYPE_STRING)
					{
						retcode = kLibSandySuccess; // if returned extensions has one or more tokens: SUCCESS
						const char* ext = xpc_string_get_string_ptr(value);
						__unused int64_t suc = sandbox_extension_consume(ext);
						HBLogDebugWeak(@"[libSandy libSandy_applyProfile] Consumed extension (%s) -> %lld", ext, suc);
					}
					return true;
				});
			}
		}
	}

	HBLogDebugWeak(@"[libSandy libSandy_applyProfile] applied profile %s => %d", profileName, retcode);

	return retcode;
}

bool libSandy_works()
{
	xpc_connection_t mgConnection = xpc_connection_create_mach_service("com.apple.mobilegestalt.xpc", 0, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
	xpc_connection_set_event_handler(mgConnection, ^(xpc_object_t object){});
	xpc_connection_resume(mgConnection);

	xpc_object_t testMessage = xpc_dictionary_create(NULL,NULL,0);
	xpc_dictionary_set_bool(testMessage, "libSandy_isTestMessage", YES);
	
	xpc_object_t reply = xpc_connection_send_message_with_reply_sync(mgConnection, testMessage);
	if(reply)
	{
		xpc_type_t replyType = xpc_get_type(reply);
		if(replyType == XPC_TYPE_DICTIONARY)
		{
			return xpc_dictionary_get_bool(reply, "works");
		}
	}
	return false;
}