#include <CoreFoundation/CoreFoundation.h>
#include <xpc/xpc.h>
#import "libSandy_private.h"
#import <sandyd.h>

// I had to implement this in C because ARC was fucking me over...

bool isMachIdentifierRedirected(const char *identifier);
bool consumeSandydGlobalExtensions(void);

xpc_object_t sandyProxySendMessage(xpc_object_t message)
{
	xpc_dictionary_set_bool(message, "SandyProxy_Redirect", true);

	xpc_connection_t connection = xpc_connection_create_mach_service(SANDY_PROXY_IDENTIFER, 0, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
	xpc_connection_set_event_handler(connection, ^(xpc_object_t object){});
	xpc_connection_resume(connection);

	return xpc_connection_send_message_with_reply_sync(connection, message);
}

xpc_object_t sandydSendMessage(xpc_object_t message)
{
	if (!consumeSandydGlobalExtensions()) return NULL;

	xpc_connection_t connection = xpc_connection_create_mach_service("com.opa334.sandyd", 0, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
	xpc_connection_set_event_handler(connection, ^(xpc_object_t object){});
	xpc_connection_resume(connection);

	xpc_object_t xreply = xpc_connection_send_message_with_reply_sync(connection, message);
	return xreply;
}

int64_t sandyProxy_customLookup(xpc_object_t xmsg, xpc_object_t *xreply)
{
	*xreply = sandyProxySendMessage(xmsg);
	if (!*xreply) return -1;

	xpc_object_t retCodeVal = xpc_dictionary_get_value(*xreply, "SandyProxy_XPCRetCode");
	int r = -1;
	if (retCodeVal) {
		r = xpc_int64_get_value(retCodeVal);
		xpc_dictionary_set_value(*xreply, "SandyProxy_XPCRetCode", NULL);
	}
	
	return r;
}

int64_t libSandy_customLookup(xpc_object_t xmsg, xpc_object_t *xreply)
{
	xpc_dictionary_set_int64(xmsg, "id", SANDYD_MESSAGE_CUSTOM_LOOKUP);
	*xreply = sandydSendMessage(xmsg);
	
	xpc_object_t retCodeVal = xpc_dictionary_get_value(*xreply, "SandyProxy_XPCRetCode");
	int r = -1;
	if (retCodeVal) {
		r = xpc_int64_get_value(retCodeVal);
		xpc_dictionary_set_value(*xreply, "SandyProxy_XPCRetCode", NULL);
	}

	return r;
}

int64_t (*_xpc_interface_routine_orig)(int msgid, xpc_object_t xmsg, xpc_object_t *xreply, void *a4, void *a5);
int64_t _xpc_interface_routine_hook(int msgid, xpc_object_t xmsg, xpc_object_t *xreply, void *a4, void *a5)
{
	int64_t r = _xpc_interface_routine_orig(msgid, xmsg, xreply, a4, a5);
	
	// If the call worked, return
	if (r == 0) return r;

	// If the message is not a lookup, return
	if (msgid != 207 && msgid != 804) return r;

	// Otherwise redirect endpoint lookup request if appropriate
	if (xmsg && xreply) {
		const char *name = xpc_dictionary_get_string(xmsg, "name");
		if (name) {
			bool needsProxy = !strcmp(name, "com.opa334.sandyd");
			bool needsRedirection = needsProxy || isMachIdentifierRedirected(name);

			if (needsRedirection) {
				xpc_object_t xmsgToSend = xpc_dictionary_create(NULL, NULL, 0);
				xpc_dictionary_apply(xmsg, ^bool(const char *key, xpc_object_t xobj){
					xpc_dictionary_set_value(xmsgToSend, key, xobj);
					return true;
				});

				xpc_dictionary_set_int64(xmsgToSend, "libsandy_msgid", msgid);

				xpc_object_t xreplyToReturn = NULL;

				// If this is a lookup request of sandyd itself, redirect to SandyProxy (running in a daemon that's widely accessible)
				if (needsProxy) {
					r = sandyProxy_customLookup(xmsgToSend, &xreplyToReturn);
				}
				// If this is a lookup request of something other than sandyd that is in gMachServicesToRedirect, redirect to sanydd
				else {
					r = libSandy_customLookup(xmsgToSend, &xreplyToReturn);
				}

				xpc_release(xmsgToSend);

				if (*xreply) {
					xpc_release(*xreply);
				}

				*xreply = xreplyToReturn;
			}
		}
	}

	return r;
}
