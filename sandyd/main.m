#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <Security.h>
#import <sys/stat.h>
#import <xpc/xpc.h>
#import <dlfcn.h>
#import <HBLogWeak.h>
#import <libroot.h>
#import <sandbox_private.h>
#import <sandyd.h>
#import "sandbox_compat.h"

void createExtensionPlist(void)
{
	NSString *targetPath = JBROOT_PATH_NSSTRING(@"/usr/lib/sandyd_global.plist");
	NSMutableArray *extensions = [NSMutableArray new];

	char *extension = NULL;
	extension = sandbox_extension_issue_mach("com.apple.app-sandbox.mach", "com.opa334.sandyd", 0);
	if (extension) [extensions addObject:[NSString stringWithUTF8String:extension]];
	extension = sandbox_extension_issue_mach("com.apple.security.exception.mach-lookup.global-name", "com.opa334.sandyd", 0);
	if (extension) [extensions addObject:[NSString stringWithUTF8String:extension]];

	HBLogDebugWeak(@"generated extensions: %@", extensions);

	NSDictionary *dictToSave = @{ @"extensions" : extensions };
	[dictToSave writeToFile:targetPath atomically:NO];
}

BOOL evaluateCondition(NSDictionary *condition)
{
	BOOL result = NO;

	NSString *conditionType = condition[@"ConditionType"];
	if ([conditionType isEqualToString:@"FileExistance"]) {
		NSString *filePath = condition[@"FilePath"];
		result = [[NSFileManager defaultManager] fileExistsAtPath:filePath];
	}

	NSNumber *negated = condition[@"Negated"];
	if ([negated boolValue]) {
		result = !result;
	}

	HBLogDebugWeak(@"[libSandySupport evaluateCondition] %@ => %d", condition, result);

	return result;
}

NSString *issueExtension(NSDictionary *extensionDict, audit_token_t auditToken)
{
	if (!extensionDict) return nil;
	char *outToken = nil;
	NSString *typeOfExtension = extensionDict[@"type"];
	NSString *extensionClass = extensionDict[@"extension_class"];
	if (!typeOfExtension) return nil;

	if ([typeOfExtension isEqualToString:@"file"]) {
		NSString *path = extensionDict[@"path"];
		outToken = compat_sandbox_extension_issue_file_to_process(extensionClass.UTF8String, path.UTF8String, 0, auditToken);
	} else if ([typeOfExtension isEqualToString:@"generic"]) {
		outToken = compat_sandbox_extension_issue_generic_to_process(extensionClass.UTF8String, 0, auditToken);
	} else if ([typeOfExtension isEqualToString:@"iokit_registry"]) {
		NSString *registryClass = extensionDict[@"registry_class"];
		outToken = compat_sandbox_extension_issue_iokit_registry_entry_class_to_process(extensionClass.UTF8String, registryClass.UTF8String, 0, auditToken);
	} else if ([typeOfExtension isEqualToString:@"iokit_user_client"]) {
		NSString *registryEntryClass = extensionDict[@"registry_entry_class"];
		outToken = sandbox_extension_issue_iokit_user_client_class(extensionClass.UTF8String, registryEntryClass.UTF8String, 0);
	} else if ([typeOfExtension isEqualToString:@"mach"]) {
		NSString *machName = extensionDict[@"mach_name"];
		outToken = compat_sandbox_extension_issue_mach_to_process(extensionClass.UTF8String, machName.UTF8String, 0, auditToken);
	} else if ([typeOfExtension isEqualToString:@"posix_ipc"]) {
		NSString *posixName = extensionDict[@"posix_name"];
		outToken = sandbox_extension_issue_posix_ipc(extensionClass.UTF8String, posixName.UTF8String, 0);
	} /*else if ([typeOfExtension isEqualToString:@"preference"]) {
		NSString *preferenceDomain = extensionDict[@"preference_domain"];
		outToken = compat_sandbox_extension_issue_preference(extensionClass.UTF8String, preferenceDomain.UTF8String, 0);
	}*/ // disabled, didn't work :(

	NSString *nsOutToken = nil;
	if (outToken) {
		nsOutToken = [NSString stringWithUTF8String:outToken];
		free(outToken);
	}

	return nsOutToken;
}

xpc_object_t getProcessExtensions(xpc_connection_t sourceConnection, const char *profileName)
{
	audit_token_t auditToken;
	xpc_connection_get_audit_token(sourceConnection, &auditToken);
	struct __SecTask *secTask = SecTaskCreateWithAuditToken(NULL, auditToken);

	NSString *sourceIdentifier = (__bridge_transfer NSString*)SecTaskCopySigningIdentifier(secTask, NULL);
	NSString *nsProfileName = [NSString stringWithUTF8String:profileName];

	HBLogDebugWeak(@"[libSandySupport getProcessExtensions] sourceIdentifier=%@ profileName=%@", sourceIdentifier, nsProfileName);

	__block xpc_object_t extensionArray = xpc_array_create(NULL, 0);
	NSString *profileRootPath = JBROOT_PATH_NSSTRING(@"/Library/libSandy");
	NSString *profilePath = [profileRootPath stringByAppendingPathComponent:[nsProfileName stringByAppendingPathExtension:@"plist"]].stringByStandardizingPath;

	if (![profilePath hasPrefix:profileRootPath]) {
		// nice try ;-)
		return extensionArray;
	}

	struct stat info;
	stat(profilePath.fileSystemRepresentation, &info);
	if (info.st_uid != 0 || info.st_gid != 0) {
		// nice try² ;-)
		return extensionArray;
	}

	HBLogDebugWeak(@"[libSandySupport getProcessExtensions] profilePath=%@", profilePath);

	if (![[NSFileManager defaultManager] fileExistsAtPath:profilePath]) {
		HBLogDebugWeak(@"[libSandySupport getProcessExtensions] profilePath does not exists, rejecting...");
	}

	NSURL *profileURL = [NSURL fileURLWithPath:profilePath isDirectory:NO];
	NSDictionary *profileDict;
	NSError *readError = nil;

	if (@available(iOS 11, *)) {
		profileDict = [NSDictionary dictionaryWithContentsOfURL:profileURL error:&readError];
	}
	else {
		profileDict = [NSDictionary dictionaryWithContentsOfURL:profileURL];
	}

	if (!profileDict) {
		HBLogDebugWeak(@"[libSandySupport getProcessExtensions] failed to read profile plist, error: %@", readError);
		return extensionArray;
	}

	// Verify if allowed
	NSArray *allowedProcesses = profileDict[@"AllowedProcesses"];
	if (![allowedProcesses isKindOfClass:NSArray.class]) return extensionArray;
	BOOL allowed = [allowedProcesses containsObject:sourceIdentifier] || [allowedProcesses containsObject:@"*"];
	if (!allowed) {
		HBLogDebugWeak(@"[libSandySupport getProcessExtensions] process %@ is not allowed to apply profile (allowedProcesses: %@), rejecting...", sourceIdentifier, allowedProcesses);
		return extensionArray;
	}

	// Verify if all conditions are met
	__block BOOL conditionsMet = YES;
	NSArray *conditions = profileDict[@"Conditions"];
	[conditions enumerateObjectsUsingBlock:^(NSDictionary *conditionDict, NSUInteger idx, BOOL *stop) {
		BOOL conditionMet = evaluateCondition(conditionDict);
		if (!conditionMet) {
			conditionsMet = NO;
			*stop = YES;
		}
	}];

	if (!conditionsMet) {
		HBLogDebugWeak(@"[libSandySupport getProcessExtensions] required conditions not met, rejecting...");
	}
	
	// Load extensions
	NSArray *containedExtensions = profileDict[@"Extensions"];
	if (![containedExtensions isKindOfClass:NSArray.class]) return extensionArray;
	if (!containedExtensions || containedExtensions.count == 0) return extensionArray;

	[containedExtensions enumerateObjectsUsingBlock:^(NSDictionary *extensionDict, NSUInteger idx, BOOL *stop) {
		if (![extensionDict isKindOfClass:NSDictionary.class]) return;
		NSString *extensionToken = issueExtension(extensionDict, auditToken);
		if (!extensionToken) {
			HBLogDebugWeak(@"[libSandySupport getProcessExtensions] failed to issue extension %@", extensionDict);
			return;
		}
		xpc_array_append_value(extensionArray, xpc_string_create(extensionToken.UTF8String));
	}];

	HBLogDebugWeak(@"[libSandySupport getProcessExtensions] success!");

	return extensionArray;
}

int main(int argc, char *argv[], char *envp[]) {
	@autoreleasepool {
		// Attempt to create the server, exit if fails
		xpc_connection_t service = xpc_connection_create_mach_service("com.opa334.sandyd", NULL, XPC_CONNECTION_MACH_SERVICE_LISTENER);
		if (!service) {
			HBLogDebugWeak(@"Failed to create XPC server. Exiting.");
			return 0;
		}

		initSandboxCompatibilityLayer();
		createExtensionPlist();

		// Configure event handler
		xpc_connection_set_event_handler(service, ^(xpc_object_t connection) {
			xpc_type_t type = xpc_get_type(connection);
			if (type == XPC_TYPE_CONNECTION) {
				xpc_connection_set_event_handler(connection, ^(xpc_object_t message) {
					if (xpc_get_type(message) == XPC_TYPE_DICTIONARY) {
						SANDYD_MESSAGE_ID messageId = xpc_dictionary_get_int64(message, "id");
						switch (messageId) {
							case SANDYD_MESSAGE_TEST_CONNECTION: {
								xpc_object_t reply = xpc_dictionary_create_reply(message);
								xpc_dictionary_set_bool(reply, "works", true);
								xpc_connection_send_message(connection, reply);
								break;
							}
							case SANDYD_MESSAGE_GET_PROFILE_EXTENSIONS: {
								const char *profileName = xpc_dictionary_get_string(message, "profile");
								xpc_object_t extensions = getProcessExtensions(connection, profileName);
								xpc_object_t reply = xpc_dictionary_create_reply(message);
								xpc_dictionary_set_value(reply, "extensions", extensions);
								xpc_connection_send_message(connection, reply);
								break;
							}
						}
					}
				});
				xpc_connection_resume(connection);
			} else if (type == XPC_TYPE_ERROR) {
				HBLogDebugWeak(@"XPC server error: %s", xpc_dictionary_get_string(connection, XPC_ERROR_KEY_DESCRIPTION));
			}
		});

		// Make connection live
		xpc_connection_resume(service);

		// Execute run loop
		[[NSRunLoop currentRunLoop] run];

		return 0;
	}
}
