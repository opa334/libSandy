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
#import "../libSandy_private.h"
#import <substrate.h>

int64_t (*_xpc_interface_routine)(int msgid, xpc_object_t xmsg, xpc_object_t *xreply, uint64_t a4, uint64_t a5);

NSString *resolveCaller(xpc_object_t sourceConnection, audit_token_t *auditTokenOut)
{
	audit_token_t auditToken;
	xpc_connection_get_audit_token(sourceConnection, &auditToken);
	if (auditTokenOut) *auditTokenOut = auditToken;

	struct __SecTask *secTask = SecTaskCreateWithAuditToken(NULL, auditToken);
	if (!secTask) {
		return nil;
	}
	NSString *callerIdentifier = (__bridge_transfer NSString *)SecTaskCopySigningIdentifier(secTask, NULL);
	CFRelease(secTask);

	return callerIdentifier;
}

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
		outToken = compat_sandbox_extension_issue_iokit_user_client_class(extensionClass.UTF8String, registryEntryClass.UTF8String, 0);
	} else if ([typeOfExtension isEqualToString:@"mach"]) {
		NSString *machName = extensionDict[@"mach_name"];
		outToken = compat_sandbox_extension_issue_mach_to_process(extensionClass.UTF8String, machName.UTF8String, 0, auditToken);
	} else if ([typeOfExtension isEqualToString:@"posix_ipc"]) {
		NSString *posixName = extensionDict[@"posix_name"];
		outToken = compat_sandbox_extension_issue_posix_ipc(extensionClass.UTF8String, posixName.UTF8String, 0);
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

bool isProfileAllowed(NSDictionary *profileDict, NSString *callerIdentifier)
{
	NSArray *allowedProcesses = profileDict[@"AllowedProcesses"];
	if (![allowedProcesses isKindOfClass:NSArray.class]) return false;
	return [allowedProcesses containsObject:callerIdentifier] || [allowedProcesses containsObject:@"*"];
}

bool areProfileConditionsMet(NSDictionary *profileDict)
{
	__block BOOL conditionsMet = YES;
	NSArray *conditions = profileDict[@"Conditions"];
	[conditions enumerateObjectsUsingBlock:^(NSDictionary *conditionDict, NSUInteger idx, BOOL *stop) {
		BOOL conditionMet = evaluateCondition(conditionDict);
		if (!conditionMet) {
			conditionsMet = NO;
			*stop = YES;
		}
	}];
	return conditionsMet;
}

xpc_object_t getProcessExtensions(NSString *callerIdentifier, audit_token_t auditToken, const char *profileName)
{
	HBLogDebugWeak(@"[libSandySupport getProcessExtensions] callerIdentifier=%@ profileName=%s", callerIdentifier, profileName);

	__block xpc_object_t extensionArray = xpc_array_create(NULL, 0);
	NSURL *profileRootURL = [NSURL fileURLWithPath:JBROOT_PATH_NSSTRING(@"/Library/libSandy") isDirectory:YES];
	NSURL *profileURL = [NSURL fileURLWithPath:[[NSString stringWithUTF8String:profileName].lastPathComponent stringByAppendingString:@".plist"] isDirectory:NO relativeToURL:profileRootURL];

	struct stat info;
	stat(profileURL.path.fileSystemRepresentation, &info);
	if (info.st_uid != 0 || info.st_gid != 0) {
		// nice try ;-)
		return extensionArray;
	}

	HBLogDebugWeak(@"[libSandySupport getProcessExtensions] profileURL=%@", profileURL.path);

	if (![profileURL checkResourceIsReachableAndReturnError:nil]) {
		HBLogDebugWeak(@"[libSandySupport getProcessExtensions] profileURL () does not exist, rejecting...");
		return extensionArray;
	}

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
	if (!isProfileAllowed(profileDict, callerIdentifier)) {
		HBLogDebugWeak(@"[libSandySupport getProcessExtensions] process %@ is not allowed to apply profile, rejecting...", callerIdentifier);
		return extensionArray;
	}

	// Verify if all conditions are met
	if (!areProfileConditionsMet(profileDict)) {
		HBLogDebugWeak(@"[libSandySupport getProcessExtensions] required conditions not met, rejecting...");
		return extensionArray;
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

NSArray *getActiveProfiles(NSString *callerIdentifier)
{
	NSMutableArray *profiles = [NSMutableArray new];

	NSURL *profileRootURL = [NSURL fileURLWithPath:JBROOT_PATH_NSSTRING(@"/Library/libSandy") isDirectory:YES];
	for (NSURL *profileURL in [[NSFileManager defaultManager] contentsOfDirectoryAtURL:profileRootURL includingPropertiesForKeys:nil options:0 error:nil]) {
		NSDictionary *profileDict;
		if (@available(iOS 11, *)) {
			profileDict = [NSDictionary dictionaryWithContentsOfURL:profileURL error:nil];
		}
		else {
			profileDict = [NSDictionary dictionaryWithContentsOfURL:profileURL];
		}
		if (!profileDict) continue;

		if (isProfileAllowed(profileDict, callerIdentifier) && areProfileConditionsMet(profileDict)) {
			[profiles addObject:profileDict];
		}
	}

	if (profiles.count) return profiles;
	return NULL;
}

bool isMachLookupAllowed(NSString *callerIdentifier, NSString *machIdentifier)
{
	for (NSDictionary *profile in getActiveProfiles(callerIdentifier)) {
		NSArray *extensions = profile[@"Extensions"];
		for (NSDictionary *extension in extensions) {
			if (![extension isKindOfClass:[NSDictionary class]]) continue;
			NSString *type = extension[@"type"];
			if (![type isKindOfClass:[NSString class]]) continue;

			if ([type isEqualToString:@"mach"]) {
				NSString *machName = extension[@"mach_name"];
				if (![machName isKindOfClass:[NSString class]]) continue;
				if ([machName isEqualToString:machIdentifier]) return YES;
			}
		}
	}
	return NO;
}

int main(int argc, char *argv[], char *envp[]) {
	@autoreleasepool {
		MSImageRef xpcImage = MSGetImageByName("/usr/lib/system/libxpc.dylib");
		_xpc_interface_routine = MSFindSymbol(xpcImage, "__xpc_interface_routine");

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
								audit_token_t auditToken;
								NSString *callerIdentifier = resolveCaller(connection, &auditToken);
								if (callerIdentifier) {
									xpc_object_t extensions = getProcessExtensions(callerIdentifier, auditToken, profileName);
									xpc_object_t reply = xpc_dictionary_create_reply(message);
									xpc_dictionary_set_value(reply, "extensions", extensions);
									xpc_connection_send_message(connection, reply);
								}
								break;
							}
							case SANDYD_MESSAGE_CUSTOM_LOOKUP: {
								if (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_16_0) {
									xpc_dictionary_set_value(message, "id", NULL);
									const char *machName = xpc_dictionary_get_string(message, "name");
									if (machName) {
										NSString *callerIdentifier = resolveCaller(connection, NULL);
										if (callerIdentifier) {
											if (isMachLookupAllowed(callerIdentifier, [NSString stringWithUTF8String:machName])) {
												xpc_object_t reply = NULL;
												int msgid = xpc_dictionary_get_int64(message, "libsandy_msgid");

												xpc_object_t messageToSend = xpc_dictionary_create(NULL, NULL, 0);
												xpc_dictionary_apply(message, ^bool(const char *key, xpc_object_t xobj) {
													if (!strcmp(key, "libsandy_msgid")) return true;
													xpc_dictionary_set_value(messageToSend, key, xobj);
													return true;
												});

												int r = _xpc_interface_routine(msgid, messageToSend, &reply, 1, 0);

												xpc_object_t replyToSend = xpc_dictionary_create_reply(message);

												if (r == 0) {
													xpc_dictionary_apply(reply, ^bool(const char *key, xpc_object_t xobj){
														xpc_dictionary_set_value(replyToSend, key, xobj);
														return true;
													});
												}

												xpc_connection_send_message(connection, replyToSend);
											}
										}
									}
									break;
								}
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
