# libSandy

libSandy is a developer library that allows developers to extend the sandbox of applications and system processes on jailbroken iOS in a secure way.

## Sandbox extensions explained

Any process can use sandbox APIs (See sandbox.h) to issue extension tokens for everything it itself has access to.

A token is just a string. This string can be consumed by any other process in order to apply the associated extension to itself.

In order for an extension to have any effect, it needs to be defined in the seatbelt profile of the process that consumes the token.

Unfortunately there is no documentation whatsoever of sandbox extensions, so take all of the above information with a grain of salt.

Sandbox extensions are available in the kernel and there is multiple syscalls, libsystem_sandbox.dylib provides the userspace API, but Apple unfortunately only implemented the functions they specifically need.

By default every process running on iOS has a sandbox profile associated to it, additional extensions can also given through entitlements.

The problem is that when hooking system processes entitlements aren't an option as you cannot change them on existing processes. So when you want to hook an existing process (instead of creating a new binary entirely), the only way to get sandbox extensions is to retrieve them from another process and them consume them, this is what libSandy internally does.

## How libSandy uses sandbox extensions

By default, all processes can only message XPC services allowed by their sandbox, libSandy hooks MobileGestaltHelper because it is unsanboxed and can be accessed by all other processes.

The sandbox extensions are issued on demand inside the MobileGestaltHelper hook and then returned to the calling process, where libSandy consumes them.

## Sandbox "Profiles" (implemented libSandy) explained

In order to be secure, libSandy uses a specific profile format that's stored in a root owned path (`(/var/jb)/Library/libSandy/<Profile Name>.plist`). These profiles are pre defined and need to be included in a package, it is recommended to use the layout directory of theos in order to add it to your project.

A sandbox profile mainly defines which extensions should be issued to the process wanting to apply it, the exact formalities and available options are detailed below.

Secondly, a sandbox profile also contains a whitelist of process signing identifiers that can apply them. If you can't figure out how to get the signing identifier of your process, compile a debug build of libSandy and try consuming a profile the process doesn't have access to, the signing identifier should be logged to console.

Thirdly and least importantly, it is also possible to define conditions under which a libSandy profile may be applied. The only condition currently implemented is file existance, meaning that the profile can only be applied when a certain file (does not (when negated is true)) exist on the file system. I mainly implemented this functionalitly in order to give Safari Plus users an option to use it sandboxed without any security concerns.

### Profile Plist Structure

* `AllowedProcesses`: Array of the process signing identifiers that can apply the profile, a single `*` means all processes are allowed

* `Conditions`: Array of conditions that have to be met

* `Extensions`: Array of the extensions (dictionaries) included in the profile

### Condition Format

A condition is a dictionary with the following keys:

* `ConditionType`: Type of condition to be met (String). As explained, only `FileExistance` currently exists.

* `FilePath`: Path of file to be checked for existance

* `Negated`: When `true`, check if the file does not exist

### Extension Format

There is multiple types of extensions, essentially any sandbox extension supported by iOS can be included in a libSandy profile, the majority of types is never really used in iOS tho so the main useful ones are `file` and `mach`.

* `type`: String, type of the extension as explained above (`file` / `mach` / `generic` / `iokit_registry` / `iokit_user_client` / `posix_name`)

#### File

* `extension_class`: String, either `com.apple.app-sandbox.read` for read or `com.apple.app-sandbox.read-write` for read-write access

* `path`: String, path to the file or directory to allow access to, directories are recursive so if you use `/` then that means access to the entire file system

#### Mach

* `extension_class`: String, should be `com.apple.app-sandbox.mach` for applications or `com.apple.security.exception.mach-lookup.global-name` for system daemons

* `mach_name`: String, name of mach service to allow access to

The other sandbox types are really not that relevant so not listed here, really the key names of the dictionary always have the same names as the arguments passed to the issue functions in sandbox.h.

## Functions provided by libSandy

In order to call these functions, you will have to run the `install_to_theos.sh` script in this repo and then add `sandy` to `<your_project>_LIBRARIES` in your Makefile.

- `int libSandy_applyProfile(const char* profileName)`: attempts to apply a libSandy profile to the calling process. For return codes see [here](libSandy.h#L5).

- `bool libSandy_works(void);`: checks if libSandy correctly works, do not bother calling this before libSandy_applyProfile as that will just return `kLibSandyErrorXPCFailure` when libSandy doesn't work. The reason for this functions existance is when you need to check whether libSandy works from a different process (In Crane many system daemons use libSandy to apply profiles but SpringBoard needs to know whether that worked, therefore it calls libSandy_works). When this returns false you can be almost sure that either libSandy is not compatible with the installed iOS version or that the user has disabled libSandySupport.dylib via Choicy, iCleaner Pro or similar.

## Accessing Preferences

Accessing preferences from sandboxed processes was always problematic and most tweaks use Cephei to do it which redirects all accesses to SpringBoard.

In at least iOS 11 and higher, it is possible to instead use libSandy to access preferences in /var/mobile/Library/Preferences using NSUserDefaults.

First, you need to give yourself read/write access to the plist path via a libSandy profile, then you can initialize NSUserDefaults as follows:

```
NSUserDefaults* yourUserDefaults = [[NSUserDefaults alloc] initWithSuiteName:@"/var/mobile/Library/Preferences/your.pref.file.plist"];
```

This will work like a normal NSUserDefaults object. Note that this doesn't work on iOS 10-ish and below.

It may also be possible to give yourself the `com.apple.security.exception.shared-preference.read-write` extension to use NSUserDefaults normally like apple would (e.g. `[[NSUserDefaults alloc] initWithSuiteName:@"your.pref.file"]`), unfortunately preference extensions aren't implemented by libsystem_sandbox.dylib and I could not find out how to properly generate them (with my attempts they would be generated and consumed but nothing would happen, sandbox_check would still fail), if anyone wants to look into it, the code with what I tried is still there but commented out.


### Examples

[Profile example (Safari Plus)](https://github.com/opa334/SafariPlus/tree/master/layout/Library/libSandy/SafariPlus_FileAccess.plist)
[Apply example (Safari Plus)](https://github.com/opa334/SafariPlus/blob/master/MobileSafari/Classes/SPFileManager.mm#L118)
[NSUserDefaults example (Safari Plus)](https://github.com/opa334/SafariPlus/blob/master/MobileSafari/Classes/SPPreferenceManager.mm#L279)
