include $(THEOS)/makefiles/common.mk

TOOL_NAME = sandyd

sandyd_ARCHS = arm64
sandyd_FILES = main.m sandbox_compat.m
sandyd_CFLAGS = -fobjc-arc -I../headers
ifneq ($(THEOS_PACKAGE_SCHEME),rootless)
sandyd_CFLAGS += -D XINA_SUPPORT=1
endif
sandyd_CODESIGN_FLAGS = -Sentitlements.plist
sandyd_INSTALL_PATH = /usr/local/libexec

include $(THEOS_MAKE_PATH)/tool.mk

ifeq ($(THEOS_PACKAGE_SCHEME),rootless)
after-sandyd-stage::
	$(ECHO_NOTHING) rm $(THEOS_STAGING_DIR)/Library/LaunchDaemons/com.opa334.sandyd.plist$(ECHO_END)
	$(ECHO_NOTHING) mv $(THEOS_STAGING_DIR)/Library/LaunchDaemons/com.opa334.sandyd.rootless.plist $(THEOS_STAGING_DIR)/Library/LaunchDaemons/com.opa334.sandyd.plist$(ECHO_END)
	$(ECHO_NOTHING)$(FAKEROOT) chown root:wheel $(THEOS_STAGING_DIR)/Library/LaunchDaemons/com.opa334.sandyd.plist$(ECHO_END)
else
after-sandyd-stage::
	$(ECHO_NOTHING) rm $(THEOS_STAGING_DIR)/Library/LaunchDaemons/com.opa334.sandyd.rootless.plist$(ECHO_END)
	$(ECHO_NOTHING)$(FAKEROOT) chown root:wheel $(THEOS_STAGING_DIR)/Library/LaunchDaemons/com.opa334.sandyd.plist$(ECHO_END)
endif