ifeq ($(THEOS_PACKAGE_SCHEME),rootless)
TARGET := iphone:clang:16.5:15.0
else
TARGET := iphone:clang:14.5:8.0
endif
INSTALL_TARGET_PROCESSES = securityd

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SandyProxy

SandyProxy_FILES = Tweak.x
SandyProxy_CFLAGS = -fobjc-arc -I../headers
ifneq ($(THEOS_PACKAGE_SCHEME),rootless)
SandyProxy_CFLAGS += -D XINA_SUPPORT=1
endif

include $(THEOS_MAKE_PATH)/tweak.mk
