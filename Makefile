ifeq ($(THEOS_PACKAGE_SCHEME),rootless)
TARGET := iphone:clang:16.2:15.0
else
TARGET := iphone:clang:14.5:8.0
endif

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = libsandy

libsandy_FILES = libSandy.m
libsandy_CFLAGS = -fobjc-arc
ifeq ($(THEOS_PACKAGE_SCHEME),rootless)
libsandy_LDFLAGS += -install_name @rpath/libsandy.dylib
endif
libsandy_INSTALL_PATH = /usr/lib
libsandy_PUBLIC_HEADERS = libSandy.h

TWEAK_NAME = libSandySupport

libSandySupport_FILES = libSandySupport.x sandbox_compat.m
libSandySupport_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/library.mk
include $(THEOS_MAKE_PATH)/tweak.mk