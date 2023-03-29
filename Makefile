TARGET := iphone:clang:13.7:8.0

ifdef ROOTLESS
export ARCHS = arm64 arm64e
else
export ARCHS = armv7 armv7s arm64 arm64e
endif

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = libsandy

libsandy_FILES = libSandy.m
libsandy_CFLAGS = -fobjc-arc
libsandy_INSTALL_PATH = /usr/lib
libsandy_PUBLIC_HEADERS = libSandy.h

TWEAK_NAME = libSandySupport

libSandySupport_FILES = libSandySupport.x sandbox_compat.m
libSandySupport_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/library.mk
include $(THEOS_MAKE_PATH)/tweak.mk