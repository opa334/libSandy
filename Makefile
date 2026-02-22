ONLY_LIBRARY ?= 0

ifeq ($(THEOS_PACKAGE_SCHEME),rootless)
TARGET := iphone:clang:16.5:15.0
else
TARGET := iphone:clang:14.5:8.0
endif

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = libsandy

libsandy_FILES = libSandy.m libSandy.c
libsandy_CFLAGS = -fobjc-arc -Iheaders -framework CydiaSubstrate
libsandy_LDFLAGS = -Xlinker -not_for_dyld_shared_cache
ifeq ($(THEOS_PACKAGE_SCHEME),rootless)
libsandy_LDFLAGS += -install_name @rpath/libsandy.dylib
else
libsandy_CFLAGS += -D XINA_SUPPORT=1
endif
libsandy_INSTALL_PATH = /usr/lib
libsandy_PUBLIC_HEADERS = libSandy.h

include $(THEOS_MAKE_PATH)/library.mk
ifeq ($(ONLY_LIBRARY),0)
SUBPROJECTS += sandyd
SUBPROJECTS += SandyProxy
endif
include $(THEOS_MAKE_PATH)/aggregate.mk
