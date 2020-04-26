TWEAK_NAME = MailMend
MailMend_FILES = Tweak.x
MailMend_PRIVATE_FRAMEWORKS = MIME
MailMend_USE_MODULES = 0

INSTALL_TARGET_PROCESSES = MobileMail maild SpringBoard

ADDITIONAL_CFLAGS = -std=c99

XCODE6_PATH ?= /Volumes/Xcode/Xcode.app
XCODE9_PATH ?= /Volumes/Xcode_9.4.1/Xcode.app

ifeq ($(wildcard $(XCODE6_PATH)/.*),)
ADDITIONAL_CFLAGS += -Idefaultheaders
IPHONE_ARCHS = armv7 armv7s arm64 arm64e
TARGET_IPHONEOS_DEPLOYMENT_VERSION = 8.4
ifeq ($(FINALPACKAGE),1)
$(error Building final package requires a legacy Xcode install!)
endif
else
#IPHONE_ARCHS = armv7 armv7s arm64 arm64e
IPHONE_ARCHS = armv7s arm64 arm64e
TARGET_IPHONEOS_DEPLOYMENT_VERSION_armv7 = 6.0
TARGET_IPHONEOS_DEPLOYMENT_VERSION_armv7s = 7.0
TARGET_IPHONEOS_DEPLOYMENT_VERSION_arm64 = 7.0
TARGET_IPHONEOS_DEPLOYMENT_VERSION_arm64e = 12.0
TARGET_IPHONEOS_DEPLOYMENT_VERSION = 9.0
THEOS_PLATFORM_SDK_ROOT_armv7 = $(XCODE6_PATH)/Contents/Developer
THEOS_PLATFORM_SDK_ROOT_armv7s = $(XCODE9_PATH)/Contents/Developer
THEOS_PLATFORM_SDK_ROOT_arm64 = $(XCODE9_PATH)/Contents/Developer
endif

include framework/makefiles/common.mk
include framework/makefiles/tweak.mk

stage::
	plutil -convert binary1 "$(THEOS_STAGING_DIR)/Library/MobileSubstrate/DynamicLibraries/MailMend.plist"
