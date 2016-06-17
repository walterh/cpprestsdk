LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
TARGET_ARCH_ABI := armeabi-v7a
LOCAL_MODULE    := iconv
LOCAL_CFLAGS    := \
    -Wno-multichar \
    -D_ANDROID \
    -DLIBDIR="\"c\"" \
    -DBUILDING_LIBICONV \
    -DIN_LIBRARY
LOCAL_C_INCLUDES := \
    ../libiconv-1.13.1 \
    ../libiconv-1.13.1/include \
    ../libiconv-1.13.1/lib \
    ../libiconv-1.13.1/libcharset/include
LOCAL_SRC_FILES := \
    ../libiconv-1.13.1/lib/iconv.c \
    ../libiconv-1.13.1/lib/relocatable.c \
    ../libiconv-1.13.1/libcharset/lib/localcharset.c
include $(BUILD_SHARED_LIBRARY)