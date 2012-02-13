LOCAL_PATH := $(my-dir)

include $(CLEAR_VARS)

LOCAL_C_INCLUDES := \
	$(KERNEL_HEADERS) \
	external/libkeyutils \
	external/openssl/include

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	libc \
	libcrypto \
	libkeyutils

LOCAL_SRC_FILES := \
	libecryptfs/main.c \
	libecryptfs/key_management.c

LOCAL_MODULE := libecryptfs
LOCAL_MODULE_TAGS := optional

include $(BUILD_SHARED_LIBRARY)
