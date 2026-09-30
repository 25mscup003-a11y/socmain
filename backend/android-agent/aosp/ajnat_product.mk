# Include from the controlled device product makefile after placing this tree
# at vendor/ajnat/android-agent (or update AJNAT_ANDROID_AGENT_PATH accordingly).
AJNAT_ANDROID_AGENT_PATH := vendor/ajnat/android-agent

PRODUCT_PACKAGES += \
    AJNATPrivilegedAgent \
    ajnatd \
    privapp-permissions-com.soc.agent.xml

PRODUCT_PRIVATE_SEPOLICY_DIRS += \
    $(AJNAT_ANDROID_AGENT_PATH)/aosp/sepolicy/private
