# The handheld's Microphone (kf_handheld/src/mic.cpp) is a USB Audio Class 2 microphone: 48 kHz,
# mono, 16-bit, one isochronous IN endpoint of up to 49 samples (98 bytes) per 1 ms frame.
# ESP TinyUSB's tusb_config.h has no audio settings, so every component gets them here; the
# FIFO holds about 10 ms. Call after including project.cmake and before project(). Handheld
# builds only: the bridge itself has no audio function.
function(keyferry_enable_handheld_usb_audio)
    foreach(definition IN ITEMS
            CFG_TUD_AUDIO=1
            CFG_TUD_AUDIO_ENABLE_EP_IN=1
            CFG_TUD_AUDIO_FUNC_1_EP_IN_SZ_MAX=98
            CFG_TUD_AUDIO_FUNC_1_EP_IN_SW_BUF_SZ=1024)
        idf_build_set_property(COMPILE_DEFINITIONS "${definition}" APPEND)
    endforeach()
endfunction()
