#include "hack.h"
#include "il2cpp_dump.h"
#include "log.h"
#include "xdl.h"
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <jni.h>
#include <thread>
#include <sys/mman.h>
#include <linux/unistd.h>
#include <array>
#include <vector>
#include <string>
#include <cstdint>

void hack_start(const char *game_data_dir) {
    void *handle = nullptr;
    LOGI("hack_start: Waiting for libil2cpp.so to map...");

    // 1. Wait for library to appear
    for (int i = 0; i < 30; i++) {
        handle = xdl_open("libil2cpp.so", 0);
        if (handle) break;
        sleep(2);
    }

    if (!handle) {
        LOGE("Aborted: libil2cpp.so not found.");
        return;
    }

    // 2. Wait for library memory to be readable
    xdl_info_t info;
    bool ready = false;
    for (int i = 0; i < 10; i++) {
        if (xdl_info(handle, XDL_DI_DLINFO, &info) && info.dli_fbase != nullptr) {
            ready = true;
            break;
        }
        sleep(1);
    }

    if (!ready) {
        LOGE("Aborted: libil2cpp.so found but base address is null.");
        xdl_close(handle);
        return;
    }

    // 3. Apply offset mapping
    uint64_t base_address = reinterpret_cast<uint64_t>(info.dli_fbase);
    uint64_t il2cpp_init_offset = 0x1D3C0E4; 
    void* init_fn = reinterpret_cast<void*>(base_address + il2cpp_init_offset);

    LOGI("Mapping success. Base: %p, Target: %p", info.dli_fbase, init_fn);
    
    il2cpp_api_init(init_fn); 
    il2cpp_dump(game_data_dir);
    
    xdl_close(handle);
}

// ... Keep your existing GetLibDir, NativeBridgeLoad, and JNI_OnLoad functions below this ...
// Make sure you do NOT copy the "void hack_start" function again after this line.
