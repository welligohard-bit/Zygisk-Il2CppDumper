#include "hack.h"
#include "il2cpp_dump.h"
#include "log.h"
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <sys/mman.h>

// Helper to find the base address of the library in memory
static uintptr_t get_lib_base(const char* lib_name) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, lib_name) && strstr(line, "r-x")) {
            base = strtoul(line, nullptr, 16);
            break;
        }
    }
    fclose(fp);
    return base;
}

// Internal logic to perform the dump
void hack_start(const char *game_data_dir) {
    LOGI("hack_start: Scanning for libil2cpp.so memory...");

    uintptr_t base_address = 0;
    // Poll for the library to be mapped
    for (int i = 0; i < 60; i++) {
        base_address = get_lib_base("libil2cpp.so");
        if (base_address != 0) break;
        sleep(1);
    }

    if (base_address == 0) {
        LOGE("Aborted: libil2cpp.so not found in memory maps.");
        return;
    }

    // Verify ELF header
    uint32_t magic = *reinterpret_cast<uint32_t*>(base_address);
    if (magic != 0x464c457f) {
        LOGE("Aborted: Found memory region, but it is not a valid ELF file.");
        return;
    }

    // Offset must be relative to the actual base found in maps
    uint64_t il2cpp_init_offset = 0x1D3C0E4; 
    void* init_fn = reinterpret_cast<void*>(base_address + il2cpp_init_offset);

    LOGI("Mapping success. Base: %p, Target: %p", (void*)base_address, init_fn);
    
    if (init_fn != nullptr) {
        il2cpp_api_init(init_fn); 
        il2cpp_dump(game_data_dir);
    } else {
        LOGE("Critical Error: Calculation resulted in a null pointer.");
    }
}

// This function is required by main.cpp to link correctly
void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("hack_prepare: Initializing...");
    
    // You can process the 'data' buffer here if needed for custom decryption
    
    // Start the dumper logic
    hack_start(game_data_dir);
}
