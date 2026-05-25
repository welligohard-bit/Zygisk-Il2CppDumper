#include <fcntl.h>
#include <sys/mman.h>
#include <fstream>
#include <sstream>

// Helper to find the base address of a loaded library via /proc/self/maps
uintptr_t get_lib_base(const char* lib_name) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, lib_name) && strstr(line, "r-x")) {
            // Found the executable segment, extract the start address
            base = strtoul(line, nullptr, 16);
            break;
        }
    }
    fclose(fp);
    return base;
}

void hack_start(const char *game_data_dir) {
    LOGI("hack_start: Scanning for libil2cpp.so memory...");

    uintptr_t base_address = 0;
    
    // 1. Polling for the library in memory maps
    // Instead of waiting for a handle, we wait for the segment to exist
    for (int i = 0; i < 60; i++) {
        base_address = get_lib_base("libil2cpp.so");
        if (base_address != 0) break;
        sleep(1);
    }

    if (base_address == 0) {
        LOGE("Aborted: libil2cpp.so not found in memory maps.");
        return;
    }

    // 2. Verify we found a valid base (check ELF magic)
    uint32_t magic = *reinterpret_cast<uint32_t*>(base_address);
    if (magic != 0x464c457f) {
        LOGE("Aborted: Found memory region, but it is not a valid ELF file.");
        return;
    }

    // 3. Apply offset calculation
    // Note: ensure this offset is relative to the base found in maps
    uint64_t il2cpp_init_offset = 0x1D3C0E4; 
    void* init_fn = reinterpret_cast<void*>(base_address + il2cpp_init_offset);

    LOGI("Mapping success. Base: %p, Target: %p", (void*)base_address, init_fn);
    
    // 4. Initialization
    // If metadata is invalid, this is where you would hook the internal 
    // metadata loader before calling il2cpp_api_init.
    if (init_fn != nullptr) {
        il2cpp_api_init(init_fn); 
        il2cpp_dump(game_data_dir);
    } else {
        LOGE("Critical Error: Calculation resulted in a null pointer.");
    }
}
