#include "hack.h"
#include "il2cpp_dump.h"
#include "log.h"
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <sys/mman.h>

// Universal ELF scanner: Finds the first executable segment that looks like an ELF file
static uintptr_t find_il2cpp_base() {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    uintptr_t base = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        // Look for read-execute segments
        if (strstr(line, "r-x")) {
            uintptr_t start = strtoul(line, nullptr, 16);
            
            // Validate ELF Magic (0x7F 'E' 'L' 'F')
            // Using a simple pointer read; ensure the address is valid/mapped
            uint32_t magic = *reinterpret_cast<uint32_t*>(start);
            if (magic == 0x464c457f) {
                // If you are still failing, add: LOGI("Candidate segment found: %s", line);
                base = start;
                break;
            }
        }
    }
    fclose(fp);
    return base;
}

void hack_start(const char *game_data_dir) {
    LOGI("hack_start: Starting universal memory scan...");

    uintptr_t base_address = 0;
    // Poll for the memory segment to be mapped/decrypted
    for (int i = 0; i < 60; i++) {
        base_address = find_il2cpp_base();
        if (base_address != 0) break;
        sleep(1);
    }

    if (base_address == 0) {
        LOGE("Aborted: Could not locate any executable ELF segment in memory.");
        return;
    }

    // Offset must be relative to the actual base found in maps
    // Ensure this offset is correct for the game's specific version
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

// Global entry point for the Zygisk module
void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("hack_prepare: Initializing custom dumper...");
    hack_start(game_data_dir);
}
