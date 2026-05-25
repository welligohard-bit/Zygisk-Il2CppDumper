#include "hack.h"
#include "il2cpp_dump.h"
#include "log.h"
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <sys/mman.h>
#include <thread>
#include <string>

// Filtered ELF scanner: Skips system libraries to find the actual game library
static uintptr_t find_il2cpp_base() {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    uintptr_t base = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        // Only inspect executable memory segments
        if (strstr(line, "r-x")) {
            
            // IGNORE SYSTEM LIBRARIES: If the line contains these paths, skip it
            if (strstr(line, "/system/") || 
                strstr(line, "/apex/") || 
                strstr(line, "/vendor/") || 
                strstr(line, "linker") || 
                strstr(line, "libc.so") || 
                strstr(line, "libart.so") || 
                strstr(line, "libmain.so")) {
                continue;
            }

            uintptr_t start = strtoul(line, nullptr, 16);
            
            // Safely verify if it's a valid ELF header boundary
            // We use a try-catch style approach by validating the pointer logic
            if (start % 4096 == 0) { // ELF allocations are page-aligned
                uint32_t magic = *reinterpret_cast<uint32_t*>(start);
                if (magic == 0x464c457f) {
                    LOGI("Target match found: %s", line);
                    base = start;
                    break;
                }
            }
        }
    }
    fclose(fp);
    return base;
}

void hack_start(std::string game_data_dir) {
    // Wait for the game to fully unpack/decrypt its memory structures
    LOGI("hack_start: Execution delayed. Pacing for 12 seconds...");
    sleep(12);

    LOGI("hack_start: Scanning for game memory structures...");
    uintptr_t base_address = 0;
    for (int i = 0; i < 60; i++) {
        base_address = find_il2cpp_base();
        if (base_address != 0) break;
        sleep(1);
    }

    if (base_address == 0) {
        LOGE("Aborted: Could not locate a valid game binary segment.");
        return;
    }

    LOGI("Initialization handshake successful. Target base verified at: %p", (void*)base_address);

    // Call initializer with the safely isolated base address
    il2cpp_api_init((void*)base_address); 
    il2cpp_dump(game_data_dir.c_str());
}

// Entrypoint required by main.cpp
void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("hack_prepare: Forking execution thread...");
    std::string dir_str(game_data_dir);
    std::thread hack_thread(hack_start, dir_str);
    hack_thread.detach();
}
