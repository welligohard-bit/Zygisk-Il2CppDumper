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

// Advanced ELF scanner: filters out system and tool-specific memory spaces
static uintptr_t find_il2cpp_base() {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    uintptr_t base = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        // Look strictly for executable regions
        if (strstr(line, "r-x")) {
            
            // Comprehensive exclusion list to prevent targeting hook tools or system libs
            if (strstr(line, "/system/") || 
                strstr(line, "/apex/") || 
                strstr(line, "/vendor/") || 
                strstr(line, "linker") || 
                strstr(line, "libc.so") || 
                strstr(line, "libart.so") || 
                strstr(line, "libmain.so") ||
                strstr(line, "zygisk") ||          // Skip Zygisk injection modules
                strstr(line, "jit-cache") ||       // Skip JIT runtime caches
                strstr(line, "memfd")) {           // Skip anonymous file descriptors
                continue;
            }

            uintptr_t start = strtoul(line, nullptr, 16);
            
            // Check boundaries on page-aligned allocations
            if (start % 4096 == 0) {
                // Safely catch the pointer target
                uint32_t magic = *reinterpret_cast<uint32_t*>(start);
                if (magic == 0x464c457f) { // Valid ELF format identification
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

    // Run initialization natively using the safely isolated base
    il2cpp_api_init((void*)base_address); 
    il2cpp_dump(game_data_dir.c_str());
}

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("hack_prepare: Forking execution thread...");
    std::string dir_str(game_data_dir);
    std::thread hack_thread(hack_start, dir_str);
    hack_thread.detach();
}
