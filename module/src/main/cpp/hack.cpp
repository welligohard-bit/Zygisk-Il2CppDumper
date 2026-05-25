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

// Scans for the unbacked, decrypted game engine block based on memory layout size
static uintptr_t find_il2cpp_base() {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    uintptr_t base = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        // 1. Must be an executable segment
        if (strstr(line, "r-x")) {
            
            // 2. Filter out standard system libraries and dependencies
            if (strstr(line, "/system/") || 
                strstr(line, "/apex/") || 
                strstr(line, "/vendor/") || 
                strstr(line, "linker") || 
                strstr(line, "libc.so") || 
                strstr(line, "libart.so") || 
                strstr(line, "libmain.so") ||
                strstr(line, "zygisk") ||          
                strstr(line, "[vdso]") ||          
                strstr(line, "[vectors]")) {
                continue;
            }

            // Extract memory range boundaries
            uintptr_t start = 0;
            uintptr_t end = 0;
            if (sscanf(line, "%lx-%lx", &start, &end) != 2) {
                continue;
            }

            // Calculate exact allocation size
            size_t region_size = end - start;

            // 3. TARGET HEURISTIC: 
            // Look for a large, unnamed executable memory allocation (typically > 15MB)
            // Protected binaries are large, while system hook fragments are small.
            // Also ensure it doesn't contain a file path (checking for '/' or '.so')
            if (region_size > 15 * 1024 * 1024 && !strstr(line, "/") && !strstr(line, ".so")) {
                LOGI("Target match found by layout size (%zu MB): %s", region_size / (1024 * 1024), line);
                base = start;
                break;
            }
        }
    }
    fclose(fp);
    return base;
}

void hack_start(std::string game_data_dir) {
    // Standard delay to ensure unpacking/decryption sequence completes
    LOGI("hack_start: Execution delayed. Pacing for 12 seconds...");
    sleep(12);

    LOGI("hack_start: Scanning for decrypted layout structures...");
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

    LOGI("Initialization handshake successful. Target base isolated at: %p", (void*)base_address);

    // Provide isolated base to initialize parsing sequences
    il2cpp_api_init((void*)base_address); 
    il2cpp_dump(game_data_dir.c_str());
}

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("hack_prepare: Forking execution thread...");
    std::string dir_str(game_data_dir);
    std::thread hack_thread(hack_start, dir_str);
    hack_thread.detach();
}
