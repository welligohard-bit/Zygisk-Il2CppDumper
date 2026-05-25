#include "hack.h"
#include "il2cpp_dump.h"
#include "log.h"
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cinttypes>   // Required for cross-platform PRIxPTR / SCNxPTR macros
#include <sys/mman.h>
#include <thread>
#include <string>

// Advanced scanner hunting for anonymous, unnamed executable segments
static uintptr_t find_il2cpp_base() {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    uintptr_t base = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        // 1. Must be a read-execute segment
        if (strstr(line, "r-x")) {
            
            // 2. Strict system exclusion filters
            if (strstr(line, "/system/") || 
                strstr(line, "/apex/") || 
                strstr(line, "/vendor/") || 
                strstr(line, "/data/") ||   // Exclude path-backed app files
                strstr(line, "linker") || 
                strstr(line, "libc.so") || 
                strstr(line, "libart.so") || 
                strstr(line, "libmain.so") ||
                strstr(line, "zygisk") ||          
                strstr(line, "memfd") ||          
                strstr(line, "[") ||        // Strips [vdso], [vectors], [anon:...], etc.
                strstr(line, "]")) {
                continue;
            }

            // Extract memory boundaries
            uintptr_t start = 0;
            uintptr_t end = 0;
            if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &start, &end) != 2) {
                continue;
            }

            size_t region_size = end - start;

            // 3. Lowered Heuristic Threshold:
            // Look for any completely unnamed executable allocation larger than 3MB.
            // A clean, anonymous memory region will have empty space where the path usually is.
            if (region_size > 3 * 1024 * 1024) {
                LOGI("Target match found by anonymous layout (%zu MB): %s", region_size / (1024 * 1024), line);
                base = start;
                break;
            }
        }
    }
    fclose(fp);
    return base;
}

void hack_start(std::string game_data_dir) {
    // Extended pacing delay to ensure the manual mapping engine finishes loading
    LOGI("hack_start: Delaying execution for 16 seconds to allow unpacker processing...");
    sleep(16);

    LOGI("hack_start: Scanning for decrypted code structures...");
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
