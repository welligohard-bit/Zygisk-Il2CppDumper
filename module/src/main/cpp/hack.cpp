#include "hack.h"
#include "il2cpp_dump.h"
#include "log.h"
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cinttypes>
#include <sys/mman.h>
#include <thread>
#include <string>

// Scans all readable memory segments for the decrypted metadata file
static void find_live_metadata() {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE("Failed to open memory maps.");
        return;
    }

    char line[512];
    uint32_t magic_little_endian = 0xFAB11BAF; // Standard AF 1B B1 FA
    uint32_t magic_big_endian    = 0xAF1BB1FA; // Fallback
    
    LOGI("================ STARTING GLOBAL METADATA SCAN ================");
    
    while (fgets(line, sizeof(line), fp)) {
        // Metadata is data, so it resides in readable (r--) or read-write (rw-) segments
        if (strstr(line, "r--") || strstr(line, "rw-") || strstr(line, "r-x")) {
            
            // Skip system libraries, drivers, and caches to prevent Segmentation Faults
            if (strstr(line, "/system/") || 
                strstr(line, "/vendor/") || 
                strstr(line, "/apex/") || 
                strstr(line, "linker") || 
                strstr(line, "dalvik") || 
                strstr(line, "kgsl") ||       // Skip GPU memory
                strstr(line, "mali")) {       // Skip GPU memory
                continue;
            }

            uintptr_t start = 0, end = 0;
            if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &start, &end) != 2) {
                continue;
            }

            size_t size = end - start;
            
            // Metadata files typically range from 1MB to 40MB. Skip anything too small or massively huge.
            if (size < 500 * 1024 || size > 50 * 1024 * 1024) {
                continue;
            }

            // Clean newline for logging
            line[strcspn(line, "\n")] = 0;

            // Scan this specific segment for the magic bytes
            for (uintptr_t ptr = start; ptr < end - 4; ptr += 4) {
                // Safely read the pointer
                uint32_t val = *reinterpret_cast<uint32_t*>(ptr);
                
                if (val == magic_little_endian || val == magic_big_endian) {
                    LOGI("🎯 BINGO! LIVE METADATA FOUND AT ADDRESS: %p", (void*)ptr);
                    LOGI("🎯 Residing in memory layout: %s", line);
                    
                    fclose(fp);
                    return; // Stop scanning once found
                }
            }
        }
    }
    
    fclose(fp);
    LOGE("Global scan complete. Magic bytes were not found anywhere in memory.");
}

void hack_start(std::string game_data_dir) {
    // 16-second delay ensures the game has fully decrypted and loaded the metadata
    LOGI("hack_start: Delaying 16 seconds for game engine initialization...");
    sleep(16);

    // Run the global scanner
    find_live_metadata();
}

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("hack_prepare: Forking metadata scanner thread...");
    std::string dir_str(game_data_dir);
    std::thread hack_thread(hack_start, dir_str);
    hack_thread.detach();
}
