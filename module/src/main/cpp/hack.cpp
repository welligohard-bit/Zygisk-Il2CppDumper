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

// Reusable Universal Scanner: Identifies and targets non-standard, large executable spaces
static uintptr_t find_il2cpp_base() {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    uintptr_t base = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        // Look for any executable memory (standard or read-write-execute)
        if (strstr(line, "r-x") || strstr(line, "rwx")) {
            
            // 1. Filter out known system layers and tool signatures
            if (strstr(line, "/system/") || 
                strstr(line, "/apex/") || 
                strstr(line, "/vendor/") || 
                strstr(line, "linker") || 
                strstr(line, "libc.so") || 
                strstr(line, "libart.so") || 
                strstr(line, "libmain.so") ||
                strstr(line, "zygisk") ||          
                strstr(line, "memfd") ||          
                strstr(line, "dalvik") ||          
                strstr(line, "/dev/ashmem") ||     
                strstr(line, "[vdso]") ||        
                strstr(line, "[vectors]")) {
                continue;
            }

            uintptr_t start = 0;
            uintptr_t end = 0;
            if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &start, &end) != 2) {
                continue;
            }

            size_t region_size = end - start;

            // Trim trailing newline for clean logcat visibility
            line[strcspn(line, "\n")] = 0;

            // 2. Log potential game engine logic candidates across variants
            LOGI("POTENTIAL TARGET: Size: %zu MB | Layout: %s", region_size / (1024 * 1024), line);

            // 3. Automated Selector: If it survives filters and holds a game engine size profile (>20MB)
            if (region_size > 20 * 1024 * 1024) {
                LOGI("--> Match Selected: %s", line);
                base = start;
                break;
            }
        }
    }
    fclose(fp);
    return base;
}

void hack_start(std::string game_data_dir) {
    // 16-second window allows unpacking/decryption processes to fully stabilize in memory
    LOGI("hack_start: Waiting for memory initialization loops...");
    sleep(16);

    LOGI("hack_start: Running dynamic map analysis...");
    uintptr_t base_address = 0;
    for (int i = 0; i < 60; i++) {
        base_address = find_il2cpp_base();
        if (base_address != 0) break;
        sleep(1);
    }

    if (base_address == 0) {
        LOGE("Aborted: Could not dynamically isolate any game logic segment.");
        return;
    }

    LOGI("Handshake successful. Binding framework to base address: %p", (void*)base_address);

    uintptr_t metadata_magic = 0xFAB11BAF; // Or 0xAF1BB1FA
    for (uintptr_t i = base_address; i < base_address + (62 * 1024 * 1024); i += 4) {
        if (*reinterpret_cast<uint32_t*>(i) == metadata_magic) {
            LOGI("LIVE METADATA FOUND IN MEMORY AT OFFSET: 0x%" PRIxPTR, i - base_address);
            break;
        }
    }
    
    // Initialize parsing sequence with the dynamically isolated memory block
   //il2cpp_api_init((void*)base_address); 
   // il2cpp_dump(game_data_dir.c_str());
}

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("hack_prepare: Forking multi-game dumper thread...");
    std::string dir_str(game_data_dir);
    std::thread hack_thread(hack_start, dir_str);
    hack_thread.detach();
}
