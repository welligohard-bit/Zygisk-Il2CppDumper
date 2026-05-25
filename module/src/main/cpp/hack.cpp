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

// Targets the custom decrypted memory segment allocated by the unpacker
static uintptr_t find_il2cpp_base() {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    uintptr_t base = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        // Target execution spaces containing the custom unpacker memory pool tag
        if ((strstr(line, "r-x") || strstr(line, "rwx")) && strstr(line, "anon:Mem_")) {
            
            uintptr_t start = 0;
            uintptr_t end = 0;
            if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &start, &end) != 2) {
                continue;
            }

            size_t region_size = end - start;

            // Double check size to ensure we grab the primary code container (~62 MB)
            if (region_size > 20 * 1024 * 1024) {
                LOGI("Target base successfully isolated: %s", line);
                base = start;
                break;
            }
        }
    }
    fclose(fp);
    return base;
}

void hack_start(std::string game_data_dir) {
    // 16-second pacing window to allow the execution container to complete unpacking
    LOGI("hack_start: Waiting for custom memory layout generation...");
    sleep(16);

    LOGI("hack_start: Intercepting custom memory spaces...");
    uintptr_t base_address = 0;
    for (int i = 0; i < 60; i++) {
        base_address = find_il2cpp_base();
        if (base_address != 0) break;
        sleep(1);
    }

    if (base_address == 0) {
        LOGE("Aborted: The targeted custom memory container was not found.");
        return;
    }

    LOGI("Initialization handshake successful. Target base verified at: %p", (void*)base_address);

    // Provide the isolated base pointer directly to the dumper logic
    il2cpp_api_init((void*)base_address); 
    il2cpp_dump(game_data_dir.c_str());
}

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("hack_prepare: Forking target execution thread...");
    std::string dir_str(game_data_dir);
    std::thread hack_thread(hack_start, dir_str);
    hack_thread.detach();
}
