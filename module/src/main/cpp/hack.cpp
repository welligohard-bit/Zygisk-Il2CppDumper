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

// Diagnostic Logger: Prints all executable segments to logcat for analysis
static void analyze_memory_layout() {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE("Diagnostic Error: Unable to open /proc/self/maps");
        return;
    }

    char line[512];
    LOGI("======================= MEMORY MAP DIAGNOSTIC START =======================");
    
    while (fgets(line, sizeof(line), fp)) {
        // Log absolutely EVERY executable segment regardless of size or name
        if (strstr(line, "r-x") || strstr(line, "rwx")) {
            
            uintptr_t start = 0;
            uintptr_t end = 0;
            sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &start, &end);
            size_t region_size = end - start;

            // Trim trailing newline for clean logs
            line[strcspn(line, "\n")] = 0;

            LOGI("EXEC REGION: Size: %zu KB (%zu MB) | Layout: %s", 
                 region_size / 1024, 
                 region_size / (1024 * 1024), 
                 line);
        }
    }
    
    LOGI("======================== MEMORY MAP DIAGNOSTIC END ========================");
    fclose(fp);
}

void hack_start(std::string game_data_dir) {
    // 16-second delay to ensure the game engine has completed initialization/decryption
    LOGI("hack_start: Diagnostic pacing delay running...");
    sleep(16);

    // Run the comprehensive map analysis
    analyze_memory_layout();
}

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("hack_prepare: Spawning diagnostic pipeline...");
    std::string dir_str(game_data_dir);
    std::thread hack_thread(hack_start, dir_str);
    hack_thread.detach();
}
