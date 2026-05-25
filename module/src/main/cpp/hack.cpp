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

// Universal ELF scanner with debug logging
static uintptr_t find_il2cpp_base() {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    uintptr_t base = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "r-x")) {
            uintptr_t start = strtoul(line, nullptr, 16);
            
            // Validate ELF Magic (0x7F 'E' 'L' 'F')
            uint32_t magic = *reinterpret_cast<uint32_t*>(start);
            if (magic == 0x464c457f) {
                // LOG WHAT WE FOUND to ensure it's not libc.so or libmain.so
                LOGI("Found ELF at: %p | Map Info: %s", (void*)start, line);
                
                // If the log shows it's grabbing the wrong library, you can add 
                // a check here like: if(strstr(line, "anon")) { base = start; break; }
                base = start;
                break;
            }
        }
    }
    fclose(fp);
    return base;
}

void hack_start(std::string game_data_dir) {
    // 1. DELAY EXECUTION: Give the game time to decrypt the protected binary
    LOGI("hack_start: Waiting 10 seconds for game to unpack/decrypt...");
    sleep(10);

    LOGI("hack_start: Scanning memory segments...");

    uintptr_t base_address = 0;
    for (int i = 0; i < 60; i++) {
        base_address = find_il2cpp_base();
        if (base_address != 0) break;
        sleep(1);
    }

    if (base_address == 0) {
        LOGE("Aborted: Could not locate any executable ELF segment in memory.");
        return;
    }

    // 2. VERIFY YOUR OFFSET
    uint64_t il2cpp_init_offset = 0x1D3C0E4; 
    void* init_fn = reinterpret_cast<void*>(base_address + il2cpp_init_offset);
    
    // Read the first 4 bytes of your target to verify it is decrypted code
    uint32_t target_instruction = *reinterpret_cast<uint32_t*>(init_fn);
    LOGI("Mapping success. Base: %p, Target: %p, Target First Bytes: 0x%X", 
         (void*)base_address, init_fn, target_instruction);

    // 3. INITIALIZE API
    // Pass the BASE ADDRESS, not the init_fn. The dumper needs the base to resolve symbols.
    if (base_address != 0) {
        il2cpp_api_init((void*)base_address); 
        il2cpp_dump(game_data_dir.c_str());
    } else {
        LOGE("Critical Error: Calculation resulted in a null pointer.");
    }
}

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("hack_prepare: Spawning delayed dumper thread...");
    
    // Pass the path by value to the thread to avoid dangling pointers
    std::string dir_str(game_data_dir);
    
    // Run the dump process in a separate thread so the game can continue loading
    std::thread hack_thread(hack_start, dir_str);
    hack_thread.detach();
}
