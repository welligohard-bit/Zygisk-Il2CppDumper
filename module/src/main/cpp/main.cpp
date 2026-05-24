#include <cstring>
#include <thread>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <cinttypes>
#include <dlfcn.h> // Added for dlopen
#include "hack.h"
#include "zygisk.hpp"
#include "game.h"
#include "log.h"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

class MyModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        auto package_name = env->GetStringUTFChars(args->nice_name, nullptr);
        auto app_data_dir = env->GetStringUTFChars(args->app_data_dir, nullptr);
        preSpecialize(package_name, app_data_dir);
        env->ReleaseStringUTFChars(args->nice_name, package_name);
        env->ReleaseStringUTFChars(args->app_data_dir, app_data_dir);
    }

    void postAppSpecialize(const AppSpecializeArgs *) override {
        if (enable_hack) {
            std::thread hack_thread([this]() {
                LOGI("Dump thread started. Scanning memory maps for libil2cpp.so...");
                
                bool found = false;
                int attempts = 0;
                
                // Poll every 1 second for up to 120 seconds
                while (!found && attempts < 120) {
                    FILE *fp = fopen("/proc/self/maps", "re");
                    if (fp) {
                        char line[512];
                        while (fgets(line, sizeof(line), fp)) {
                            if (strstr(line, "libil2cpp.so") != nullptr) {
                                found = true;
                                break;
                            }
                        }
                        fclose(fp);
                    }
                    
                    if (!found) {
                        attempts++;
                        sleep(1);
                    }
                }

                if (found) {
                    LOGI("libil2cpp.so detected via maps! Giving the engine 2 seconds to settle...");
                    sleep(2); // Short grace period to ensure initialization completes
                    hack_prepare(game_data_dir, data, length);
                } else {
                    LOGE("Timeout: libil2cpp.so never appeared in memory maps.");
                }
            });
            hack_thread.detach();
        }
    }
                
             // Poll every 1 second, up to 120 seconds max
while (handle == nullptr && attempts < 120) {
    handle = dlopen("libil2cpp.so", RTLD_NOLOAD);
    if (handle == nullptr) {
        attempts++;
        sleep(1); 
    }
}

                if (handle != nullptr) {
                    LOGI("libil2cpp.so detected in memory! Starting hack_prepare...");
                    hack_prepare(game_data_dir, data, length);
                } else {
                    LOGE("Timeout: libil2cpp.so was never loaded by the game.");
                }
            });
            hack_thread.detach();
        }
    }

private:
    Api *api;
    JNIEnv *env;
    bool enable_hack;
    char *game_data_dir;
    void *data;
    size_t length;

    void preSpecialize(const char *package_name, const char *app_data_dir) {
        if (strcmp(package_name, GamePackageName) == 0) {
            LOGI("detect game: %s", package_name);
            enable_hack = true;
            game_data_dir = new char[strlen(app_data_dir) + 1];
            strcpy(game_data_dir, app_data_dir);

#if defined(__i386__)
            auto path = "zygisk/armeabi-v7a.so";
#endif
#if defined(__x86_64__)
            auto path = "zygisk/arm64-v8a.so";
#endif
#if defined(__i386__) || defined(__x86_64__)
            int dirfd = api->getModuleDir();
            int fd = openat(dirfd, path, O_RDONLY);
            if (fd != -1) {
                struct stat sb{};
                fstat(fd, &sb);
                length = sb.st_size;
                data = mmap(nullptr, length, PROT_READ, MAP_PRIVATE, fd, 0);
                close(fd);
            } else {
                LOGW("Unable to open arm file");
            }
#endif
        } else {
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }
    }
};

REGISTER_ZYGISK_MODULE(MyModule)
