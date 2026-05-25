#include "hack.h"
#include "il2cpp_dump.h"
#include "log.h"
#include "xdl.h"
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <jni.h>
#include <thread>
#include <sys/mman.h>
#include <linux/unistd.h>
#include <array>
#include <vector>
#include <string>
#include <cstdint>

// Forward declarations
void hack_start(const char *game_data_dir);

void hack_start(const char *game_data_dir) {
    void *handle = nullptr;
    LOGI("hack_start: Waiting for libil2cpp.so to map...");

    // 1. Wait for library to appear
    for (int i = 0; i < 30; i++) {
        handle = xdl_open("libil2cpp.so", 0);
        if (handle) break;
        sleep(2);
    }

    if (!handle) {
        LOGE("Aborted: libil2cpp.so not found.");
        return;
    }

    // 2. Wait for library memory to be readable
    xdl_info_t info;
    bool ready = false;
    // Change to 60 iterations (60 seconds)
for (int i = 0; i < 60; i++) {
    if (xdl_info(handle, XDL_DI_DLINFO, &info) && info.dli_fbase != nullptr) {
        ready = true;
        break;
    }
    sleep(1);
}

    if (!ready) {
        LOGE("Aborted: libil2cpp.so found but base address is null.");
        xdl_close(handle);
        return;
    }

    // 3. Apply offset mapping
    uint64_t base_address = reinterpret_cast<uint64_t>(info.dli_fbase);
    uint64_t il2cpp_init_offset = 0x1D3C0E4; 
    void* init_fn = reinterpret_cast<void*>(base_address + il2cpp_init_offset);

    LOGI("Mapping success. Base: %p, Target: %p", info.dli_fbase, init_fn);
    
    if (init_fn != nullptr) {
        il2cpp_api_init(init_fn); 
        il2cpp_dump(game_data_dir);
    } else {
        LOGE("Critical Error: Calculation resulted in a null pointer.");
    }
    
    xdl_close(handle);
}

// --- Helper Functions ---
std::string GetLibDir(JavaVM *vms) {
    JNIEnv *env = nullptr;
    vms->AttachCurrentThread(&env, nullptr);
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz != nullptr) {
        jmethodID currentApplicationId = env->GetStaticMethodID(activity_thread_clz, "currentApplication", "()Landroid/app/Application;");
        if (currentApplicationId) {
            jobject application = env->CallStaticObjectMethod(activity_thread_clz, currentApplicationId);
            jclass application_clazz = env->GetObjectClass(application);
            if (application_clazz) {
                jmethodID get_application_info = env->GetMethodID(application_clazz, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
                if (get_application_info) {
                    jobject application_info = env->CallObjectMethod(application, get_application_info);
                    jfieldID native_library_dir_id = env->GetFieldID(env->GetObjectClass(application_info), "nativeLibraryDir", "Ljava/lang/String;");
                    if (native_library_dir_id) {
                        auto native_library_dir_jstring = (jstring) env->GetObjectField(application_info, native_library_dir_id);
                        auto path = env->GetStringUTFChars(native_library_dir_jstring, nullptr);
                        std::string lib_dir(path);
                        env->ReleaseStringUTFChars(native_library_dir_jstring, path);
                        return lib_dir;
                    }
                }
            }
        }
    }
    return {};
}

static std::string GetNativeBridgeLibrary() {
    auto value = std::array<char, PROP_VALUE_MAX>();
    __system_property_get("ro.dalvik.vm.native.bridge", value.data());
    return {value.data()};
}

struct NativeBridgeCallbacks {
    uint32_t version;
    void *initialize;
    void *(*loadLibrary)(const char *libpath, int flag);
    void *(*getTrampoline)(void *handle, const char *name, const char *shorty, uint32_t len);
    void *isSupported, *getAppEnv, *isCompatibleWith, *getSignalHandler, *unloadLibrary, *getError, *isPathSupported, *initAnonymousNamespace, *createNamespace, *linkNamespaces;
    void *(*loadLibraryExt)(const char *libpath, int flag, void *ns);
};

bool NativeBridgeLoad(const char *game_data_dir, int api_level, void *data, size_t length) {
    sleep(5);
    auto libart = dlopen("libart.so", RTLD_NOW);
    auto JNI_GetCreatedJavaVMs = (jint (*)(JavaVM **, jsize, jsize *)) dlsym(libart, "JNI_GetCreatedJavaVMs");
    JavaVM *vms_buf[1];
    jsize num_vms;
    if (JNI_GetCreatedJavaVMs(vms_buf, 1, &num_vms) == JNI_OK && num_vms > 0) {
        auto lib_dir = GetLibDir(vms_buf[0]);
        if (!lib_dir.empty() && lib_dir.find("/lib/x86") == std::string::npos) {
            auto nb = dlopen("libhoudini.so", RTLD_NOW);
            if (!nb) nb = dlopen(GetNativeBridgeLibrary().data(), RTLD_NOW);
            if (nb) {
                auto callbacks = (NativeBridgeCallbacks *) dlsym(nb, "NativeBridgeItf");
                if (callbacks) {
                    int fd = syscall(__NR_memfd_create, "anon", MFD_CLOEXEC);
                    ftruncate(fd, (off_t) length);
                    void *mem = mmap(nullptr, length, PROT_WRITE, MAP_SHARED, fd, 0);
                    memcpy(mem, data, length);
                    munmap(mem, length);
                    munmap(data, length);
                    char path[PATH_MAX];
                    snprintf(path, PATH_MAX, "/proc/self/fd/%d", fd);
                    void *arm_handle = (api_level >= 26) ? callbacks->loadLibraryExt(path, RTLD_NOW, (void *) 3) : callbacks->loadLibrary(path, RTLD_NOW);
                    if (arm_handle) {
                        auto init = (void (*)(JavaVM *, void *)) callbacks->getTrampoline(arm_handle, "JNI_OnLoad", nullptr, 0);
                        init(vms_buf[0], (void *) game_data_dir);
                        return true;
                    }
                    close(fd);
                }
            }
        }
    }
    return false;
}

// --- The missing function required by main.cpp ---
void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("hack_prepare: Initializing...");
    int api_level = android_get_device_api_level();
#if defined(__i386__) || defined(__x86_64__)
    if (!NativeBridgeLoad(game_data_dir, api_level, data, length)) {
#endif
        hack_start(game_data_dir);
#if defined(__i386__) || defined(__x86_64__)
    }
#endif
}

#if defined(__arm__) || defined(__aarch64__)
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    auto game_data_dir = (const char *) reserved;
    std::thread hack_thread(hack_start, game_data_dir);
    hack_thread.detach();
    return JNI_VERSION_1_6;
}
#endif
