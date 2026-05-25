//
// Created by Perfare on 2020/7/4.
// Updated for Anonymous Memory/Stripped Engine layouts
//

#include "il2cpp_dump.h"
#include <dlfcn.h>
#include <cstdlib>
#include <cstring>
#include <cinttypes>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <unistd.h>
#include "xdl.h"
#include "log.h"
#include "il2cpp-tabledefs.h"
#include "il2cpp-class.h"

// Instantiate the function pointers globally
#define DO_API(r, n, p) r (*n) p
#include "il2cpp-api-functions.h"
#undef DO_API

static uint64_t il2cpp_base = 0;

// Bypasses the stripped symbol table using explicit offsets found in Ghidra
// Uses decltype to perfectly match expected function pointer signatures
void init_il2cpp_api_direct(uintptr_t base) {
    LOGI("init_il2cpp_api_direct: Mapping function pointers via explicit offsets...");

    // Example Offsets (Replace the hex values with your actual Ghidra findings)
    
    // Core Initialization
    il2cpp_init                        = reinterpret_cast<decltype(il2cpp_init)>(base + 0x1D3C0E4); // <-- Your verified offset
    il2cpp_domain_get                  = reinterpret_cast<decltype(il2cpp_domain_get)>(base + 0x1A2B3C4); 
    il2cpp_domain_get_assemblies       = reinterpret_cast<decltype(il2cpp_domain_get_assemblies)>(base + 0x2B3C4D5); 
    il2cpp_assembly_get_image          = reinterpret_cast<decltype(il2cpp_assembly_get_image)>(base + 0x3C4D5E6); 
    il2cpp_image_get_name              = reinterpret_cast<decltype(il2cpp_image_get_name)>(base + 0x4D5E6F7); 
    
    // Version specific check pointers (2018.3+)
    il2cpp_image_get_class_count       = reinterpret_cast<decltype(il2cpp_image_get_class_count)>(base + 0x5E6F7A8); 
    il2cpp_image_get_class             = reinterpret_cast<decltype(il2cpp_image_get_class)>(base + 0x6F7A8B9); 
    il2cpp_class_get_type              = reinterpret_cast<decltype(il2cpp_class_get_type)>(base + 0x7A8B9C0); 
    
    // Core structural descriptors
    il2cpp_class_from_type             = reinterpret_cast<decltype(il2cpp_class_from_type)>(base + 0x8B9C0D1); 
    il2cpp_class_get_name              = reinterpret_cast<decltype(il2cpp_class_get_name)>(base + 0x9C0D1E2); 
    il2cpp_class_get_namespace         = reinterpret_cast<decltype(il2cpp_class_get_namespace)>(base + 0xAD1E2F3); 
    il2cpp_class_get_flags             = reinterpret_cast<decltype(il2cpp_class_get_flags)>(base + 0xBE2F304); 
    il2cpp_class_is_valuetype          = reinterpret_cast<decltype(il2cpp_class_is_valuetype)>(base + 0xCF30415); 
    il2cpp_class_is_enum               = reinterpret_cast<decltype(il2cpp_class_is_enum)>(base + 0xDF40526); 
    il2cpp_class_get_parent            = reinterpret_cast<decltype(il2cpp_class_get_parent)>(base + 0xEF50637); 
    il2cpp_class_get_interfaces        = reinterpret_cast<decltype(il2cpp_class_get_interfaces)>(base + 0xFF60748); 
    
    // Core member iterators
    il2cpp_class_get_fields            = reinterpret_cast<decltype(il2cpp_class_get_fields)>(base + 0x1170859); 
    il2cpp_class_get_methods           = reinterpret_cast<decltype(il2cpp_class_get_methods)>(base + 0x228096A); 
    il2cpp_class_get_properties        = reinterpret_cast<decltype(il2cpp_class_get_properties)>(base + 0x3390A7B); 
    
    // Member details extraction variables
    il2cpp_field_get_flags             = reinterpret_cast<decltype(il2cpp_field_get_flags)>(base + 0x44A0B8C); 
    il2cpp_field_get_type              = reinterpret_cast<decltype(il2cpp_field_get_type)>(base + 0x55B0C9D); 
    il2cpp_field_get_name              = reinterpret_cast<decltype(il2cpp_field_get_name)>(base + 0x66C0DAE); 
    il2cpp_field_static_get_value      = reinterpret_cast<decltype(il2cpp_field_static_get_value)>(base + 0x77D0EBF); 
    il2cpp_field_get_offset            = reinterpret_cast<decltype(il2cpp_field_get_offset)>(base + 0x88E0FC0); 
    
    il2cpp_method_get_flags            = reinterpret_cast<decltype(il2cpp_method_get_flags)>(base + 0x99F01D1); 
    il2cpp_method_get_return_type      = reinterpret_cast<decltype(il2cpp_method_get_return_type)>(base + 0xAAF02E2); 
    il2cpp_method_get_name             = reinterpret_cast<decltype(il2cpp_method_get_name)>(base + 0xBBF03F3); 
    il2cpp_method_get_param_count      = reinterpret_cast<decltype(il2cpp_method_get_param_count)>(base + 0xCCF04F4); 
    il2cpp_method_get_param            = reinterpret_cast<decltype(il2cpp_method_get_param)>(base + 0xDDF05F5); 
    il2cpp_method_get_param_name       = reinterpret_cast<decltype(il2cpp_method_get_param_name)>(base + 0xEEF06F6); 
    
    il2cpp_property_get_get_method     = reinterpret_cast<decltype(il2cpp_property_get_get_method)>(base + 0xFFF07F7); 
    il2cpp_property_get_set_method     = reinterpret_cast<decltype(il2cpp_property_get_set_method)>(base + 0x11008F8); 
    il2cpp_property_get_name           = reinterpret_cast<decltype(il2cpp_property_get_name)>(base + 0x22109F9); 
    
    // Thread environment contexts
    il2cpp_is_vm_thread                = reinterpret_cast<decltype(il2cpp_is_vm_thread)>(base + 0x3320AF0); 
    il2cpp_thread_attach               = reinterpret_cast<decltype(il2cpp_thread_attach)>(base + 0x4430BF1); 
}

std::string get_method_modifier(uint32_t flags) {
    std::stringstream outPut;
    auto access = flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK;
    switch (access) {
        case METHOD_ATTRIBUTE_PRIVATE: outPut << "private "; break;
        case METHOD_ATTRIBUTE_PUBLIC: outPut << "public "; break;
        case METHOD_ATTRIBUTE_FAMILY: outPut << "protected "; break;
        case METHOD_ATTRIBUTE_ASSEM:
        case METHOD_ATTRIBUTE_FAM_AND_ASSEM: outPut << "internal "; break;
        case METHOD_ATTRIBUTE_FAM_OR_ASSEM: outPut << "protected internal "; break;
    }
    if (flags & METHOD_ATTRIBUTE_STATIC) outPut << "static ";
    if (flags & METHOD_ATTRIBUTE_ABSTRACT) {
        outPut << "abstract ";
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT) outPut << "override ";
    } else if (flags & METHOD_ATTRIBUTE_FINAL) {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT) outPut << "sealed override ";
    } else if (flags & METHOD_ATTRIBUTE_VIRTUAL) {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_NEW_SLOT) outPut << "virtual ";
        else outPut << "override ";
    }
    if (flags & METHOD_ATTRIBUTE_PINVOKE_IMPL) outPut << "extern ";
    return outPut.str();
}

bool _il2cpp_type_is_byref(const Il2CppType *type) {
    auto byref = type->byref;
    if (il2cpp_type_is_byref) {
        byref = il2cpp_type_is_byref(type);
    }
    return byref;
}

std::string dump_method(Il2CppClass *klass) {
    std::stringstream outPut;
    outPut << "\n\t// Methods\n";
    void *iter = nullptr;
    while (auto method = il2cpp_class_get_methods(klass, &iter)) {
        if (method->methodPointer) {
            outPut << "\t// RVA: 0x" << std::hex << (uint64_t) method->methodPointer - il2cpp_base;
            outPut << " VA: 0x" << std::hex << (uint64_t) method->methodPointer;
        } else {
            outPut << "\t// RVA: 0x VA: 0x0";
        }
        outPut << "\n\t";
        uint32_t iflags = 0;
        auto flags = il2cpp_method_get_flags(method, &iflags);
        outPut << get_method_modifier(flags);
        auto return_type = il2cpp_method_get_return_type(method);
        if (_il2cpp_type_is_byref(return_type)) outPut << "ref ";
        auto return_class = il2cpp_class_from_type(return_type);
        outPut << il2cpp_class_get_name(return_class) << " " << il2cpp_method_get_name(method) << "(";
        auto param_count = il2cpp_method_get_param_count(method);
        for (int i = 0; i < param_count; ++i) {
            auto param = il2cpp_method_get_param(method, i);
            auto attrs = param->attrs;
            if (_il2cpp_type_is_byref(param)) {
                if (attrs & PARAM_ATTRIBUTE_OUT && !(attrs & PARAM_ATTRIBUTE_IN)) outPut << "out ";
                else if (attrs & PARAM_ATTRIBUTE_IN && !(attrs & PARAM_ATTRIBUTE_OUT)) outPut << "in ";
                else outPut << "ref ";
            } else {
                if (attrs & PARAM_ATTRIBUTE_IN) outPut << "[In] ";
                if (attrs & PARAM_ATTRIBUTE_OUT) outPut << "[Out] ";
            }
            auto parameter_class = il2cpp_class_from_type(param);
            outPut << il2cpp_class_get_name(parameter_class) << " " << il2cpp_method_get_param_name(method, i) << ", ";
        }
        if (param_count > 0) outPut.seekp(-2, outPut.cur);
        outPut << ") { }\n";
    }
    return outPut.str();
}

std::string dump_property(Il2CppClass *klass) {
    std::stringstream outPut;
    outPut << "\n\t// Properties\n";
    void *iter = nullptr;
    while (auto prop_const = il2cpp_class_get_properties(klass, &iter)) {
        auto prop = const_cast<PropertyInfo *>(prop_const);
        auto get = il2cpp_property_get_get_method(prop);
        auto set = il2cpp_property_get_set_method(prop);
        auto prop_name = il2cpp_property_get_name(prop);
        outPut << "\t";
        Il2CppClass *prop_class = nullptr;
        uint32_t iflags = 0;
        if (get) {
            outPut << get_method_modifier(il2cpp_method_get_flags(get, &iflags));
            prop_class = il2cpp_class_from_type(il2cpp_method_get_return_type(get));
        } else if (set) {
            outPut << get_method_modifier(il2cpp_method_get_flags(set, &iflags));
            auto param = il2cpp_method_get_param(set, 0);
            prop_class = il2cpp_class_from_type(param);
        }
        if (prop_class) {
            outPut << il2cpp_class_get_name(prop_class) << " " << prop_name << " { ";
            if (get) outPut << "get; ";
            if (set) outPut << "set; ";
            outPut << "}\n";
        } else {
            if (prop_name) outPut << " // unknown property " << prop_name;
        }
    }
    return outPut.str();
}

std::string dump_field(Il2CppClass *klass) {
    std::stringstream outPut;
    outPut << "\n\t// Fields\n";
    auto is_enum = il2cpp_class_is_enum(klass);
    void *iter = nullptr;
    while (auto field = il2cpp_class_get_fields(klass, &iter)) {
        outPut << "\t";
        auto attrs = il2cpp_field_get_flags(field);
        auto access = attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK;
        switch (access) {
            case FIELD_ATTRIBUTE_PRIVATE: outPut << "private "; break;
            case FIELD_ATTRIBUTE_PUBLIC: outPut << "public "; break;
            case FIELD_ATTRIBUTE_FAMILY: outPut << "protected "; break;
            case FIELD_ATTRIBUTE_ASSEMBLY:
            case FIELD_ATTRIBUTE_FAM_AND_ASSEM: outPut << "internal "; break;
            case FIELD_ATTRIBUTE_FAM_OR_ASSEM: outPut << "protected internal "; break;
        }
        if (attrs & FIELD_ATTRIBUTE_LITERAL) outPut << "const ";
        else {
            if (attrs & FIELD_ATTRIBUTE_STATIC) outPut << "static ";
            if (attrs & FIELD_ATTRIBUTE_INIT_ONLY) outPut << "readonly ";
        }
        auto field_type = il2cpp_field_get_type(field);
        auto field_class = il2cpp_class_from_type(field_type);
        outPut << il2cpp_class_get_name(field_class) << " " << il2cpp_field_get_name(field);
        if (attrs & FIELD_ATTRIBUTE_LITERAL && is_enum) {
            uint64_t val = 0;
            il2cpp_field_static_get_value(field, &val);
            outPut << " = " << std::dec << val;
        }
        outPut << "; // 0x" << std::hex << il2cpp_field_get_offset(field) << "\n";
    }
    return outPut.str();
}

std::string dump_type(const Il2CppType *type) {
    std::stringstream outPut;
    auto *klass = il2cpp_class_from_type(type);
    outPut << "\n// Namespace: " << il2cpp_class_get_namespace(klass) << "\n";
    auto flags = il2cpp_class_get_flags(klass);
    if (flags & TYPE_ATTRIBUTE_SERIALIZABLE) outPut << "[Serializable]\n";
    auto is_valuetype = il2cpp_class_is_valuetype(klass);
    auto is_enum = il2cpp_class_is_enum(klass);
    auto visibility = flags & TYPE_ATTRIBUTE_VISIBILITY_MASK;
    switch (visibility) {
        case TYPE_ATTRIBUTE_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_PUBLIC: outPut << "public "; break;
        case TYPE_ATTRIBUTE_NOT_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM:
        case TYPE_ATTRIBUTE_NESTED_ASSEMBLY: outPut << "internal "; break;
        case TYPE_ATTRIBUTE_NESTED_PRIVATE: outPut << "private "; break;
        case TYPE_ATTRIBUTE_NESTED_FAMILY: outPut << "protected "; break;
        case TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM: outPut << "protected internal "; break;
    }
    if (flags & TYPE_ATTRIBUTE_ABSTRACT && flags & TYPE_ATTRIBUTE_SEALED) outPut << "static ";
    else if (!(flags & TYPE_ATTRIBUTE_INTERFACE) && flags & TYPE_ATTRIBUTE_ABSTRACT) outPut << "abstract ";
    else if (!is_valuetype && !is_enum && flags & TYPE_ATTRIBUTE_SEALED) outPut << "sealed ";
    if (flags & TYPE_ATTRIBUTE_INTERFACE) outPut << "interface ";
    else if (is_enum) outPut << "enum ";
    else if (is_valuetype) outPut << "struct ";
    else outPut << "class ";
    outPut << il2cpp_class_get_name(klass);
    std::vector<std::string> extends;
    auto parent = il2cpp_class_get_parent(klass);
    if (!is_valuetype && !is_enum && parent) {
        auto parent_type = il2cpp_class_get_type(parent);
        if (parent_type->type != IL2CPP_TYPE_OBJECT) extends.emplace_back(il2cpp_class_get_name(parent));
    }
    void *iter = nullptr;
    while (auto itf = il2cpp_class_get_interfaces(klass, &iter)) extends.emplace_back(il2cpp_class_get_name(itf));
    if (!extends.empty()) {
        outPut << " : " << extends[0];
        for (int i = 1; i < extends.size(); ++i) outPut << ", " << extends[i];
    }
    outPut << "\n{";
    outPut << dump_field(klass);
    outPut << dump_property(klass);
    outPut << dump_method(klass);
    outPut << "}\n";
    return outPut.str();
}

void il2cpp_api_init(void *handle) {
    il2cpp_base = reinterpret_cast<uint64_t>(handle);
    LOGI("il2cpp_handle base registered at: %" PRIx64, il2cpp_base);
    
    // Core change: Bypass string resolution entirely
    init_il2cpp_api_direct(il2cpp_base);
    
    // Check key initialization component validity 
    if (!il2cpp_domain_get_assemblies) {
        LOGE("Crucial validation pointer missing. Double check offset tables.");
        return;
    }
    
    // Synchronize loop structures natively
    while (!il2cpp_is_vm_thread(nullptr)) {
        LOGI("Waiting for execution context baseline sync...");
        sleep(1);
    }
    
    auto domain = il2cpp_domain_get();
    il2cpp_thread_attach(domain);
}

void il2cpp_dump(const char *outDir) {
    LOGI("dumping...");
    size_t size;
    auto domain = il2cpp_domain_get();
    auto assemblies = il2cpp_domain_get_assemblies(domain, &size);
    std::stringstream imageOutput;
    for (int i = 0; i < size; ++i) {
        auto image = il2cpp_assembly_get_image(assemblies[i]);
        imageOutput << "// Image " << i << ": " << il2cpp_image_get_name(image) << "\n";
    }
    std::vector<std::string> outPuts;
    if (il2cpp_image_get_class) {
        LOGI("Version greater than 2018.3");
        for (int i = 0; i < size; ++i) {
            auto image = il2cpp_assembly_get_image(assemblies[i]);
            std::stringstream imageStr;
            imageStr << "\n// Dll : " << il2cpp_image_get_name(image);
            auto classCount = il2cpp_image_get_class_count(image);
            for (int j = 0; j < classCount; ++j) {
                auto klass = il2cpp_image_get_class(image, j);
                if(!klass) continue;
                auto type = il2cpp_class_get_type(const_cast<Il2CppClass *>(klass));
                auto outPut = imageStr.str() + dump_type(type);
                outPuts.push_back(outPut);
            }
        }
    } else {
        LOGE("Error: Legacy reflection modes are unbacked within offset mapping models.");
        return;
    }
    
    LOGI("write dump file");
    auto outPath = std::string(outDir).append("/files/dump.cs");
    std::ofstream outStream(outPath);
    outStream << imageOutput.str();
    auto count = outPuts.size();
    for (int i = 0; i < count; ++i) {
        outStream << outPuts[i];
    }
    outStream.close();
    LOGI("dump done!");
}
