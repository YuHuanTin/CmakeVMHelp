#pragma once

#define PLUGIN_NAME    "CmakeVMHelp"
#define PLUGIN_VERSION 2
#define PLUG_EXPORT    extern "C" __declspec(dllexport)

#define LOG(fmt, ...) _plugin_logprintf("[" PLUGIN_NAME "] " fmt "\n", ##__VA_ARGS__);

inline int gPluginHandle;
