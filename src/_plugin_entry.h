#pragma once

#define PLUGIN_NAME    "CmakeVMHelp"
#define PLUGIN_VERSION 2
#define PLUG_EXPORT    extern "C" __declspec(dllexport)

#define OUTPUT_FILE "../traceLog"

#ifdef OUTPUT_FILE
extern void plugin_log_to_file(const char *fmt, ...);
    #define LOG(fmt, ...) plugin_log_to_file("[" PLUGIN_NAME "] " fmt "\n", ##__VA_ARGS__);
#else
    #define LOG(fmt, ...) _plugin_logprintf("[" PLUGIN_NAME "] " fmt "\n", ##__VA_ARGS__);
#endif

inline int gPluginHandle;
