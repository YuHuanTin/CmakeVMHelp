#pragma once

#define Cmd(x) DbgCmdExecDirect(x)
#define Eval(x) DbgValFromString(x)
#define PLUG_EXPORT extern "C" __declspec(dllexport)

// plugin data
#define PLUGIN_NAME_utf16 L"VMHelp"
#define PLUGIN_NAME "VMHelp"
#define PLUGIN_VERSION 1

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT *initStruct);

PLUG_EXPORT bool plugstop();

PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT *setupStruct);
