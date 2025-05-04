//
// Created by YuHuanTin on 2025/5/5.
//

#pragma once

#define Cmd(x) DbgCmdExecDirect(x)
#define Eval(x) DbgValFromString(x)
#define PLUG_EXPORT extern "C" __declspec(dllexport)


//superglobal variables
extern int  pluginHandle;
extern HWND hwndDlg;
extern int  hMenu;
extern int  hMenuDisasm;
extern int  hMenuDump;
extern int  hMenuStack;

int  pluginHandle;
HWND hwndDlg;
int  hMenu;
int  hMenuDisasm;
int  hMenuDump;
int  hMenuStack;

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT *initStruct) {
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion    = PLUG_SDKVERSION;
    strncpy(initStruct->pluginName, PLUGIN_NAME, sizeof(PLUGIN_NAME) + 1);
    pluginHandle = initStruct->pluginHandle;
    return pluginInit(initStruct);
}

PLUG_EXPORT bool plugstop() {
    return pluginStop();
}

PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT *setupStruct) {
    hwndDlg     = setupStruct->hwndDlg;
    hMenu       = setupStruct->hMenu;
    hMenuDisasm = setupStruct->hMenuDisasm;
    hMenuDump   = setupStruct->hMenuDump;
    hMenuStack  = setupStruct->hMenuStack;
    pluginSetup();
}
