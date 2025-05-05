#pragma once

#define Cmd(x) DbgCmdExecDirect(x)
#define Eval(x) DbgValFromString(x)
#define PLUG_EXPORT extern "C" __declspec(dllexport)

// plugin data
#define PLUGIN_NAME_utf16 L"VMHelp"
#define PLUGIN_NAME "VMHelp"
#define PLUGIN_VERSION 1


// superglobal variables
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

bool InitImpl(PLUG_INITSTRUCT *Init_struct);

bool StopImpl();

void SetupImpl();

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT *initStruct) {
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion    = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, PLUGIN_NAME, sizeof(PLUGIN_NAME));
    pluginHandle = initStruct->pluginHandle;
    return InitImpl(initStruct);
}

PLUG_EXPORT bool plugstop() {
    return StopImpl();
}

PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT *setupStruct) {
    hwndDlg     = setupStruct->hwndDlg;
    hMenu       = setupStruct->hMenu;
    hMenuDisasm = setupStruct->hMenuDisasm;
    hMenuDump   = setupStruct->hMenuDump;
    hMenuStack  = setupStruct->hMenuStack;
    SetupImpl();
}
