//
// Created by YuHuanTin on 2026/5/18.
//

#include "GUI.h"

#include "_plugin_entry.h"

enum GUI_IDS {
    ABOUD = 1000
};

void cb_click(CBTYPE cbType, void *callbackInfo) {
    MessageBox(nullptr, "A plugin for vm analyze", "info", MB_OK);
}

bool init_gui(PLUG_SETUPSTRUCT *GUI) {
    _plugin_menuaddentry(GUI->hMenu, GUI_IDS::ABOUD, "VMHelp");
    _plugin_registercallback(gPluginHandle, CBTYPE::CB_MENUENTRY, cb_click);
    return true;
}
