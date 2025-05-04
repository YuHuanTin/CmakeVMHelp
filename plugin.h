#pragma once

//plugin data
#define PLUGIN_NAME_utf16 L"VMHelp"
#define PLUGIN_NAME "VMHelp"
#define PLUGIN_VERSION 1

//functions
bool pluginInit(PLUG_INITSTRUCT *initStruct);

bool pluginStop();

void pluginSetup();
