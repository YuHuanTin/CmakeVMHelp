#pragma once


// std library
#include <cstdio>
#include <format>
#include <fstream>
#include <map>
#include <string>
#include <vector>

// 3rd library
#include <capstone/capstone.h>
#include <unicorn/unicorn.h>

// x64dbg library
#include "pluginsdk/_plugins.h"


#ifdef _WIN64
#pragma comment(lib, "x64dbg.lib")
#pragma comment(lib, "x64bridge.lib")
#else
#pragma comment(lib, "x32dbg.lib")
#pragma comment(lib, "x32bridge.lib")
#endif //_WIN64

// superglobal variables
extern int  pluginHandle;
extern HWND hwndDlg;
extern int  hMenu;
extern int  hMenuDisasm;
extern int  hMenuDump;
extern int  hMenuStack;
