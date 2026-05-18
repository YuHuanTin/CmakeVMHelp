#pragma once


// std library
#include <cstdio>
#include <format>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#ifndef __out
#define __out
#endif

// 3rd library
#include <capstone/capstone.h>
#include <unicorn/unicorn.h>

// x64dbg library
#include "_plugins.h"

// superglobal variables
extern int  pluginHandle;
extern HWND hwndDlg;
extern int  hMenu;
extern int  hMenuDisasm;
extern int  hMenuDump;
extern int  hMenuStack;
