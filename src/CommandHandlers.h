#pragma once

bool cb_run_until_page_switch(int argc, char *argv[]);
bool cb_run_until_breakpoint(int argc, char *argv[]);
bool cb_run_until_instruction(int argc, char *argv[]);
bool cb_run_until_call_return(int argc, char *argv[]);

bool cb_test_DbgGetBpxTypeAt(int argc, char *argv[]);
bool cb_test_PageQuery(int argc, char *argv[]);
bool cb_test_StepInAndQueryPage(int argc, char *argv[]);
