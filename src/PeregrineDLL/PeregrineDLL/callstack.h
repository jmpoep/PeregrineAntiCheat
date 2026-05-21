#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

void callstack_init(void);

int callstack_check(const char* hook_name);

#ifdef __cplusplus
}
#endif
