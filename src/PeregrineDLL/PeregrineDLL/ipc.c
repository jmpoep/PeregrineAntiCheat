#include <stdio.h>
#include "ipc.h"
#include <string.h>
#include <stdarg.h>
#include <windows.h>

#define IPC_PIPE_NAMEA "\\\\.\\pipe\\peregrine_ipc"

static HANDLE g_pipe = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_lock;
static volatile LONG g_lock_init = 0;

static void EnsureLock(void) {
    if (InterlockedCompareExchange(&g_lock_init, 1, 0) == 0)
        InitializeCriticalSection(&g_lock);
}

static HANDLE GetPipe(void) {
    if (g_pipe != INVALID_HANDLE_VALUE)
        return g_pipe;

    if (!WaitNamedPipeA(IPC_PIPE_NAMEA, 1000))
        return INVALID_HANDLE_VALUE;

    g_pipe = CreateFileA(
        IPC_PIPE_NAMEA,
        GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    return g_pipe;
}

static void ClosePipe(void) {
    if (g_pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_pipe);
        g_pipe = INVALID_HANDLE_VALUE;
    }
}

void ipc_write_json(const char* json) {
    if (!json) return;
    EnsureLock();

    EnterCriticalSection(&g_lock);

    HANDLE h = GetPipe();
    if (h == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&g_lock);
        return;
    }

    DWORD len = (DWORD)strlen(json);
    DWORD written = 0;
    if (!WriteFile(h, json, len, &written, NULL)) {
        ClosePipe();
    }

    LeaveCriticalSection(&g_lock);
}

void ipc_log_event(const char* event, const char* fmt, ...) {
    char params[768];
    va_list args;
    va_start(args, fmt);
    vsnprintf(params, sizeof(params), fmt, args);
    va_end(args);

    char buf[1024];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "{\"event\":\"%s\",%s}", event, params);

    ipc_write_json(buf);
}
